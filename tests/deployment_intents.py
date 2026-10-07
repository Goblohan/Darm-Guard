"""Real-kernel file checks for the Compose intent fixture; no container isolation claim."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from darm_guard.broker import AuditLog, Broker, BrokerConfig, Keys, load_intents
from darm_guard.kernel import KernelClient


class DeploymentIntentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="darm-deploy-intents-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        (self.workspace / "reports").mkdir(parents=True)
        (self.workspace / "notes.txt").write_text("hello from notes\n")
        config = json.loads((ROOT / "deploy/fixture/config.json").read_text())
        config["workspace"] = str(self.workspace)
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(config))
        cfg = BrokerConfig.load(str(config_path), str(ROOT / "deploy/fixture/registry.txt"))
        self.intents = self.root / "intents.txt"
        self.intents.write_text((ROOT / "deploy/fixture/intents.txt").read_text())
        self.kernel = KernelClient()
        self.addCleanup(self.kernel.close)
        self.broker = Broker(cfg, self.kernel, AuditLog(str(self.root / "audit.jsonl")),
                             load_intents(str(self.intents)), str(self.intents), Keys.generate())
        # Decision-only control: establishes that refusals are due to intents,
        # not an absent kernel or a policy/provenance refusal.
        self.control = Broker(cfg, self.kernel, AuditLog(str(self.root / "control.jsonl")))
        self.content = "written by the confined agent"
        self.path = "/workspace/reports/hello.md"
        self.line = "write_file path=" + self.path + " content_sha256=" + hashlib.sha256(self.content.encode()).hexdigest()

    def proposal(self, tool, **args):
        return {"tool": tool, "args": [[key, value] for key, value in args.items()]}

    def assert_intent_refusal(self, response):
        self.assertEqual(tuple(response.get(k) for k in ("decision", "failure", "effect")),
                         ("reject", "intent", "none"), response)

    def test_missing_and_mismatched_intents_preserve_authority(self):
        original = self.intents.read_text()
        proposals = [self.proposal("read_file", path="/workspace/notes.txt"),
                     self.proposal("write_file", path="/workspace/reports/other.md", content=self.content),
                     self.proposal("write_file", path=self.path, content="substituted content")]
        for proposal in proposals:
            with self.subTest(proposal=proposal):
                self.assertEqual(self.control.decide(proposal)[2]["decision"], "admit")
                self.assert_intent_refusal(self.broker.handle(proposal))
                self.assertEqual(self.intents.read_text(), original)
                self.assertEqual(list((self.workspace / "reports").iterdir()), [])

    def test_exact_write_spends_intent_and_replay_is_rejected(self):
        proposal = self.proposal("write_file", path=self.path, content=self.content)
        response = self.broker.handle(proposal)
        self.assertEqual(response.get("effect"), "succeeded", response)
        self.assertEqual(response.get("intent_state"), "spent", response)
        self.assertEqual(response.get("intent_consumed"), self.line, response)
        self.assertTrue(response.get("attested"), response)
        self.assertNotIn(self.line, self.intents.read_text().splitlines())
        self.assert_intent_refusal(self.broker.handle(proposal))
        self.assertEqual((self.workspace / "reports/hello.md").read_text(), self.content)
        response = self.broker.handle(self.proposal("read_file", path=self.path))
        self.assertEqual(response.get("content"), self.content, response)
        self.assertEqual(response.get("intent_consumed"), "read_file path=" + self.path, response)

    def test_matching_intent_does_not_override_provenance(self):
        original = self.intents.read_text()
        response = self.broker.handle(self.proposal("read_file", path="/workspace/invented.txt"))
        self.assertEqual(tuple(response.get(k) for k in ("decision", "failure", "effect")),
                         ("reject", "provenance", "none"), response)
        self.assertEqual(self.intents.read_text(), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
