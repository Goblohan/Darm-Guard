"""DARM Verify adapter for AgentLock (webpro255/agentlock), probed against 1.10.3.

Translates only the subset confirmed by hand probes: tool registration (O),
allowed_roles (A), a single exact-value recipient allowlist (S), and
parameter lineage via user-message and web-content writes (P). Anything
else is declined with a reason, so divergences measure AgentLock, not this
translation. AgentLock escalations ('approval_required') are reported as
their own outcome, distinct from denials.
"""
import hashlib

from ..verify import Verdict

TOOLS = ["send_email", "share_doc", "post_msg"]
VALUES = ["alice@corp.example", "bob@corp.example", "carol@corp.example",
          "mallory@evil.example"]


def scenario(rng) -> dict:
    tools = []
    for t in TOOLS:
        if rng.random() < 0.8:
            tools.append({"tool": t, "rules": [{"key": "to",
                          "allowedValues": rng.sample(VALUES, rng.randint(1, 3)),
                          "allowedPrefixes": []}]})
    cred = {"tools": rng.sample(TOOLS, rng.randint(1, 3)), "expired": False}
    tool = rng.choice(TOOLS) if rng.random() < 0.9 else "delete_all"
    args = [] if rng.random() < 0.15 else [
        {"key": "to", "value": rng.choice(VALUES),
         "prov": rng.choice(["authoritative", "authoritative", "untrusted"])}]
    return {"policy": {"tools": tools}, "credential": cred,
            "invocation": {"tool": tool, "args": args},
            # outside the kernel's request format: unrelated untrusted content
            "session_noise": rng.random() < 0.3}


def _decline(reason):
    return Verdict(False, reason, supported=False)


def _write(gate, session, source, content):
    gate.notify_context_write(session.session_id, source,
                              hashlib.sha256(content.encode()).hexdigest(), content=content)


def agentlock_adapter(req: dict) -> Verdict:
    try:
        from agentlock import AuthorizationGate, AgentLockPermissions, ContextSource
        from agentlock.schema import ScopeConfig, LineagePolicyConfig, RecipientPolicy
    except ImportError:
        return _decline("agentlock not installed")
    if req["credential"]["expired"]:
        return _decline("credential expiry (AgentLock sessions expire by elapsed time)")
    inv, cred = req["invocation"], set(req["credential"]["tools"])
    gate, ruled, rkey = AuthorizationGate(), {}, {}
    for tp in req["policy"]["tools"]:
        rules = tp["rules"]
        if len(rules) > 1:
            return _decline("more than one ruled argument per tool")
        if any(r.get("payload") for r in rules):
            return _decline("payload roles")
        kw = {"lineage_policy": LineagePolicyConfig(
            enabled=True, param_lineage_enabled=True, param_lineage_action="deny")}
        if rules:
            r = rules[0]
            if r["allowedPrefixes"]:
                return _decline("prefix rules")
            kw["scope"] = ScopeConfig(allowed_recipients=RecipientPolicy.ALLOWLIST,
                                      recipient_allowlist=list(r["allowedValues"]),
                                      recipient_parameter=r["key"])
            rkey[tp["tool"]] = r["key"]
        ruled[tp["tool"]] = {r["key"] for r in rules}
        roles = ["agent"] if tp["tool"] in cred else ["admin"]
        gate.register_tool(tp["tool"], AgentLockPermissions(
            risk_level="low", allowed_roles=roles, **kw))
    for a in inv["args"]:
        if inv["tool"] in ruled and a["key"] not in ruled[inv["tool"]]:
            return _decline("argument key without a rule (AgentLock does not restrict parameter names)")
        if a["prov"] == "derived":
            return _decline("derived provenance (no probed AgentLock counterpart)")
        if len(a["value"]) < 6:
            return _decline("value shorter than AgentLock's lineage minimum")
    session = gate.create_session(user_id="u1", role="agent")
    user = " ".join(a["value"] for a in inv["args"] if a["prov"] == "authoritative")
    _write(gate, session, ContextSource.USER_MESSAGE, "request: " + user)
    web = " ".join(a["value"] for a in inv["args"] if a["prov"] == "untrusted")
    if web:
        _write(gate, session, ContextSource.WEB_CONTENT, "page: " + web)
    if req.get("session_noise"):
        _write(gate, session, ContextSource.WEB_CONTENT, "unrelated page about the weather")
    params = {a["key"]: a["value"] for a in inv["args"]}
    result = gate.authorize(inv["tool"], user_id="u1", parameters=params,
                            recipient=params.get(rkey.get(inv["tool"], ""), ""),
                            is_external=True)
    if result.allowed:
        return Verdict(True)
    d = result.denial or {}
    if d.get("status") == "approval_required":
        return Verdict(False, "escalated: " + str(d.get("reason", "")))
    return Verdict(False, str(d.get("reason", "denied")))
