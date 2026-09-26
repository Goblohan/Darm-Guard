#!/usr/bin/env bash
# Runs tests/intent_attacks.py the way it expects: a real broker started with
# --intents holding 'write_file' twice. Used locally and by CI.
set -uo pipefail
cd "$(dirname "$0")/.."
D=/tmp/darmdemo; A=$D/intent_attacks.jsonl; SOCK=/tmp/darm-broker.sock
./tests/setup_demo.sh > /dev/null
rm -f "$A" "$A".key "$A".pub.json "$A".legacy.key "$A".lock "$SOCK"
printf 'write_file\nwrite_file\n' > $D/intents.txt
PYTHONPATH=. python3 -c "from darm_guard.broker import main; main()" \
  --config $D/config.json --registry $D/registry.txt --socket $SOCK \
  --audit "$A" --intents $D/intents.txt > /tmp/intent_attacks_broker.txt 2>&1 &
BPID=$!
for _ in $(seq 1 200); do
  grep -q '"start"' "$A" 2>/dev/null && break
  kill -0 $BPID 2>/dev/null || { echo "broker exited during startup:"; cat /tmp/intent_attacks_broker.txt; exit 1; }
  sleep 0.05
done
python3 tests/intent_attacks.py; code=$?
kill $BPID; wait $BPID 2>/dev/null
exit $code
