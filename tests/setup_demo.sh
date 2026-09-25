#!/bin/sh
# Rebuild the demo fixture in /tmp/darmdemo (cleared whenever the machine restarts).
set -e
D=/tmp/darmdemo
rm -rf "$D/workspace"   # every run starts from an empty workspace
mkdir -p "$D/workspace/docs" "$D/workspace/reports"
echo "hello from notes" > "$D/workspace/notes.txt"
echo "the agent invented this path" > "$D/workspace/other.txt"
echo "a" > "$D/workspace/docs/a.txt"
echo "TOP SECRET" > "$D/secret.txt"
ln -sf "$D/secret.txt" "$D/workspace/link.txt"
cat > "$D/config.json" << 'EOF'
{"policy": {"tools": [
   {"tool": "read_file",  "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/"]}]},
   {"tool": "list_dir",   "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/"]}]},
   {"tool": "write_file", "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/"]},
                                    {"key": "content", "allowedValues": [], "allowedPrefixes": [""], "payload": true}]},
   {"tool": "delete_file", "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/reports/"]}]}]},
 "credential_tools": ["read_file", "list_dir", "write_file", "delete_file"],
 "workspace": "/tmp/darmdemo/workspace"}
EOF
printf '/workspace/notes.txt\n/workspace/link.txt\n/workspace/../secret.txt\n/workspace/docs\n/workspace/reports/*\n' > "$D/registry.txt"
echo "demo fixture ready at $D"
