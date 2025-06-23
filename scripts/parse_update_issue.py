#!/usr/bin/env python3
import sys, json

if len(sys.argv) < 2:
    print("Usage: parse_update_issue.py <issue_body_file>")
    sys.exit(1)

text = open(sys.argv[1], encoding='utf-8').read().splitlines()

reqid = ""
carid = ""
rules = []
current = None

for line in text:
    # Top‐level fields
    if line.startswith("### Request ID"):
        parts = line.split(":", 1)
        reqid = parts[1].strip() if len(parts) > 1 else ""
    elif line.startswith("### CARID"):
        parts = line.split(":", 1)
        carid = parts[1].strip() if len(parts) > 1 else ""

    # New rule start
    elif line.startswith("#### Rule"):
        if current:
            rules.append(current)
        current = {
            "existing_rule_name": "",
            "action": "update",
            "new_source_ips": "",
            "new_destination_ips": "",
            "new_ports": "",
            "new_protocol": "",
            "new_direction": "",
            "new_justification": ""
        }

    # Inside a rule block
    elif current is not None and line.strip().startswith("🔹"):
        # strip bullet and split on first colon
        content = line.strip()[2:].strip()
        key_val = content.split(":", 1)
        if len(key_val) < 2:
            continue
        key, val = key_val[0].strip(), key_val[1].strip().strip("`")
        mapping = {
            "Existing Rule Name": "existing_rule_name",
            "Action": "action",
            "New Source IP(s) or CIDR(s)": "new_source_ips",
            "New Destination IP(s) or CIDR(s)": "new_destination_ips",
            "New Port(s)": "new_ports",
            "New Protocol": "new_protocol",
            "New Direction": "new_direction",
            "New Business Justification": "new_justification"
        }
        field = mapping.get(key)
        if field:
            current[field] = val

# append last block
if current:
    rules.append(current)

output = {"reqid": reqid, "carid": carid, "rules": rules}
print(json.dumps(output, indent=2))
