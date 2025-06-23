#!/usr/bin/env python3
import sys, json

if len(sys.argv) < 2:
    print("Usage: parse_update_issue.py <issue_body_file>")
    sys.exit(1)

lines = open(sys.argv[1], encoding='utf-8').read().splitlines()

reqid = ""
carid = ""
rules = []
current = None

for line in lines:
    # Top-level fields
    if line.startswith("### Request ID"):
        reqid = line.split(":",1)[1].strip()
    elif line.startswith("### CARID"):
        carid = line.split(":",1)[1].strip()

    # Start a new rule block
    elif line.startswith("#### Rule"):
        if current:
            rules.append(current)
        current = {
            "existing_rule_name": "",
            "action": "",
            "new_source_ips": "",
            "new_destination_ips": "",
            "new_ports": "",
            "new_protocol": "",
            "new_direction": "",
            "new_justification": ""
        }

    # Inside a rule block, parse bullets
    elif current is not None and line.strip().startswith("🔹"):
        # Remove bullet and any leading space
        content = line.strip()[1:].strip()
        # Split once at colon
        if ":" not in content:
            continue
        key, val = content.split(":",1)
        key = key.strip()
        val = val.strip().strip("`")
        # Map to our JSON fields
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
        if field is not None:
            current[field] = val

# Append last rule
if current:
    rules.append(current)

print(json.dumps({
    "reqid": reqid,
    "carid": carid,
    "rules": rules
}, indent=2))
