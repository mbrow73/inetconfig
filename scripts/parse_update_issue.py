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

for raw in lines:
    line = raw.strip()

    # Top-level fields
    if line.startswith("### Request ID"):
        parts = line.split(":",1)
        reqid = parts[1].strip() if len(parts)>1 else ""
        continue
    if line.startswith("### CARID"):
        parts = line.split(":",1)
        carid = parts[1].strip() if len(parts)>1 else ""
        continue

    # Start new rule
    if line.startswith("#### Rule"):
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
        continue

    # Inside a rule block: look for each label
    if current is not None:
        if "Existing Rule Name:" in line:
            current["existing_rule_name"] = line.split("Existing Rule Name:",1)[1].strip().strip("` ")
        elif line.startswith("🔹 Action:") or line.startswith("- Action:") or " Action:" in line:
            if "Action:" in line:
                current["action"] = line.split("Action:",1)[1].strip().strip("` ")
        elif "New Source IP" in line:
            current["new_source_ips"] = line.split(":",1)[1].strip().strip("` ")
        elif "New Destination IP" in line:
            current["new_destination_ips"] = line.split(":",1)[1].strip().strip("` ")
        elif "New Port" in line:
            current["new_ports"] = line.split(":",1)[1].strip().strip("` ")
        elif "New Protocol" in line:
            current["new_protocol"] = line.split(":",1)[1].strip().strip("` ")
        elif "New Direction" in line:
            current["new_direction"] = line.split(":",1)[1].strip().strip("` ")
        elif "New Business Justification" in line:
            current["new_justification"] = line.split(":",1)[1].strip()

# append last rule
if current:
    rules.append(current)

print(json.dumps({
    "reqid": reqid,
    "carid": carid,
    "rules": rules
}, indent=2))
