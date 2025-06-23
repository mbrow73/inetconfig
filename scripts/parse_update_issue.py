#!/usr/bin/env python3
import sys
import re
import json

if len(sys.argv) < 2:
    print("Usage: parse_update_issue.py <issue_body_file>")
    sys.exit(1)

with open(sys.argv[1], encoding='utf-8') as f:
    body = f.read()

def extract_field(regex, text, group=1, fallback=""):
    m = re.search(regex, text, re.IGNORECASE)
    return m.group(group).strip() if m else fallback

reqid = extract_field(r"Request ID \(REQID\):\s*(REQ\d+)", body)
carid = extract_field(r"CARID:\s*([^\n]+)", body)

# Parse all rule blocks
rule_blocks = re.split(r"#### Rule \d+", body)
rules = []
for block in rule_blocks[1:]:
    rule = {}
    rule['existing_rule_name'] = extract_field(r"Existing Rule Name:\s*`?([^\n`]+)`?", block)
    rule['action'] = extract_field(r"Action:\s*`?([a-zA-Z]+)`?", block, fallback="update").lower()
    rule['new_source_ips'] = extract_field(r"New Source IP\(s\) or CIDR\(s\):\s*`?([^\n`]+)`?", block)
    rule['new_destination_ips'] = extract_field(r"New Destination IP\(s\) or CIDR\(s\):\s*`?([^\n`]+)`?", block)
    rule['new_ports'] = extract_field(r"New Port\(s\):\s*`?([^\n`]+)`?", block)
    rule['new_protocol'] = extract_field(r"New Protocol:\s*`?([^\n`]+)`?", block)
    rule['new_direction'] = extract_field(r"New Direction:\s*`?([^\n`]+)`?", block)
    rule['new_justification'] = extract_field(r"New Business Justification:\s*([^\n]+)", block)
    rules.append(rule)

out = {
    "reqid": reqid,
    "carid": carid,
    "rules": rules
}
print(json.dumps(out))
