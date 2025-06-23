#!/usr/bin/env python3
import sys, re, json

if len(sys.argv) < 2:
    print("Usage: parse_update_issue.py <issue_body_file>")
    sys.exit(1)

# Read the entire Markdown issue body
with open(sys.argv[1], encoding='utf-8') as f:
    body = f.read()

def extract_field(regex, text, group=1, fallback=""):
    m = re.search(regex, text, re.IGNORECASE)
    return m.group(group).strip() if m else fallback

reqid = extract_field(r"Request ID \(REQID\):\s*(REQ\d+)", body)
carid = extract_field(r"CARID:\s*([^\n]+)", body)

# Split into blocks at "#### Rule N"
blocks = re.split(r"#### Rule \d+", body)
rules = []
for blk in blocks[1:]:
    r = {}
    r['existing_rule_name'] = extract_field(
        r"Existing Rule Name:\s*`?([^\n`]+)`?", blk
    )
    r['action'] = extract_field(
        r"Action:\s*`?([a-zA-Z]+)`?", blk, fallback="update"
    ).lower()
    r['new_source_ips'] = extract_field(
        r"New Source IP\(s\) or CIDR\(s\):\s*`?([^\n`]*)`?", blk
    )
    r['new_destination_ips'] = extract_field(
        r"New Destination IP\(s\) or CIDR\(s\):\s*`?([^\n`]*)`?", blk
    )
    r['new_ports'] = extract_field(
        r"New Port\(s\):\s*`?([^\n`]*)`?", blk
    )
    r['new_protocol'] = extract_field(
        r"New Protocol:\s*`?([^\n`]*)`?", blk
    )
    r['new_direction'] = extract_field(
        r"New Direction:\s*`?([^\n`]*)`?", blk
    )
    r['new_justification'] = extract_field(
        r"New Business Justification:\s*([^\n]*)", blk
    )
    rules.append(r)

output = {
    "reqid": reqid,
    "carid": carid,
    "rules": rules
}
print(json.dumps(output, indent=2))
