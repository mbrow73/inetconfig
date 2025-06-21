#!/usr/bin/env python3
import sys, json
from json.decoder import JSONDecodeError
from ipaddress import ip_network

# 1) Load and normalize the issue JSON
issue = json.loads(sys.argv[1])
tfpath = sys.argv[2]

# 2) Load existing tfvars JSON, or initialize if empty/missing
try:
    with open(tfpath) as f:
        data = json.load(f)
        if not isinstance(data, dict):
            data = {}
except (JSONDecodeError, FileNotFoundError):
    data = {}

# 3) Ensure a list exists under the key
rules = data.get("inet_firewall_rules")
if not isinstance(rules, list):
    rules = []

# 4) Compute next priority
max_prio = max((r.get("priority", 0) for r in rules), default=1000)
new_prio = max_prio + 1

# 5) Build the new rule object
new_rule = {
    "name":             issue["request_id_reqid"],
    "description":      issue["business_justification"],
    "direction":        issue["direction"].upper(),
    "src_ip_ranges":    [ip.strip() for ip in issue["source_ip_s_or_cidr_s"].split(",")],
    "dest_ip_ranges":   [ip.strip() for ip in issue["destination_ip_s_or_cidr_s"].split(",")],
    "protocol":         issue["protocol"].upper(),
    "ports":            [p.strip() for p in issue["port_s"].split(",")],
    "enable_logging":   True,
    "action":           "allow",
    "tls_inspect":      False,
    "priority":         new_prio
}

# 6) Append and write back
rules.append(new_rule)
data["inet_firewall_rules"] = rules

with open(tfpath, "w") as f:
    json.dump(data, f, indent=2)

print(f"Appended rule {new_rule['name']} with priority {new_prio}")
