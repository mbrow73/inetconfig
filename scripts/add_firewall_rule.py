#!/usr/bin/env python3
import sys, json
from json.decoder import JSONDecodeError

# 1) Load & normalize the issue JSON
raw   = json.loads(sys.argv[1])
issue = { k.strip('_'): v for k, v in raw.items() }

# 2) Path to your auto-tfvars file (unchanged)
tfpath = sys.argv[2]

# 3) Load existing tfvars, or start fresh
try:
    with open(tfpath) as f:
        data = json.load(f)
        if not isinstance(data, dict):
            data = {}
except (JSONDecodeError, FileNotFoundError):
    data = {}

# 4) Pull out the auto list (default to empty)
rules = data.get("auto_firewall_rules")
if not isinstance(rules, list):
    rules = []

# 5) Compute next priority
max_prio = max((r.get("priority", 0) for r in rules), default=1000)
new_prio = max_prio + 1

# 6) Build the new rule (no tls_inspection here)
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
    "priority":         new_prio
}

# 7) Append & write back under the auto_* key
rules.append(new_rule)
data["auto_firewall_rules"] = rules

with open(tfpath, "w") as f:
    json.dump(data, f, indent=2)

print(f"✅ Appended rule {new_rule['name']} with priority {new_prio}")
