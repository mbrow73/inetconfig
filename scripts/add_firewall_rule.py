#!/usr/bin/env python3
import sys, json

# args: [0]=this_script, [1]=issue_json_str, [2]=tfvars_path
issue = json.loads(sys.argv[1])
tfpath = sys.argv[2]

# Load existing tfvars JSON
with open(tfpath) as f:
    data = json.load(f)

rules = data.get("inet_firewall_rules", [])
# Compute next priority
max_prio = max((r.get("priority",0) for r in rules), default=1000)
new_prio = max_prio + 1

# Build new rule object
new_rule = {
    "name": issue["request_id"],
    "description": issue["business_justification"],
    "direction": issue["direction"].upper(),
    "src_ip_ranges": [ ip.strip() for ip in issue["source_ip_s_or_cidrs"].split(',') ],
    "dest_ip_ranges": [ ip.strip() for ip in issue["destination_ip_s_or_cidrs"].split(',') ],
    "protocol": issue["protocol"].upper(),
    "ports": [ p.strip() for p in issue["ports"].split(',') ],
    "enable_logging": True,
    "action": "allow",
    "tls_inspect": False,
    "priority": new_prio
}

rules.append(new_rule)
data["inet_firewall_rules"] = rules

# Write back
with open(tfpath, "w") as f:
    json.dump(data, f, indent=2)

print(f"Appended rule {new_rule['name']} with priority {new_prio}")