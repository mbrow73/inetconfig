import glob
import json
import os

BASE_PRIORITY = 1000
PRIORITY_STEP = 1

all_rules = []

# Gather all rules from all tfvars files
for path in sorted(glob.glob("firewall-requests/*.auto.tfvars.json")):
    with open(path) as f:
        data = json.load(f)
        for rule in data.get("auto_firewall_rules", []):
            rule["_file"] = path
            all_rules.append(rule)

# Sort by whatever field you want. Example: by name
all_rules.sort(key=lambda r: r["name"])

# Assign unique, gapless priorities
for i, rule in enumerate(all_rules):
    rule["priority"] = BASE_PRIORITY + i * PRIORITY_STEP

# Write rules back to their respective files
files = {}
for rule in all_rules:
    path = rule["_file"]
    rule.pop("_file", None)
    files.setdefault(path, []).append(rule)

for path, rules in files.items():
    with open(path, "w") as f:
        json.dump({"auto_firewall_rules": rules}, f, indent=2)
