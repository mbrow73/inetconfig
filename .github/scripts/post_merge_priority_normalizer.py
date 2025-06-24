import glob
import json

BASE_PRIORITY = 1000
PRIORITY_STEP = 1

# Gather all rules from all tfvars files
all_rules = []
file_map = {}

for path in sorted(glob.glob("firewall-requests/*.auto.tfvars.json")):
    with open(path) as f:
        data = json.load(f)
        for rule in data.get("auto_firewall_rules", []):
            rule["_file"] = path
            all_rules.append(rule)

# Sort all rules by name (or another stable field if desired)
all_rules.sort(key=lambda r: r["name"])

# Assign globally unique, gapless priorities
for i, rule in enumerate(all_rules):
    rule["priority"] = BASE_PRIORITY + i * PRIORITY_STEP

# Group back into their respective files
files = {}
for rule in all_rules:
    path = rule["_file"]
    rule.pop("_file", None)
    files.setdefault(path, []).append(rule)

# Only rewrite files if anything changed, to avoid unnecessary commits
for path, rules in files.items():
    with open(path, "r") as f:
        orig = json.load(f).get("auto_firewall_rules", [])
    if orig != rules:
        with open(path, "w") as f:
            json.dump({"auto_firewall_rules": rules}, f, indent=2)
