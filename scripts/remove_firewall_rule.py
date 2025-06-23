#!/usr/bin/env python3
import sys, json

if len(sys.argv)!=4:
    print("Usage: remove_firewall_rule.py <inputs.json> <in.tfvars> <out.tfvars>"); sys.exit(1)

data = json.load(open(sys.argv[1]))
reqid = data.get("reqid","").strip()   or sys.exit("❌ Missing reqid")
carid = data.get("carid","").strip()   or sys.exit("❌ Missing carid")
name  = data.get("existing_rule_name","").strip() or sys.exit("❌ Missing existing_rule_name")
just  = data.get("justification","").strip()      or sys.exit("❌ Missing justification")

tfvars = json.load(open(sys.argv[2]))
all_rules = sum((tfvars.get(k,[]) for k in ["inet_firewall_rules","auto_firewall_rules","manual_firewall_rules"]), [])
if name not in [r["name"] for r in all_rules]:
    sys.exit(f"❌ Rule {name} not found")

final = [r for r in all_rules if r["name"]!=name]
tfvars["auto_firewall_rules"] = final
json.dump(tfvars, open(sys.argv[3],"w"), indent=2)

pr_body = f"- **Remove** `{name}`\n  Justification: {just}"
print(f"::set-output name=reqid::{reqid}")
print("::set-output name=action::remove")
print(f"::set-output name=pr_body::{pr_body}")
print("::set-output name=ownership_changed::false")
