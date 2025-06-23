#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def valid_ip(x):
    try:
        ip_network(x, strict=False)
        return True
    except:
        return False

def valid_ports(s):
    pr = re.compile(r'^\d+(-\d+)?$')
    return all(pr.match(p) and 1 <= int(p.split('-')[0]) <= 65535
               for p in re.split(r'[,\s]+', s) if p)

def valid_proto(p):
    return p in ("tcp","udp","icmp")

def valid_dir(d):
    return d.upper() in ("INGRESS","EGRESS")

if len(sys.argv) != 4:
    print("Usage: update_remove_firewall_rule.py <inputs.json> <in.tfvars> <out.tfvars>")
    sys.exit(1)

# Load form inputs
data   = json.load(open(sys.argv[1]))
tfvars = json.load(open(sys.argv[2]))

reqid = data["reqid"].strip()
carid = data["carid"].strip()

# Determine if update or remove form by presence of new_source_ips
if "new_source_ips" in data:
    action = "update"
    rule = {
      "action": action,
      "existing_rule_name": data["existing_rule_name"].strip(),
      "new_source_ips": data["new_source_ips"].strip(),
      "new_destination_ips": data["new_destination_ips"].strip(),
      "new_ports": data["new_ports"].strip(),
      "new_protocol": data["new_protocol"].strip().lower(),
      "new_direction": data["new_direction"].strip().upper(),
      "new_justification": data["new_justification"].strip()
    }
else:
    action = "remove"
    rule = {
      "action": action,
      "existing_rule_name": data["existing_rule_name"].strip()
    }

# Gather existing rules
all_rules = []
for k in ["inet_firewall_rules","auto_firewall_rules","manual_firewall_rules"]:
    all_rules.extend(tfvars.get(k, []))
by_name = {r["name"]: r for r in all_rules}

updates, removals = [], []

# Process single rule
name = rule["existing_rule_name"]
if action == "remove":
    removals.append(name)
else:
    # Validate update fields
    src, dst = rule["new_source_ips"], rule["new_destination_ips"]
    pts, proto = rule["new_ports"], rule["new_protocol"]
    direc, just = rule["new_direction"], rule["new_justification"]

    # Basic presence
    if not all([name, src, dst, pts, proto, direc, just, reqid, carid]):
        print(f"Validation failed: missing fields for update of {name}")
        sys.exit(1)
    if not all(valid_ip(x) for x in src.split(",")):
        print(f"Validation failed: bad source IP in {name}")
        sys.exit(1)
    if not all(valid_ip(x) for x in dst.split(",")):
        print(f"Validation failed: bad destination IP in {name}")
        sys.exit(1)
    if not valid_ports(pts):
        print(f"Validation failed: bad port(s) in {name}")
        sys.exit(1)
    if not valid_proto(proto):
        print(f"Validation failed: bad protocol in {name}")
        sys.exit(1)
    if not valid_dir(direc):
        print(f"Validation failed: bad direction in {name}")
        sys.exit(1)
    if name not in by_name:
        print(f"Validation failed: rule {name} not found")
        sys.exit(1)

    old = by_name[name]
    parts = name.split("-")
    if len(parts) >= 6:
        parts[1], parts[2] = carid, reqid
        new_name = "-".join(parts)
    else:
        new_name = name

    ownership_changed = (old.get("carid","") != carid)

    new_r = dict(old)
    new_r.update({
      "name": new_name,
      "src_ip_ranges": [x.strip() for x in src.split(",")],
      "dest_ip_ranges":[x.strip() for x in dst.split(",")],
      "ports":       [x.strip() for x in pts.split(",")],
      "protocol":    proto,
      "direction":   direc,
      "description": just,
      "carid":       carid
    })
    updates.append((name, new_r, ownership_changed))

# Rebuild final list
final = []
for r in all_rules:
    if r["name"] in removals:
        continue
    upd = next((u for u in updates if u[0] == r["name"]), None)
    final.append(upd[1] if upd else r)

tfvars["auto_firewall_rules"] = final
with open(sys.argv[3], "w") as f:
    json.dump(tfvars, f, indent=2)

# Prepare PR body
if action == "remove":
    pr_body = f"- **Remove** rule `{name}`\n\nJustification: {data.get('justification', '').strip()}"
else:
    pr_body = (
      f"- **Update** rule `{name}`:\n"
      f"  - New Source: {src}\n"
      f"  - New Dest: {dst}\n"
      f"  - Ports: {pts}\n"
      f"  - Proto: {proto}\n"
      f"  - Dir: {direc}\n"
      f"  - Justification: {just}"
    )

# Emit outputs
print(f"::set-output name=reqid::{reqid}")
print(f"::set-output name=action::{action}")
print(f"::set-output name=pr_body::{pr_body}")
print(f"::set-output name=ownership_changed::{str(ownership_changed).lower()}")
print("✅ Complete")
