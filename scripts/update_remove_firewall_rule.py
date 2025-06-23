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
    return p in ("tcp", "udp", "icmp")

def valid_dir(d):
    return d.upper() in ("INGRESS", "EGRESS")

# --- Entry point ---
if len(sys.argv) != 4:
    print("Usage: update_remove_firewall_rule.py <inputs.json> <in.tfvars> <out.tfvars>")
    sys.exit(1)

# Load data
data   = json.load(open(sys.argv[1]))
tfvars = json.load(open(sys.argv[2]))

# --- Validate presence of critical fields ---
reqid = data.get("reqid")
if not reqid:
    print("❌ Validation error: Missing Request ID (REQID). Are you using the correct Issue Form?")
    sys.exit(1)
reqid = reqid.strip()

carid = data.get("carid")
if not carid:
    print("❌ Validation error: Missing CARID. Are you using the correct Issue Form?")
    sys.exit(1)
carid = carid.strip()

# Determine action & assemble a single rule dict
if "new_source_ips" in data:
    action = "update"
    name = data.get("existing_rule_name", "").strip()
    src  = data.get("new_source_ips", "").strip()
    dst  = data.get("new_destination_ips", "").strip()
    pts  = data.get("new_ports", "").strip()
    proto= data.get("new_protocol", "").lower().strip()
    direc= data.get("new_direction", "").upper().strip()
    just = data.get("new_justification", "").strip()

    # Presence checks
    for fld,val in [
        ("Existing Rule Name", name),
        ("New Source IP(s)", src),
        ("New Destination IP(s)", dst),
        ("New Port(s)", pts),
        ("New Protocol", proto),
        ("New Direction", direc),
        ("Business Justification", just)
    ]:
        if not val:
            print(f"❌ Validation error: Missing {fld} for update of rule.")
            sys.exit(1)

    # Field‐specific validations
    if not all(valid_ip(x) for x in src.split(",")):
        print(f"❌ Validation error: Bad source IP/CIDR in {name}")
        sys.exit(1)
    if not all(valid_ip(x) for x in dst.split(",")):
        print(f"❌ Validation error: Bad destination IP/CIDR in {name}")
        sys.exit(1)
    if not valid_ports(pts):
        print(f"❌ Validation error: Bad port(s) in {name}")
        sys.exit(1)
    if not valid_proto(proto):
        print(f"❌ Validation error: Protocol must be tcp/udp/icmp in {name}")
        sys.exit(1)
    if not valid_dir(direc):
        print(f"❌ Validation error: Direction must be INGRESS or EGRESS in {name}")
        sys.exit(1)
elif "justification" in data:
    action = "remove"
    name = data.get("existing_rule_name", "").strip()
    just = data.get("justification", "").strip()

    if not name:
        print("❌ Validation error: Missing Existing Rule Name for removal.")
        sys.exit(1)
    if not just:
        print("❌ Validation error: Missing Business Justification for removal.")
        sys.exit(1)
else:
    print("❌ Validation error: Could not determine update vs remove form inputs.")
    sys.exit(1)

# Gather existing rules
all_rules = []
for key in ["inet_firewall_rules", "auto_firewall_rules", "manual_firewall_rules"]:
    all_rules.extend(tfvars.get(key, []))
by_name = {r["name"]: r for r in all_rules}

# Process removal
updates, removals = [], []
if action == "remove":
    if name not in by_name:
        print(f"❌ Validation error: Rule {name} not found for removal.")
        sys.exit(1)
    removals.append(name)

# Process update
if action == "update":
    if name not in by_name:
        print(f"❌ Validation error: Rule {name} not found for update.")
        sys.exit(1)
    old = by_name[name]

    # Build new rule name with updated CARID & REQID
    parts = name.split("-")
    if len(parts) >= 6:
        parts[1] = carid
        parts[2] = reqid
        new_name = "-".join(parts)
    else:
        new_name = name

    # Detect ownership change
    ownership_changed = (old.get("carid","") != carid)

    # Create updated rule object
    new_rule = dict(old)
    new_rule.update({
        "name": new_name,
        "src_ip_ranges": [x.strip() for x in src.split(",")],
        "dest_ip_ranges": [x.strip() for x in dst.split(",")],
        "ports": [x.strip() for x in pts.split(",")],
        "protocol": proto,
        "direction": direc,
        "description": just,
        "carid": carid
    })
    updates.append((name, new_rule, ownership_changed))

# Rebuild the final rule list
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
    pr_body = f"- **Remove** rule `{name}`\n\nJustification: {just}"
else:
    pr_body = (
        f"- **Update** rule `{name}`:\n"
        f"  • New Source: {src}\n"
        f"  • New Destination: {dst}\n"
        f"  • Ports: {pts}\n"
        f"  • Protocol: {proto}\n"
        f"  • Direction: {direc}\n"
        f"  • Justification: {just}"
    )

# Emit outputs
print(f"::set-output name=reqid::{reqid}")
print(f"::set-output name=action::{action}")
print(f"::set-output name=pr_body::{pr_body}")
print(f"::set-output name=ownership_changed::{str(ownership_changed).lower()}")
print("✅ Change complete.")
