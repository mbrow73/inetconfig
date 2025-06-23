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
    return all(pr.match(p) and 0 < int(p.split("-")[0]) <= 65535
               for p in re.split(r'[,\s]+', s) if p)

def valid_proto(p):
    return p in ("tcp","udp","icmp")

def valid_dir(d):
    return d.upper() in ("INGRESS","EGRESS")

if len(sys.argv) < 4:
    print("Usage: update_remove_firewall_rule.py <parsed.json> <tfvars_in> <tfvars_out>")
    sys.exit(1)

issue = json.load(open(sys.argv[1]))
tfvars = json.load(open(sys.argv[2]))

reqid = issue["reqid"]
carid = issue["carid"]

# Gather existing rules
all_rules = []
for k in ["inet_firewall_rules","auto_firewall_rules","manual_firewall_rules"]:
    all_rules.extend(tfvars.get(k,[]))
by_name = {r["name"]: r for r in all_rules}

updates = []
removals = []

for r in issue["rules"]:
    name   = r["existing_rule_name"]
    action = r["action"].lower()

    if action == "remove":
        removals.append(name)
        continue

    src  = r["new_source_ips"]
    dst  = r["new_destination_ips"]
    ports= r["new_ports"]
    proto= r["new_protocol"].lower()
    direc= r["new_direction"].upper()
    just = r["new_justification"]

    # Validate presence
    if not all([name,src,dst,ports,proto,direc,just,reqid,carid]):
        print(f"Validation failed: missing fields for update of {name}")
        sys.exit(1)
    if not all(valid_ip(x) for x in re.split(r'[,\s]+',src)):
        print(f"Validation failed: bad source IP/CIDR in {name}")
        sys.exit(1)
    if not all(valid_ip(x) for x in re.split(r'[,\s]+',dst)):
        print(f"Validation failed: bad destination IP/CIDR in {name}")
        sys.exit(1)
    if not valid_ports(ports):
        print(f"Validation failed: bad port(s) in {name}")
        sys.exit(1)
    if not valid_proto(proto):
        print(f"Validation failed: protocol must be tcp/udp/icmp in {name}")
        sys.exit(1)
    if not valid_dir(direc):
        print(f"Validation failed: direction must be INGRESS/EGRESS in {name}")
        sys.exit(1)

    if name not in by_name:
        print(f"Validation failed: rule {name} not found")
        sys.exit(1)
    old = by_name[name]

    parts = name.split("-")
    if len(parts) >= 6:
        parts[1] = carid
        parts[2] = reqid
        new_name = "-".join(parts)
    else:
        new_name = name

    ownership_changed = (old.get("carid","") != carid)

    new_r = dict(old)
    new_r.update({
      "name": new_name,
      "src_ip_ranges": [x.strip() for x in src.split(",")],
      "dest_ip_ranges":[x.strip() for x in dst.split(",")],
      "ports":       [x.strip() for x in ports.split(",")],
      "protocol": proto,
      "direction": direc,
      "description": just,
      "carid": carid
    })
    updates.append((name,new_r,ownership_changed))

# Build final list
final = []
for r in all_rules:
    if r["name"] in removals:
        continue
    upd = next((u for u in updates if u[0]==r["name"]), None)
    final.append(upd[1] if upd else r)

tfvars["auto_firewall_rules"] = final
with open(sys.argv[3],"w") as f:
    json.dump(tfvars, f, indent=2)

flag = any(u[2] for u in updates)
print(f"::set-output name=ownership_changed::{str(flag).lower()}")
print("✅ Update/Remove complete.")
