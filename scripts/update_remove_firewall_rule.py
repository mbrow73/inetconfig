#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def valid_ip(x):
    try: ip_network(x, strict=False); return True
    except: return False

def valid_ports(s):
    pr = re.compile(r'^\d+(-\d+)?$')
    return all(pr.match(p) and 1 <= int(p.split('-')[0]) <= 65535
               for p in re.split(r'[,\s]+', s) if p)

def valid_proto(p):  return p in ("tcp","udp","icmp")
def valid_dir(d):    return d.upper() in ("INGRESS","EGRESS")

if len(sys.argv)!=4:
    print("Usage: update_remove_firewall_rule.py <inputs.json> <in.tfvars> <out.tfvars>")
    sys.exit(1)

data   = json.load(open(sys.argv[1]))
tfvars = json.load(open(sys.argv[2]))

reqid = data["reqid"].strip()
carid = data["carid"].strip()
rules = json.loads(data["rules_json"])

# gather existing
all_rules=[]
for k in ["inet_firewall_rules","auto_firewall_rules","manual_firewall_rules"]:
    all_rules.extend(tfvars.get(k,[]))
by_name={r["name"]:r for r in all_rules}

updates, removals = [], []
for r in rules:
    name   = r.get("existing_rule_name","").strip()
    action = r.get("action","").lower().strip()
    if action not in ("update","remove"):
        print(f"Invalid action '{action}' for {name}"); sys.exit(1)
    if action=="remove":
        removals.append(name); continue

    src = r.get("new_source_ips","").strip()
    dst = r.get("new_destination_ips","").strip()
    pts = r.get("new_ports","").strip()
    proto = r.get("new_protocol","").lower().strip()
    direc = r.get("new_direction","").upper().strip()
    just = r.get("new_justification","").strip()

    # validate
    if not all([name,src,dst,pts,proto,direc,just,reqid,carid]):
        print(f"Missing fields for update of {name}"); sys.exit(1)
    if not all(valid_ip(x) for x in src.split(",")):
        print(f"Bad source IP in {name}"); sys.exit(1)
    if not all(valid_ip(x) for x in dst.split(",")):
        print(f"Bad destination IP in {name}"); sys.exit(1)
    if not valid_ports(pts):
        print(f"Bad port(s) in {name}"); sys.exit(1)
    if not valid_proto(proto):
        print(f"Bad protocol in {name}"); sys.exit(1)
    if not valid_dir(direc):
        print(f"Bad direction in {name}"); sys.exit(1)
    if name not in by_name:
        print(f"Rule {name} not found"); sys.exit(1)

    old = by_name[name]
    parts = name.split("-")
    new_name = "-".join([parts[0], carid, reqid] + parts[3:]) if len(parts)>=6 else name
    ownership = (old.get("carid","") != carid)

    nr = dict(old, **{
        "name": new_name,
        "src_ip_ranges":[x.strip() for x in src.split(",")],
        "dest_ip_ranges":[x.strip() for x in dst.split(",")],
        "ports":[x.strip() for x in pts.split(",")],
        "protocol":proto,
        "direction":direc,
        "description":just,
        "carid":carid
    })
    updates.append((name, nr, ownership))

# rebuild
final=[]
for r in all_rules:
    if r["name"] in removals: continue
    u = next((u for u in updates if u[0]==r["name"]), None)
    final.append(u[1] if u else r)

tfvars["auto_firewall_rules"] = final
with open(sys.argv[3],"w") as f: json.dump(tfvars, f, indent=2)

flag = any(u[2] for u in updates)
print(f"::set-output name=ownership_changed::{str(flag).lower()}")
print("✅ Complete")
