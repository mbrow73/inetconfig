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

def valid_proto(p): return p in ("tcp","udp","icmp")
def valid_dir(d):   return d.upper() in ("INGRESS","EGRESS")

if len(sys.argv) != 4:
    print("Usage: update_firewall_rule.py <inputs.json> <in.tfvars> <out.tfvars>")
    sys.exit(1)

data = json.load(open(sys.argv[1]))
reqid = data.get("reqid","").strip()   or sys.exit("❌ Missing reqid")
carid = data.get("carid","").strip()   or sys.exit("❌ Missing carid")
name  = data.get("existing_rule_name","").strip() or sys.exit("❌ Missing existing_rule_name")
src   = data.get("new_source_ips","").strip()     or sys.exit("❌ Missing new_source_ips")
dst   = data.get("new_destination_ips","").strip()or sys.exit("❌ Missing new_destination_ips")
pts   = data.get("new_ports","").strip()          or sys.exit("❌ Missing new_ports")
proto = data.get("new_protocol","").lower().strip() or sys.exit("❌ Missing new_protocol")
direc = data.get("new_direction","").upper().strip()or sys.exit("❌ Missing new_direction")
just  = data.get("new_justification","").strip()  or sys.exit("❌ Missing new_justification")

# Field validations
if not all(valid_ip(x) for x in src.split(",")): sys.exit("❌ Bad source IP")
if not all(valid_ip(x) for x in dst.split(",")): sys.exit("❌ Bad destination IP")
if not valid_ports(pts):                         sys.exit("❌ Bad ports")
if not valid_proto(proto):                       sys.exit("❌ Bad protocol")
if not valid_dir(direc):                         sys.exit("❌ Bad direction")

tfvars = json.load(open(sys.argv[2]))
all_rules = sum((tfvars.get(k,[]) for k in ["inet_firewall_rules","auto_firewall_rules","manual_firewall_rules"]), [])
by_name   = {r["name"]:r for r in all_rules}
if name not in by_name: 
    sys.exit(f"❌ Rule {name} not found")

old = by_name[name]
parts = name.split("-")
if len(parts) >= 6:
    parts[1], parts[2] = carid, reqid
new_name = "-".join(parts)

ownership = (old.get("carid","") != carid)

new_r = dict(old, **{
    "name": new_name,
    "src_ip_ranges":[x.strip() for x in src.split(",")],
    "dest_ip_ranges":[x.strip() for x in dst.split(",")],
    "ports":[x.strip() for x in pts.split(",")],
    "protocol":proto,
    "direction":direc,
    "description":just,
    "carid":carid
})

final = [new_r if r["name"]==name else r for r in all_rules]
tfvars["auto_firewall_rules"] = final
json.dump(tfvars, open(sys.argv[3],"w"), indent=2)

pr_body = (
  f"- **Update** `{name}` → `{new_name}`\n"
  f"  • Source: {src}\n  • Dest:   {dst}\n"
  f"  • Ports:  {pts}\n"
  f"  • Proto:  {proto}\n"
  f"  • Dir:    {direc}\n"
  f"  • Justification: {just}"
)

print(f"::set-output name=reqid::{reqid}")
print("::set-output name=action::update")
print(f"::set-output name=pr_body::{pr_body}")
print(f"::set-output name=ownership_changed::{str(ownership).lower()}")
