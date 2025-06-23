#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def die(msg):
    print(f"❌ {msg}")
    sys.exit(1)

def valid_cidr(x):
    try:
        ip_network(x.strip(), strict=False)
        return True
    except:
        return False

def valid_ports(s):
    for p in re.split(r'[,\s]+', s):
        if not re.match(r'^\d+(-\d+)?$', p):
            return False
        if not (1 <= int(p.split('-')[0]) <= 65535):
            return False
    return True

if len(sys.argv) != 4:
    die("Usage: update_remove_firewall_request.py <issue_body.md> <in.tfvars> <out.tfvars>")

body = open(sys.argv[1], encoding='utf-8').read()

# 1) Extract REQID & CARID
m = re.search(r'Request ID \(REQID\):\s*(REQ\d+)', body)
reqid = m.group(1) if m else die("Missing or invalid REQID")
m = re.search(r'CARID:\s*([A-Za-z0-9_-]+)', body)
carid = m.group(1) if m else die("Missing CARID")

# 2) Split into blocks by the '#### Rule' header
blocks = re.split(r'#### Rule', body)
if len(blocks) < 2:
    die("No ‘#### Rule’ blocks found")

# 3) Load existing rules
tfvars = json.load(open(sys.argv[2]))
all_rules = sum((tfvars.get(k, []) for k in
                 ["inet_firewall_rules","auto_firewall_rules","manual_firewall_rules"]), [])
by_name = {r["name"]: r for r in all_rules}

updates, removals, pr_lines = [], [], []
ownership_changed = False

for blk in blocks[1:]:
    text = blk.strip()
    # Update if it has a “New Source” line, otherwise removal
    if '🔹 **New Source**' in text:
        get = lambda pat: re.search(pat, text) and re.search(pat, text).group(1).strip()
        name = get(r'🔹 \*\*Existing Name\*\*:\s*`([^`]+)`') \
               or die("Missing Existing Name in update block")
        src  = get(r'🔹 \*\*New Source\*\*:\s*`([^`]+)`')     or die(f"Missing New Source for {name}")
        dst  = get(r'🔹 \*\*New Destination\*\*:\s*`([^`]+)`') or die(f"Missing New Destination for {name}")
        pts  = get(r'🔹 \*\*New Ports\*\*:\s*`([^`]+)`')       or die(f"Missing New Ports for {name}")
        proto= get(r'🔹 \*\*New Protocol\*\*:\s*`([^`]+)`')    or die(f"Missing New Protocol for {name}")
        direc= get(r'🔹 \*\*New Direction\*\*:\s*`([^`]+)`')   or die(f"Missing New Direction for {name}")
        just = get(r'🔹 \*\*New Justification\*\*:\s*(.+)')     or die(f"Missing Justification for {name}")

        # Validate
        if not all(valid_cidr(x) for x in src.split(',')):
            die(f"Bad CIDR in New Source for {name}")
        if not all(valid_cidr(x) for x in dst.split(',')):
            die(f"Bad CIDR in New Destination for {name}")
        if not valid_ports(pts):
            die(f"Bad ports {pts} for {name}")
        if name not in by_name:
            die(f"Rule {name} not found")

        old = by_name[name]
        parts = name.split('-')
        if len(parts) >= 6:
            parts[1], parts[2] = carid, reqid
            new_name = '-'.join(parts)
        else:
            new_name = name

        if old.get("carid", "") != carid:
            ownership_changed = True

        new_r = dict(old, **{
            "name": new_name,
            "src_ip_ranges": [x.strip() for x in src.split(",")],
            "dest_ip_ranges":[x.strip() for x in dst.split(",")],
            "ports":       [x.strip() for x in pts.split(",")],
            "protocol":    proto,
            "direction":   direc,
            "description": just,
            "carid":       carid
        })
        updates.append((name, new_r))
        pr_lines.append(
            f"- **Update** `{name}` → `{new_name}`: {src} → {dst} on {proto}/{pts}\n"
            f"  Justification: {just}"
        )

    else:
        # Removal block
        get = lambda pat: re.search(pat, text) and re.search(pat, text).group(1).strip()
        name = get(r'🔹 \*\*Existing Name\*\*:\s*`([^`]+)`') \
               or die("Missing Existing Name in removal block")
        just = get(r'🔹 \*\*Justification\*\*:\s*(.+)') \
               or die(f"Missing Justification for removal of {name}")
        if name not in by_name:
            die(f"Rule {name} not found for removal")
        removals.append(name)
        pr_lines.append(f"- **Remove** `{name}`\n  Justification: {just}")

# 4) Rebuild your tfvars list
final = []
for r in all_rules:
    if r["name"] in removals:
        continue
    u = next((u for u in updates if u[0] == r["name"]), None)
    final.append(u[1] if u else r)

tfvars["auto_firewall_rules"] = final
json.dump(tfvars, open(sys.argv[3], "w"), indent=2)

# 5) Emit outputs for the PR step
print(f"::set-output name=reqid::{reqid}")
print(f"::set-output name=pr_body::{chr(10).join(pr_lines)}")
print(f"::set-output name=ownership_changed::{str(ownership_changed).lower()}")
print("✅ Done.")
