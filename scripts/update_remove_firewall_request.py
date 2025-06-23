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
        if not re.match(r'^\d+(-\d+)?$', p): return False
        if not (1 <= int(p.split('-')[0]) <= 65535): return False
    return True

if len(sys.argv) != 4:
    die("Usage: update_remove_firewall_request.py <issue_body.md> <in.tfvars> <out.tfvars>")

# 1) Load inputs
body = open(sys.argv[1], encoding='utf-8').read()
m = re.search(r'Request ID \(REQID\):\s*(REQ\d+)', body)
reqid = m.group(1) if m else die("Missing or invalid REQID")
m = re.search(r'CARID:\s*([A-Za-z0-9_-]+)', body)
carid = m.group(1) if m else die("Missing CARID")

# 2) Parse blocks
blocks = re.split(r'#### Rule', body)[1:]
if not blocks:
    die("No ‘#### Rule’ blocks found")

# 3) Load tfvars and isolate auto_firewall_rules
tfvars = json.load(open(sys.argv[2]))
rules = tfvars.get("auto_firewall_rules", [])
by_name = {r["name"]: r for r in rules}

updates = []   # tuples of (old_name, new_rule_dict)
removals = []  # list of names to remove
pr_lines = []
ownership_changed = False

for blk in blocks:
    text = blk.strip()

    # decide update vs removal
    if '🔹 **New Source**' in text:
        get = lambda pat: re.search(pat, text) and re.search(pat, text).group(1).strip()
        old_name = get(r'🔹 \*\*Existing Name\*\*:\s*`([^`]+)`') \
                   or die("Missing Existing Name in update block")
        src  = get(r'🔹 \*\*New Source\*\*:\s*`([^`]+)`')     or die(f"Missing New Source for {old_name}")
        dst  = get(r'🔹 \*\*New Destination\*\*:\s*`([^`]+)`') or die(f"Missing New Destination for {old_name}")
        pts  = get(r'🔹 \*\*New Ports\*\*:\s*`([^`]+)`')       or die(f"Missing New Ports for {old_name}")
        proto= get(r'🔹 \*\*New Protocol\*\*:\s*`([^`]+)`')    or die(f"Missing New Protocol for {old_name}")
        direc= get(r'🔹 \*\*New Direction\*\*:\s*`([^`]+)`')   or die(f"Missing New Direction for {old_name}")
        just = get(r'🔹 \*\*New Justification\*\*:\s*(.+)')     or die(f"Missing Justification for {old_name}")

        # validate
        if not all(valid_cidr(x) for x in src.split(',')):
            die(f"Bad CIDR in New Source for {old_name}")
        if not all(valid_cidr(x) for x in dst.split(',')):
            die(f"Bad CIDR in New Destination for {old_name}")
        if not valid_ports(pts):
            die(f"Bad ports {pts} for {old_name}")
        if old_name not in by_name:
            die(f"Rule {old_name} not found")

        old = by_name[old_name]
        parts = old_name.split('-')
        if len(parts) >= 6:
            parts[1], parts[2] = carid, reqid
            new_name = '-'.join(parts)
        else:
            new_name = old_name

        if old.get("carid","") != carid:
            ownership_changed = True

        new_rule = dict(old, **{
            "name": new_name,
            "src_ip_ranges": [x.strip() for x in src.split(",")],
            "dest_ip_ranges":[x.strip() for x in dst.split(",")],
            "ports":       [x.strip() for x in pts.split(",")],
            "protocol":    proto,
            "direction":   direc,
            "description": just,
            "carid":       carid
        })

        updates.append((old_name, new_rule))
        pr_lines.append(
            f"- **Update** `{old_name}` → `{new_name}`: {src} → {dst} on {proto}/{pts}\n"
            f"  Justification: {just}"
        )

    else:
        # removal block
        get = lambda pat: re.search(pat, text) and re.search(pat, text).group(1).strip()
        old_name = get(r'🔹 \*\*Existing Name\*\*:\s*`([^`]+)`') \
                   or die("Missing Existing Name in removal block")
        just = get(r'🔹 \*\*Justification\*\*:\s*(.+)') \
               or die(f"Missing Justification for removal of {old_name}")
        if old_name not in by_name:
            die(f"Rule {old_name} not found for removal")
        removals.append(old_name)
        pr_lines.append(f"- **Remove** `{old_name}`\n  Justification: {just}")

# 4) Patch only the affected entries in-place
#   - First remove
rules = [r for r in rules if r["name"] not in removals]
#   - Then apply updates
for old_name, new_rule in updates:
    for idx, r in enumerate(rules):
        if r["name"] == old_name:
            rules[idx] = new_rule
            break

# 5) Write back
tfvars["auto_firewall_rules"] = rules
json.dump(tfvars, open(sys.argv[3], "w"), indent=2)

# 6) Emit PR outputs
print(f"::set-output name=reqid::{reqid}")
print(f"::set-output name=pr_body::{chr(10).join(pr_lines)}")
print(f"::set-output name=ownership_changed::{str(ownership_changed).lower()}")
print("✅ Done.")
