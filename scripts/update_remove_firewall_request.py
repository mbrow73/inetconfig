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

def find_block(lines, name):
    """Find the start/end line indexes of the JSON object whose "name" equals name.
       Returns (start_idx, end_idx, had_comma_on_closing)."""
    pat = re.compile(r'"name"\s*:\s*"' + re.escape(name) + r'"')
    for i,line in enumerate(lines):
        if pat.search(line):
            # back up to the opening '{'
            start = i
            while start>0 and '{' not in lines[start]:
                start -= 1
            # now scan forward to match braces
            brace = 0
            end = start
            had_comma = False
            while end < len(lines):
                brace += lines[end].count('{')
                brace -= lines[end].count('}')
                if brace == 0:
                    # did the '}' line end with a comma?
                    if lines[end].rstrip().endswith(','):
                        had_comma = True
                    break
                end += 1
            return start, end, had_comma
    return None, None, None

if len(sys.argv) != 4:
    die("Usage: update_remove_firewall_request.py <issue_body.md> <in.tfvars> <out.tfvars>")

# 1) Read issue body
body = open(sys.argv[1], encoding='utf-8').read()
m = re.search(r'Request ID \(REQID\):\s*(REQ\d+)', body)
reqid = m.group(1) if m else die("Missing or invalid REQID")
m = re.search(r'CARID:\s*([A-Za-z0-9_-]+)', body)
carid = m.group(1) if m else die("Missing CARID")

# 2) Split into #### Rule blocks
blocks = re.split(r'#### Rule', body)[1:]
if not blocks:
    die("No '#### Rule' blocks found")

# 3) Load tfvars
tfvars = json.load(open(sys.argv[2]))
rules = tfvars.get("auto_firewall_rules", [])
by_name = {r["name"]: r for r in rules}

updates = []   # [(old_name, new_rule_dict)]
removals = []  # [old_name]
pr_lines = []
ownership_changed = False

for blk in blocks:
    text = blk.strip()
    # update if it has “New Source”, else removal
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

        # validations
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
            "src_ip_ranges": [x.strip() for x in src.split(',')],
            "dest_ip_ranges":[x.strip() for x in dst.split(',')],
            "ports":       [x.strip() for x in pts.split(',')],
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
        # removal
        get = lambda pat: re.search(pat, text) and re.search(pat, text).group(1).strip()
        old_name = get(r'🔹 \*\*Existing Name\*\*:\s*`([^`]+)`') \
                   or die("Missing Existing Name in removal block")
        just = get(r'🔹 \*\*Justification\*\*:\s*(.+)') \
               or die(f"Missing Justification for removal of {old_name}")
        if old_name not in by_name:
            die(f"Rule {old_name} not found for removal")

        removals.append(old_name)
        pr_lines.append(f"- **Remove** `{old_name}`\n  Justification: {just}")

# 4) Read tfvars file lines
with open(sys.argv[2]) as f:
    lines = f.read().splitlines()

# Apply removals first
for old_name in removals:
    start, end, had_comma = find_block(lines, old_name)
    if start is None:
        die(f"Could not locate block for removal of {old_name}")
    # Drop those lines
    lines = lines[:start] + lines[end+1:]
    # If the removed block was the _last_ (no comma), strip the comma of the previous line
    if not had_comma:
        idx = start - 1
        while idx >= 0 and not lines[idx].strip():
            idx -= 1
        if idx >= 0 and lines[idx].rstrip().endswith(','):
            lines[idx] = lines[idx].rstrip()[:-1]

# Then apply updates
for old_name, new_rule in updates:
    start, end, had_comma = find_block(lines, old_name)
    if start is None:
        die(f"Could not locate block for update of {old_name}")

    # Serialize the new block to JSON text
    raw = json.dumps(new_rule, indent=2)
    raw_lines = raw.splitlines()
    indent = re.match(r'^(\s*)', lines[start]).group(1)
    new_block = [indent + l for l in raw_lines]
    # Preserve the trailing comma if originally present
    if had_comma:
        new_block[-1] += ','

    # Replace in-place
    lines = lines[:start] + new_block + lines[end+1:]

# 5) Write patched file
with open(sys.argv[3], 'w') as f:
    f.write('\n'.join(lines) + '\n')

# 6) Emit outputs
print(f"::set-output name=reqid::{reqid}")
print(f"::set-output name=pr_body::{chr(10).join(pr_lines)}")
print(f"::set-output name=ownership_changed::{str(ownership_changed).lower()}")
print("✅ Done.")
