#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def validate_ip(ip):
    try:
        ip_network(ip, strict=False)
        return True
    except:
        return False

def validate_ports(ports):
    pr = re.compile(r'^\d+(-\d+)?$')
    for p in re.split(r'[,\s]+', ports):
        if not pr.match(p) or not (0 < int(p.split('-')[0]) <= 65535):
            return False
    return True

def validate_protocol(proto):
    return proto in ("tcp", "udp", "icmp")

def validate_direction(direction):
    return direction.upper() in ("INGRESS", "EGRESS")

if len(sys.argv) < 4:
    print("Usage: update_remove_firewall_rule.py <parsed_issue.json> <tfvars_in> <tfvars_out>")
    sys.exit(1)

# Load inputs
with open(sys.argv[1]) as f:
    issue = json.load(f)
with open(sys.argv[2]) as f:
    tfvars = json.load(f)

reqid = issue['reqid'].strip()
carid = issue['carid'].strip()

# Gather all existing rules
all_rules = []
for key in ['inet_firewall_rules', 'auto_firewall_rules', 'manual_firewall_rules']:
    all_rules.extend(tfvars.get(key, []))
rules_map = {r['name']: r for r in all_rules}

updated = []
removed = []

for r in issue['rules']:
    name = r.get('existing_rule_name', '').strip()
    action = r.get('action','update').strip().lower()

    if action == 'remove':
        removed.append(name)
        continue

    src = r.get('new_source_ips','').strip('`')
    dst = r.get('new_destination_ips','').strip('`')
    ports = r.get('new_ports','').strip('`')
    proto = r.get('new_protocol','').strip('`').lower()
    direction = r.get('new_direction','').strip('`').upper()
    just = r.get('new_justification','').strip()

    # Required fields check
    if not (name and src and dst and ports and proto and direction and just and reqid and carid):
        print(f"Validation failed: missing fields for update of rule {name}")
        sys.exit(1)
    if not all(validate_ip(x) for x in re.split(r'[,\s]+', src)):
        print(f"Validation failed: bad source IP/CIDR in {name}")
        sys.exit(1)
    if not all(validate_ip(x) for x in re.split(r'[,\s]+', dst)):
        print(f"Validation failed: bad dest IP/CIDR in {name}")
        sys.exit(1)
    if not validate_ports(ports):
        print(f"Validation failed: bad port(s) in {name}")
        sys.exit(1)
    if not validate_protocol(proto):
        print(f"Validation failed: protocol must be tcp/udp/icmp in {name}")
        sys.exit(1)
    if not validate_direction(direction):
        print(f"Validation failed: direction must be INGRESS/EGRESS in {name}")
        sys.exit(1)

    if name not in rules_map:
        print(f"Validation failed: rule {name} not found")
        sys.exit(1)
    old = rules_map[name]

    parts = name.split('-')
    if len(parts) >= 6:
        parts[1] = carid
        parts[2] = reqid
        new_name = '-'.join(parts)
    else:
        new_name = name

    ownership_changed = (old.get('carid','') != carid)

    new_rule = dict(old)
    new_rule.update({
        'name': new_name,
        'src_ip_ranges': [x.strip() for x in src.split(',')],
        'dest_ip_ranges': [x.strip() for x in dst.split(',')],
        'ports': [x.strip() for x in ports.split(',')],
        'protocol': proto,
        'direction': direction,
        'description': just,
        'carid': carid
    })
    updated.append((name, new_rule, ownership_changed))

# Rebuild rule list
final = []
for r in all_rules:
    if r['name'] in removed:
        continue
    match = next((u for u in updated if u[0] == r['name']), None)
    final.append(match[1] if match else r)

tfvars['auto_firewall_rules'] = final
with open(sys.argv[3], 'w') as f:
    json.dump(tfvars, f, indent=2)

# Emit ownership change flag
flag = any(u[2] for u in updated)
print(f"::set-output name=ownership_changed::{str(flag).lower()}")

print("✅ Update/Remove complete.")
