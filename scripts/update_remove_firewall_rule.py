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
    port_re = re.compile(r'^\d+(-\d+)?$')
    for p in re.split(r'[,\s]+', ports):
        if not port_re.match(p) or not (0 < int(p.split('-')[0]) <= 65535):
            return False
    return True

def validate_protocol(proto):
    return proto in ("tcp", "udp", "icmp")

def validate_direction(direction):
    return direction.upper() in ("INGRESS", "EGRESS")

if len(sys.argv) < 4:
    print("Usage: update_remove_firewall_rule.py <parsed_issue_json> <tfvars_in> <tfvars_out>")
    sys.exit(1)

with open(sys.argv[1]) as f:
    issue = json.load(f)

with open(sys.argv[2]) as f:
    tfvars = json.load(f)

updated_rules = []
removed_rules = []
reqid = issue['reqid'].strip()
carid = issue['carid'].strip()

# Flatten all existing rules
rules = []
for key in ['inet_firewall_rules', 'auto_firewall_rules', 'manual_firewall_rules']:
    rules.extend(tfvars.get(key, []))
rules_by_name = {r['name']: r for r in rules}

for r in issue['rules']:
    ex_name = r.get('existing_rule_name', '').strip()
    action = r.get('action', 'update').strip().lower()
    if action == 'remove':
        removed_rules.append(ex_name)
        continue

    src = r.get('new_source_ips', '').strip('`')
    dst = r.get('new_destination_ips', '').strip('`')
    port = r.get('new_ports', '').strip('`')
    proto = r.get('new_protocol', '').strip('`').lower()
    direction = r.get('new_direction', '').strip('`').upper()
    just = r.get('new_justification', '').strip()

    # Basic presence check
    if not (src and dst and port and proto and direction and just and reqid and carid):
        print(f"Validation failed: All fields required for update of rule {ex_name}")
        sys.exit(1)
    if not all(validate_ip(ip) for ip in re.split(r'[,\s]+', src)):
        print(f"Validation failed: Bad source IP/CIDR in update of rule {ex_name}")
        sys.exit(1)
    if not all(validate_ip(ip) for ip in re.split(r'[,\s]+', dst)):
        print(f"Validation failed: Bad destination IP/CIDR in update of rule {ex_name}")
        sys.exit(1)
    if not validate_ports(port):
        print(f"Validation failed: Bad port(s) in update of rule {ex_name}")
        sys.exit(1)
    if not validate_protocol(proto):
        print(f"Validation failed: Protocol must be 'tcp', 'udp', or 'icmp' in update of rule {ex_name}")
        sys.exit(1)
    if not validate_direction(direction):
        print(f"Validation failed: Direction must be INGRESS or EGRESS in update of rule {ex_name}")
        sys.exit(1)

    if ex_name not in rules_by_name:
        print(f"Validation failed: Rule {ex_name} not found in tfvars!")
        sys.exit(1)
    old = rules_by_name[ex_name]

    # Build new rule-name with updated CARID and REQID
    parts = ex_name.split('-')
    if len(parts) >= 6:
        parts[1] = carid
        parts[2] = reqid
        new_name = '-'.join(parts)
    else:
        new_name = ex_name

    ownership_changed = (old.get('carid', '') != carid)

    new_rule = dict(old)
    new_rule.update({
        'name': new_name,
        'src_ip_ranges': [s.strip() for s in src.split(',')],
        'dest_ip_ranges': [d.strip() for d in dst.split(',')],
        'ports': [p.strip() for p in port.split(',')],
        'protocol': proto,
        'direction': direction,
        'description': just,
        'carid': carid
    })
    updated_rules.append((ex_name, new_rule, ownership_changed))

# Reassemble final rule list
final_rules = []
for r in rules:
    if r['name'] in removed_rules:
        continue
    upd = next((u for u in updated_rules if u[0] == r['name']), None)
    final_rules.append(upd[1] if upd else r)

tfvars['auto_firewall_rules'] = final_rules

with open(sys.argv[3], 'w') as f:
    json.dump(tfvars, f, indent=2)

# Emit ownership change output
ownership_flag = any(u[2] for u in updated_rules)
print(f"::set-output name=ownership_changed::{str(ownership_flag).lower()}")

print("✅ Update/Remove complete.")
