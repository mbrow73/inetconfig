#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def validate_ip(ip):
    try:
        ip_network(ip, strict=False)
        return True
    except Exception:
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
ownership_changes = []
reqid = issue['reqid'].strip()
carid = issue['carid'].strip()

# Pull all rules into a flat list
rules = []
for rules_key in ['inet_firewall_rules', 'auto_firewall_rules', 'manual_firewall_rules']:
    rules.extend(tfvars.get(rules_key, []))
rules_by_name = {r['name']: r for r in rules}

for r in issue['rules']:
    ex_name = r['existing_rule_name'].strip()
    if r.get('action', '').strip().lower() == 'remove':
        # Remove rule
        removed_rules.append(ex_name)
        continue

    # Parse new fields (for update)
    src = r.get('new_source_ips', '').strip('`')
    dst = r.get('new_destination_ips', '').strip('`')
    port = r.get('new_ports', '').strip('`')
    proto = r.get('new_protocol', '').strip('`').lower()
    direction = r.get('new_direction', '').strip('`').upper()
    just = r.get('new_justification', '').strip()

    # Validations
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

    # Find old rule, update
    if ex_name not in rules_by_name:
        print(f"Validation failed: Rule {ex_name} not found in tfvars!")
        sys.exit(1)
    old = rules_by_name[ex_name]
    # Change REQID and CARID in rule name if needed
    parts = ex_name.split('-')
    # Format: AUTO-APP1-REQ12345-1-TCP-443
    if len(parts) >= 6:
        parts[1] = carid
        parts[2] = reqid
        new_name = '-'.join(parts)
    else:
        new_name = ex_name  # fallback

    ownership_changed = False
    if old.get('carid', '') != carid:
        ownership_changed = True
    # Build new rule object
    new_rule = dict(old)  # start with the old rule
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

# Now, rewrite rules for output
final_rules = []
for r in rules:
    # If removing, skip
    if r['name'] in removed_rules:
        continue
    # If updating, use new rule
    updated = next(((oldname, nr, oc) for oldname, nr, oc in updated_rules if oldname == r['name']), None)
    if updated:
        final_rules.append(updated[1])
    else:
        final_rules.append(r)

# Re-assemble tfvars structure (replace the key you use for automation)
tfvars['auto_firewall_rules'] = final_rules

with open(sys.argv[3], 'w') as f:
    json.dump(tfvars, f, indent=2)

# Output PR labels for automation
for _, _, oc in updated_rules:
    if oc:
        print("::set-output name=ownership_changed::true")
        break
else:
    print("::set-output name=ownership_changed::false")

print("✅ Update/Remove complete.")
