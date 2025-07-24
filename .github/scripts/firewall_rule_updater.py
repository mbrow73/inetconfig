import re
import sys
import os
import glob
import json
import ipaddress

def validate_reqid(reqid):
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid))

def validate_carid(carid):
    return bool(re.fullmatch(r"\d{9}", carid))

def validate_ip(ip):
    try:
        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def validate_port(port):
    if re.fullmatch(r"\d{1,5}", port):
        n = int(port)
        return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port):
        a, b = map(int, port.split('-'))
        return 1 <= a <= b <= 65535
    return False

def validate_protocol(proto):
    return proto in {"tcp", "udp", "icmp", "sctp"}

def load_all_rules():
    rule_map = {}
    file_map = {}
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        with open(path) as f:
            data = json.load(f)
            for rule in data.get("auto_firewall_rules", []):
                rule_map[rule["name"]] = rule
                file_map[rule["name"]] = path
    return rule_map, file_map

def update_rule_fields(rule, updates, new_reqid, new_carid):
    """
    Update fields and rename rule using new_reqid and stored index.
    """
    idx = rule.get("_update_index", 1)
    proto = updates.get("protocol") or rule["protocol"]
    ports = updates.get("ports") or rule["ports"]
    direction = updates.get("direction") or rule["direction"]
    carid = new_carid or rule["name"].split("-")[2]

    # Construct new rule name without old REQID
    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    rule["name"] = new_name

    # Apply updates to fields
    for k, v in updates.items():
        if v:
            if k in ["protocol", "direction"]:
                rule[k] = v.lower()
            else:
                rule[k] = v

    desc_just = updates.get("description") or rule.get("description", "").split("|", 1)[-1]
    rule["description"] = f"{new_name} | {desc_just.strip()}"
    return rule

def validate_rule(rule, idx=1):
    errors = []
    for field in ["src_ip_ranges", "dest_ip_ranges"]:
        for ip in rule.get(field, []):
            if not validate_ip(ip):
                errors.append(f"Rule {idx}: Invalid {field.replace('_',' ')} '{ip}'. Please use a valid IP or CIDR.")
    for port in rule.get("ports", []):
        if not validate_port(port):
            errors.append(f"Rule {idx}: Invalid port or range: '{port}'.")
    proto = rule.get("protocol", "")
    if proto != proto.lower() or not validate_protocol(proto):
        errors.append(f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp (lowercase). Found: '{proto}'")
    if rule.get("direction","").upper() not in {"INGRESS", "EGRESS"}:
        errors.append(f"Rule {idx}: Direction must be INGRESS or EGRESS.")
    carid = rule["name"].split("-")[2]
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found: '{carid}'.")
    return errors

def parse_blocks(issue_body):
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]

def make_update_summary(idx, rule_name, old_rule, updates, new_rule):
    changes = []
    labels = [
        ("src_ip_ranges", "Source"),
        ("dest_ip_ranges", "Destination"),
        ("ports", "Ports"),
        ("protocol", "Protocol"),
        ("direction", "Direction"),
        ("carid", "CARID"),
        ("description", "Justification"),
    ]
    for k, label in labels:
        old = old_rule.get(k)
        new = updates.get(k) if updates.get(k) else None
        if new is not None and old != new:
            old_val = ','.join(old) if isinstance(old, list) else old
            new_val = ','.join(new) if isinstance(new, list) else new
            changes.append(f"{label}: `{old_val}` → `{new_val}`")
    if old_rule["name"] != new_rule["name"]:
        changes.append(f"Rule Name: `{old_rule['name']}` → `{new_rule['name']}`")
    if not changes:
        changes = ["(No fields updated, only name/desc changed)"]
    return f"- **Rule {idx}** (`{old_rule['name']}`): " + "; ".join(changes)

def main():
    if len(sys.argv) == 2:
        issue_body = sys.argv[1]
    else:
        issue_body = sys.stdin.read()
    errors = []
    summaries = []

    # Parse new REQID
    m_reqid = re.search(r"New Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    new_reqid = m_reqid.group(1).strip() if m_reqid else None
    if not new_reqid or not validate_reqid(new_reqid):
        errors.append(f"New REQID must be 'REQ' followed by 7 or 8 digits. Found: '{new_reqid}'.")

    # Parse rule blocks
    rule_blocks = parse_blocks(issue_body)
    updates = []
    for idx, block in enumerate(rule_blocks, 1):
        # Ensure we have a Current Rule Name
        m_name = re.search(r"Current Rule Name.*?:\s*([^\n]+)", block, re.IGNORECASE)
        if not m_name:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        rule_name = m_name.group(1).strip()

        # Extract all other fields
        def extract(label):
            m = re.search(rf"{label}.*?:\s*(.+)", block, re.IGNORECASE)
            return m.group(1).strip() if m else ""

        updates.append({
            "idx": idx,
            "rule_name": rule_name,
            "src_ip_ranges": [ip.strip() for ip in extract("New Source IP").split(",") if ip.strip()],
            "dest_ip_ranges": [ip.strip() for ip in extract("New Destination IP").split(",") if ip.strip()],
            "ports": [p.strip() for p in extract("New Port").split(",") if p.strip()],
            "protocol": extract("New Protocol"),
            "direction": extract("New Direction"),
            "carid": extract("New CARID"),
            "description": extract("New Business Justification"),
        })

    # Load existing rules
    rule_map, file_map = load_all_rules()

    # Group updates by file path
    updates_by_file = {}
    for update in updates:
        rule_name = update["rule_name"]
        if rule_name not in file_map:
            errors.append(f"Rule {update['idx']}: No rule found in codebase with name '{rule_name}'.")
            continue
        file = file_map[rule_name]
        updates_by_file.setdefault(file, []).append(update)

    # Apply updates per file
    for file, update_list in updates_by_file.items():
        with open(file) as f:
            file_data = json.load(f)
        orig_rules = file_data.get("auto_firewall_rules", [])

        new_rules = []
        for idx, rule in enumerate(orig_rules, 1):
            if rule["name"] in {u["rule_name"] for u in update_list}:
                update = next(u for u in update_list if u["rule_name"] == rule["name"])
                new_fields = {}
                if update["src_ip_ranges"]: new_fields["src_ip_ranges"] = update["src_ip_ranges"]
                if update["dest_ip_ranges"]: new_fields["dest_ip_ranges"] = update["dest_ip_ranges"]
                if update["ports"]: new_fields["ports"] = update["ports"]
                if update["protocol"]: new_fields["protocol"] = update["protocol"]
                if update["direction"]: new_fields["direction"] = update["direction"]
                if update["description"]: new_fields["description"] = update["description"]
                new_carid = update["carid"]

                # attach index for naming
                to_update = rule.copy()
                to_update["_update_index"] = idx
                updated_rule = update_rule_fields(to_update, new_fields, new_reqid, new_carid)

                rule_errors = validate_rule(updated_rule, idx=update["idx"])
                if rule_errors:
                    errors.extend(rule_errors)
                new_rules.append(updated_rule)

                # Build PR summary
                summaries.append(make_update_summary(update["idx"], rule["name"], rule, update, updated_rule))
            else:
                new_rules.append(rule)

        if not errors:
            dirpath = os.path.dirname(file)
            new_filename = f"{new_reqid}-{os.path.basename(file)}"
            new_path = os.path.join(dirpath, new_filename)

            with open(new_path, "w") as f:
                json.dump({"auto_firewall_rules": new_rules}, f, indent=2)

            if os.path.abspath(file) != os.path.abspath(new_path):
                os.remove(file)

    # Write summary if no errors
    if not errors:
        with open("rule_update_summary.txt", "w") as f:
            for line in summaries:
                f.write(line + "\n")

    # Output validation errors if any
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
