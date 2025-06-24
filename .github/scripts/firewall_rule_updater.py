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
    proto = updates.get("protocol") or rule["protocol"]
    ports = updates.get("ports") or rule["ports"]
    direction = updates.get("direction") or rule["direction"]
    carid = new_carid or rule["name"].split("-")[2]
    # Rule name: AUTO-REQID-CARID-PROTO-PORTS-INDEX
    parts = rule["name"].split("-")
    idx = parts[-1] if len(parts) > 1 else "1"
    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    rule["name"] = new_name

    for k, v in updates.items():
        if v:
            if k in ["protocol", "direction"]:
                rule[k] = v.lower()
            else:
                rule[k] = v

    desc_just = updates.get("description") or rule.get("description", "").split("|",1)[-1]
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
    # Matches "#### Rule N" or "Rule N", splits on each, returns blocks
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]

def make_update_summary(idx, rule_name, old_rule, updates, new_rule):
    changes = []
    # Compare each field and output old -> new if changed
    for k, label in [
        ("src_ip_ranges", "Source"),
        ("dest_ip_ranges", "Destination"),
        ("ports", "Ports"),
        ("protocol", "Protocol"),
        ("direction", "Direction"),
        ("carid", "CARID"),
        ("description", "Justification"),
    ]:
        old = old_rule.get(k)
        new = updates.get(k) if updates.get(k) else None
        if new is not None and old != new:
            old_val = ','.join(old) if isinstance(old, list) else old
            new_val = ','.join(new) if isinstance(new, list) else new
            changes.append(f"{label}: `{old_val}` → `{new_val}`")
    # Always show new rule name
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
        m_name = re.search(r"Current Rule Name.*?:\s*([^\n]+)", block, re.IGNORECASE)
        rule_name = m_name.group(1).strip() if m_name else None
        if not rule_name:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        def extract(label):
            m = re.search(rf"{label}.*?:\s*(.+)", block, re.IGNORECASE)
            val = m.group(1).strip() if m else ""
            return val

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

    # Load all rules and file paths
    rule_map, file_map = load_all_rules()

    # Group update requests by file
    updates_by_file = {}
    for update in updates:
        rule_name = update["rule_name"]
        if rule_name not in file_map:
            errors.append(f"Rule {update['idx']}: No rule found in codebase with name '{rule_name}'.")
            continue
        file = file_map[rule_name]
        updates_by_file.setdefault(file, []).append(update)

    # For each file, rewrite rules with updated versions in-place, preserving order
    for file, update_list in updates_by_file.items():
        with open(file) as f:
            file_data = json.load(f)
        orig_rules = file_data.get("auto_firewall_rules", [])

        update_map = {u["rule_name"]: u for u in update_list}
        new_rules = []
        for idx, rule in enumerate(orig_rules, 1):
            if rule["name"] in update_map:
                update = update_map[rule["name"]]
                new_fields = {}
                if update["src_ip_ranges"]: new_fields["src_ip_ranges"] = update["src_ip_ranges"]
                if update["dest_ip_ranges"]: new_fields["dest_ip_ranges"] = update["dest_ip_ranges"]
                if update["ports"]: new_fields["ports"] = update["ports"]
                if update["protocol"]: new_fields["protocol"] = update["protocol"]
                if update["direction"]: new_fields["direction"] = update["direction"]
                if update["description"]: new_fields["description"] = update["description"]
                new_carid = update["carid"]
                updated_rule = update_rule_fields(rule.copy(), new_fields, new_reqid, new_carid)
                rule_errors = validate_rule(updated_rule, idx=update["idx"])
                if rule_errors: errors.extend(rule_errors)
                new_rules.append(updated_rule)

                # Build PR summary for this rule
                summaries.append(make_update_summary(update["idx"], rule["name"], rule, update, updated_rule))
            else:
                new_rules.append(rule)

        if not errors:
            filename_reqs = re.findall(r"REQ\d{7,8}", file)
            if new_reqid and (not filename_reqs or new_reqid not in filename_reqs):
                new_name = new_reqid + "-" + "-".join(filename_reqs) + ".auto.tfvars.json"
                new_path = os.path.join(os.path.dirname(file), new_name)
                with open(new_path, "w") as f:
                    json.dump({"auto_firewall_rules": new_rules}, f, indent=2)
                if os.path.abspath(file) != os.path.abspath(new_path):
                    os.remove(file)
            else:
                with open(file, "w") as f:
                    json.dump({"auto_firewall_rules": new_rules}, f, indent=2)

    if not errors:
        # Write the PR summary
        with open("rule_update_summary.txt", "w") as f:
            for line in summaries:
                f.write(line + "\n")

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
