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
    # Extract protocol, ports, direction for rule name
    proto = updates.get("protocol") or rule["protocol"]
    ports = updates.get("ports") or rule["ports"]
    direction = updates.get("direction") or rule["direction"]
    carid = new_carid or rule["name"].split("-")[2]
    # Rule name: AUTO-REQID-CARID-PROTO-PORTS-INDEX
    parts = rule["name"].split("-")
    idx = parts[-1] if len(parts) > 1 else "1"
    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    rule["name"] = new_name

    # Update all relevant fields if specified
    for k, v in updates.items():
        if v:
            if k in ["protocol", "direction"]:
                rule[k] = v.lower()
            else:
                rule[k] = v

    # Update CARID in description
    desc_just = updates.get("description") or rule.get("description", "").split("|",1)[-1]
    rule["description"] = f"{new_name} | {desc_just.strip()}"
    return rule

def validate_rule(rule, idx=1):
    errors = []
    # Validate IPs
    for field in ["src_ip_ranges", "dest_ip_ranges"]:
        for ip in rule.get(field, []):
            if not validate_ip(ip):
                errors.append(f"Rule {idx}: Invalid {field.replace('_',' ')} '{ip}'. Please use a valid IP or CIDR.")
    # Ports
    for port in rule.get("ports", []):
        if not validate_port(port):
            errors.append(f"Rule {idx}: Invalid port or range: '{port}'.")
    # Protocol
    proto = rule.get("protocol", "")
    if proto != proto.lower() or not validate_protocol(proto):
        errors.append(f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp (lowercase). Found: '{proto}'")
    # Direction
    if rule.get("direction","").upper() not in {"INGRESS", "EGRESS"}:
        errors.append(f"Rule {idx}: Direction must be INGRESS or EGRESS.")
    # CARID
    carid = rule["name"].split("-")[2]
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found: '{carid}'.")
    return errors

def parse_blocks(issue_body):
    # Matches "#### Rule N" or "Rule N", splits on each, returns blocks
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    # The first block is before Rule 1, so skip it
    return [b for b in blocks[1:] if b.strip()]

def main():
    # Accept issue body as single arg or from stdin
    if len(sys.argv) == 2:
        issue_body = sys.argv[1]
    else:
        issue_body = sys.stdin.read()
    errors = []

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
        rule_name = m_name.group(1) if m_name else None
        if rule_name:
            rule_name = rule_name.strip().lstrip("*").strip().lstrip(":").strip()
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
    # Track for each file: list of (orig_rule_name, updated_rule or None)
    rules_update_map = {}  # file -> {old_rule_name: updated_rule_obj or None}
    updates_by_file = {}   # file -> list of updates for that file

    # Map updates to rules and files
    for update in updates:
        idx = update["idx"]
        rule_name = update["rule_name"]
        if rule_name not in rule_map:
            errors.append(f"Rule {idx}: No rule found in codebase with name '{rule_name}'.")
            continue
        rule = rule_map[rule_name]
        old_file = file_map[rule_name]
        updates_by_file.setdefault(old_file, []).append((rule_name, update))

    # Build final rules for each file, preserving original order
    for file_path, file_updates in updates_by_file.items():
        # Load original file content and order
        with open(file_path) as f:
            original_data = json.load(f)
        original_rule_list = original_data.get("auto_firewall_rules", [])

        # Build a dict of rule_name -> update
        updates_dict = {ru[0]: ru[1] for ru in file_updates}

        # Track new rules after update
        new_rule_list = []
        updated_names = set()

        for orig_rule in original_rule_list:
            old_name = orig_rule["name"]
            if old_name in updates_dict:
                upd = updates_dict[old_name]
                # Prepare update dict
                new_fields = {}
                if upd["src_ip_ranges"]: new_fields["src_ip_ranges"] = upd["src_ip_ranges"]
                if upd["dest_ip_ranges"]: new_fields["dest_ip_ranges"] = upd["dest_ip_ranges"]
                if upd["ports"]: new_fields["ports"] = upd["ports"]
                if upd["protocol"]: new_fields["protocol"] = upd["protocol"]
                if upd["direction"]: new_fields["direction"] = upd["direction"]
                if upd["description"]: new_fields["description"] = upd["description"]
                new_carid = upd["carid"]
                # Apply changes
                rule = update_rule_fields(orig_rule.copy(), new_fields, new_reqid, new_carid)
                rule_errors = validate_rule(rule, idx=upd["idx"])
                if rule_errors: errors.extend(rule_errors)
                new_rule_list.append(rule)
                updated_names.add(old_name)
            else:
                # Not updated, keep original
                new_rule_list.append(orig_rule)

    # If no errors, handle file renaming if needed
        if not errors:
            # If file doesn't already have new REQID, rename
            filename_reqs = re.findall(r"REQ\d{7,8}", file_path)
            if new_reqid and (not filename_reqs or new_reqid not in filename_reqs):
                new_name = new_reqid + "-" + "-".join(filename_reqs) + ".auto.tfvars.json"
                new_path = os.path.join(os.path.dirname(file_path), new_name)
                with open(new_path, "w") as f:
                    json.dump({"auto_firewall_rules": new_rule_list}, f, indent=2)
                if os.path.abspath(file_path) != os.path.abspath(new_path):
                    os.remove(file_path)
            else:
                with open(file_path, "w") as f:
                    json.dump({"auto_firewall_rules": new_rule_list}, f, indent=2)

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
