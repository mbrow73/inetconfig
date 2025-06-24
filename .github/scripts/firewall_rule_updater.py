import re
import sys
import os
import glob
import json
import shutil
import ipaddress

def validate_reqid(reqid):
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid))

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

def update_rule_fields(rule, updates, new_reqid):
    # Keep the rest of the rule, but update only fields provided
    for k, v in updates.items():
        if v:
            # handle protocol normalization
            if k == "protocol":
                v = v.lower()
            rule[k] = v
    # Update the name and description to use the new REQID
    parts = rule["name"].split("-")
    parts[1] = new_reqid  # REQ
    rule["name"] = "-".join(parts)
    # Update description if it contains old REQID
    desc = rule.get("description", "")
    old_reqid = parts[2] if len(parts) > 2 else ""
    rule["description"] = rule["name"] + " | " + rule.get("description", "").split("|",1)[-1]
    # Optionally: Add/update a 'history' field here
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
    return errors

def main():
    # Accept issue body as single arg
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

    # Parse all rule blocks
    rule_blocks = re.split(r"#### Rule", issue_body, flags=re.IGNORECASE)[1:]
    updates = []
    for idx, block in enumerate(rule_blocks, 1):
        # Current Rule Name is required
        m_name = re.search(r"Current Rule Name.*?:\s*([A-Za-z0-9\-]+)", block, re.IGNORECASE)
        rule_name = m_name.group(1).strip() if m_name else None
        if not rule_name:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        # Parse fields (optional)
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
            "description": extract("New Business Justification"),
        })

    # Load all current rules and their file paths
    rule_map, file_map = load_all_rules()

    # Actually apply updates
    rules_to_write = {}  # filename -> list of rules
    updated_rule_names = set()
    for update in updates:
        idx = update["idx"]
        rule_name = update["rule_name"]
        if rule_name not in rule_map:
            errors.append(f"Rule {idx}: No rule found in codebase with name '{rule_name}'.")
            continue
        rule = rule_map[rule_name]
        old_file = file_map[rule_name]
        # Remove rule from its old file's rule list (will rewrite below)
        if old_file not in rules_to_write:
            with open(old_file) as f:
                data = json.load(f)
            rules_to_write[old_file] = [r for r in data.get("auto_firewall_rules", []) if r["name"] != rule_name]
        else:
            rules_to_write[old_file] = [r for r in rules_to_write[old_file] if r["name"] != rule_name]
        # Prepare updates (ignore blank fields)
        new_fields = {}
        if update["src_ip_ranges"]: new_fields["src_ip_ranges"] = update["src_ip_ranges"]
        if update["dest_ip_ranges"]: new_fields["dest_ip_ranges"] = update["dest_ip_ranges"]
        if update["ports"]: new_fields["ports"] = update["ports"]
        if update["protocol"]: new_fields["protocol"] = update["protocol"]
        if update["direction"]: new_fields["direction"] = update["direction"]
        if update["description"]: new_fields["description"] = update["description"]
        rule = update_rule_fields(rule, new_fields, new_reqid)
        # Validate new rule
        rule_errors = validate_rule(rule, idx=idx)
        if rule_errors: errors.extend(rule_errors)
        # Queue for writing
        updated_rule_names.add(rule["name"])
        rules_to_write.setdefault(old_file, []).append(rule)

    # If no errors, handle file renaming if necessary
    if not errors:
        for old_file, rules in rules_to_write.items():
            if not rules:
                os.remove(old_file)
                continue
            # Determine if filename needs to be changed
            filename_reqs = re.findall(r"REQ\d{7,8}", old_file)
            if new_reqid and (not filename_reqs or new_reqid not in filename_reqs):
                new_name = new_reqid + "-" + "-".join(filename_reqs) + ".auto.tfvars.json"
                new_path = os.path.join(os.path.dirname(old_file), new_name)
                with open(new_path, "w") as f:
                    json.dump({"auto_firewall_rules": rules}, f, indent=2)
                if os.path.abspath(old_file) != os.path.abspath(new_path):
                    os.remove(old_file)
            else:
                with open(old_file, "w") as f:
                    json.dump({"auto_firewall_rules": rules}, f, indent=2)

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
