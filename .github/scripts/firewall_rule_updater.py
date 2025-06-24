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

    # --- New robust logic below ---

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

        # Map rule_name -> update object for this file
        update_map = {u["rule_name"]: u for u in update_list}

        # Replace rules as needed
        new_rules = []
        for idx, rule in enumerate(orig_rules, 1):
            if rule["name"] in update_map:
                update = update_map[rule["name"]]
                # Prepare update dict
                new_fields = {}
                if update["src_ip_ranges"]: new_fields["src_ip_ranges"] = update["src_ip_ranges"]
                if update["dest_ip_ranges"]: new_fields["dest_ip_ranges"] = update["dest_ip_ranges"]
                if update["ports"]: new_fields["ports"] = update["ports"]
                if update["protocol"]: new_fields["protocol"] = update["protocol"]
                if update["direction"]: new_fields["direction"] = update["direction"]
                if update["description"]: new_fields["description"] = update["description"]
                new_carid = update["carid"]
                # Apply changes
                updated_rule = update_rule_fields(rule.copy(), new_fields, new_reqid, new_carid)
                rule_errors = validate_rule(updated_rule, idx=update["idx"])
                if rule_errors: errors.extend(rule_errors)
                new_rules.append(updated_rule)
            else:
                new_rules.append(rule)

        # If no errors, write/rename file
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

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
