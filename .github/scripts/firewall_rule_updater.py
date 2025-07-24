#!/usr/bin/env python3
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
    Rename and update the rule in-place, using only the passed-in index
    and update fields.
    """
    idx = rule.get("_update_index", 1)
    proto = updates.get("protocol") or rule["protocol"]
    ports = updates.get("ports") or rule["ports"]
    direction = updates.get("direction") or rule["direction"]
    carid = new_carid or rule["name"].split("-")[2]

    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    rule["name"] = new_name

    for k, v in updates.items():
        if v:
            rule[k] = v.lower() if k in ["protocol", "direction"] else v

    desc_just = updates.get("description") or rule.get("description", "").split("|",1)[-1]
    rule["description"] = f"{new_name} | {desc_just.strip()}"
    return rule

def validate_rule(rule, idx=1):
    errors = []
    for field in ["src_ip_ranges", "dest_ip_ranges"]:
        for ip in rule.get(field, []):
            if not validate_ip(ip):
                errors.append(f"Rule {idx}: Invalid {field.replace('_',' ')} '{ip}'.")
    for port in rule.get("ports", []):
        if not validate_port(port):
            errors.append(f"Rule {idx}: Invalid port or range: '{port}'.")
    proto = rule.get("protocol", "")
    if proto != proto.lower() or not validate_protocol(proto):
        errors.append(f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp.")
    if rule.get("direction","").upper() not in {"INGRESS","EGRESS"}:
        errors.append(f"Rule {idx}: Direction must be INGRESS or EGRESS.")
    carid = rule["name"].split("-")[2]
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found '{carid}'.")
    return errors

def parse_blocks(issue_body):
    parts = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in parts[1:] if b.strip()]

def make_update_summary(idx, rule_name, old_rule, updates, new_rule):
    changes = []
    labels = [
        ("src_ip_ranges","Source"),
        ("dest_ip_ranges","Destination"),
        ("ports","Ports"),
        ("protocol","Protocol"),
        ("direction","Direction"),
        ("description","Justification"),
    ]
    for k,label in labels:
        old = old_rule.get(k)
        new = updates.get(k) if updates.get(k) else None
        if new is not None and old != new:
            old_val = ",".join(old) if isinstance(old,list) else old
            new_val = ",".join(new) if isinstance(new,list) else new
            changes.append(f"{label}: `{old_val}` → `{new_val}`")
    if old_rule["name"] != new_rule["name"]:
        changes.append(f"Rule Name: `{old_rule['name']}` → `{new_rule['name']}`")
    if not changes:
        changes = ["(No fields updated, only name/desc would change)"]
    return f"- **Rule {idx}** (`{old_rule['name']}`): " + "; ".join(changes)

def main():
    # load the issue body
    if len(sys.argv)==2:
        issue_body = sys.argv[1]
    else:
        issue_body = sys.stdin.read()

    errors, summaries = [], []

    # 1) Parse new REQID
    m = re.search(r"New Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    new_reqid = m.group(1).strip() if m else None
    if not new_reqid or not validate_reqid(new_reqid):
        errors.append(f"New REQID must be 'REQ' plus 7–8 digits. Found '{new_reqid}'.")
        print_errors(errors)

    # 2) Parse blocks & build update entries
    blocks = parse_blocks(issue_body)
    updates = []
    for idx,blk in enumerate(blocks,1):
        mname = re.search(r"Current Rule Name.*?:\s*([^\n]+)", blk, re.IGNORECASE)
        if not mname:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        rule_name = mname.group(1).strip()

        # gather any fields the user actually provided
        def extract(label):
            mm = re.search(rf"{label}.*?:\s*(.+)", blk, re.IGNORECASE)
            return mm.group(1).strip() if mm else ""

        entry = {
            "idx": idx,
            "rule_name": rule_name,
            "src_ip_ranges": [i.strip() for i in extract("New Source IP").split(",") if i.strip()],
            "dest_ip_ranges": [i.strip() for i in extract("New Destination IP").split(",") if i.strip()],
            "ports": [p.strip() for p in extract("New Port").split(",") if p.strip()],
            "protocol": extract("New Protocol"),
            "direction": extract("New Direction"),
            "description": extract("New Business Justification"),
        }
        # only keep it if they actually filled in at least one field
        if any([
            entry["src_ip_ranges"],
            entry["dest_ip_ranges"],
            entry["ports"],
            entry["protocol"],
            entry["direction"],
            entry["description"]
        ]):
            updates.append(entry)

    # 3) Load existing rules
    rule_map, file_map = load_all_rules()

    # 4) Group updates per file
    updates_by_file = {}
    for u in updates:
        if u["rule_name"] not in file_map:
            errors.append(f"Rule {u['idx']}: No rule named '{u['rule_name']}' in codebase.")
            continue
        updates_by_file.setdefault(file_map[u["rule_name"]], []).append(u)

    # 5) Apply each file’s updates
    for path, ulist in updates_by_file.items():
        with open(path) as f: data = json.load(f)
        orig = data.get("auto_firewall_rules", [])
        new_rules = []

        for i,rule in enumerate(orig,1):
            # did we get updates for this rule?
            matched = [u for u in ulist if u["rule_name"]==rule["name"]]
            if not matched:
                new_rules.append(rule)
                continue

            u = matched[0]
            # attach index for name
            rcopy = rule.copy()
            rcopy["_update_index"] = i

            # apply the update
            updated = update_rule_fields(rcopy, u, new_reqid, None)
            errs = validate_rule(updated, idx=u["idx"])
            if errs:
                errors.extend(errs)
            else:
                new_rules.append(updated)
                summaries.append(make_update_summary(u["idx"], rule["name"], rule, u, updated))

        # if anything changed, write it out
        if new_rules != orig:
            dirn = os.path.dirname(path)
            newname = f"{new_reqid}-{os.path.basename(path)}"
            newpath = os.path.join(dirn, newname)
            with open(newpath, "w") as fo:
                json.dump({"auto_firewall_rules": new_rules}, fo, indent=2)
            if os.path.abspath(newpath)!=os.path.abspath(path):
                os.remove(path)

    # 6) Emit summary or errors
    if errors:
        print_errors(errors)
    if summaries:
        with open("rule_update_summary.txt","w") as fo:
            for l in summaries:
                fo.write(l+"\n")

def print_errors(errs):
    print("VALIDATION_ERRORS_START")
    for e in errs: print(e)
    print("VALIDATION_ERRORS_END")
    sys.exit(1)

if __name__=="__main__":
    main()
