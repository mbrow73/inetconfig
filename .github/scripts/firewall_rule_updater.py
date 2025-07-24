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
    except:
        return False

def validate_port(port):
    if re.fullmatch(r"\d{1,5}", port):
        n = int(port); return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port):
        a, b = map(int, port.split('-')); return 1 <= a <= b <= 65535
    return False

def validate_protocol(proto):
    return proto in {"tcp","udp","icmp","sctp"}

def load_all_rules():
    rule_map, file_map = {}, {}
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        data = json.load(open(path))
        for rule in data.get("auto_firewall_rules",[]):
            rule_map[rule["name"]] = rule
            file_map[rule["name"]] = path
    return rule_map, file_map

def update_rule_fields(rule, updates, new_reqid, new_carid):
    idx     = rule.get("_update_index", 1)
    proto   = updates.get("protocol") or rule["protocol"]
    ports   = updates.get("ports")    or rule["ports"]
    direction=updates.get("direction") or rule["direction"]
    carid   = new_carid or rule["name"].split("-")[2]

    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    rule["name"] = new_name

    for k,v in updates.items():
        if v:
            rule[k] = v.lower() if k in ["protocol","direction"] else v

    desc_just = updates.get("description") or rule.get("description","").split("|",1)[-1]
    rule["description"] = f"{new_name} | {desc_just.strip()}"
    return rule

def validate_rule(rule, idx=1):
    errs = []
    for field in ["src_ip_ranges","dest_ip_ranges"]:
        for ip in rule.get(field,[]):
            if not validate_ip(ip):
                errs.append(f"Rule {idx}: Invalid {field.replace('_',' ')} '{ip}'.")
    for p in rule.get("ports",[]):
        if not validate_port(p):
            errs.append(f"Rule {idx}: Invalid port/range '{p}'.")
    proto = rule.get("protocol","")
    if proto!=proto.lower() or not validate_protocol(proto):
        errs.append(f"Rule {idx}: Protocol must be tcp, udp, icmp or sctp.")
    if rule.get("direction","").upper() not in {"INGRESS","EGRESS"}:
        errs.append(f"Rule {idx}: Direction must be INGRESS or EGRESS.")
    carid = rule["name"].split("-")[2]
    if not validate_carid(carid):
        errs.append(f"Rule {idx}: CARID must be 9 digits. Found '{carid}'.")
    return errs

def parse_blocks(body):
    parts = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", body, flags=re.IGNORECASE)
    return [b for b in parts[1:] if b.strip()]

def make_update_summary(idx, old_name, old_rule, updates, new_rule):
    changes=[]
    for key,label in [
        ("src_ip_ranges","Source"),
        ("dest_ip_ranges","Destination"),
        ("ports","Ports"),
        ("protocol","Protocol"),
        ("direction","Direction"),
        ("description","Justification"),
    ]:
        old = old_rule.get(key)
        new = updates.get(key) if updates.get(key) else None
        if new is not None and old!=new:
            ov=",".join(old) if isinstance(old,list) else old
            nv=",".join(new) if isinstance(new,list) else new
            changes.append(f"{label}: `{ov}` → `{nv}`")
    if old_name!=new_rule["name"]:
        changes.append(f"Rule Name: `{old_name}` → `{new_rule['name']}`")
    if not changes:
        changes=["(No functional changes requested)"]
    return f"- **Rule {idx}** (`{old_name}`): " + "; ".join(changes)

def print_errors(errs):
    print("VALIDATION_ERRORS_START")
    for e in errs: print(e)
    print("VALIDATION_ERRORS_END")
    sys.exit(1)

def main():
    body = sys.argv[1] if len(sys.argv)==2 else sys.stdin.read()
    errors, summaries = [], []
    # --- 1) REQID ---
    m = re.search(r"New Request ID.*?:\s*([A-Z0-9]+)", body, re.IGNORECASE)
    new_reqid = m.group(1).strip() if m else None
    if not new_reqid or not validate_reqid(new_reqid):
        errors.append(f"New REQID must be 'REQ' plus 7-8 digits. Found '{new_reqid}'.")
        print_errors(errors)

    # --- 2) Parse blocks & build updates only if fields beyond REQID/CARID are present ---
    blocks = parse_blocks(body)
    updates=[]
    for idx,blk in enumerate(blocks,1):
        mname = re.search(r"Current Rule Name.*?:\s*([^\n]+)", blk, re.IGNORECASE)
        if not mname:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        rule_name = mname.group(1).strip()
        def ex(l): 
            mm = re.search(rf"{l}.*?:\s*(.+)", blk, re.IGNORECASE)
            return mm.group(1).strip() if mm else ""
        entry = {
            "idx": idx,
            "rule_name": rule_name,
            "src_ip_ranges": [i.strip() for i in ex("New Source IP").split(",") if i.strip()],
            "dest_ip_ranges":[i.strip() for i in ex("New Destination IP").split(",") if i.strip()],
            "ports":[p.strip() for p in ex("New Port").split(",") if p.strip()],
            "protocol":ex("New Protocol"),
            "direction":ex("New Direction"),
            "description":ex("New Business Justification"),
            "carid":ex("New CARID"),    # we ignore CARID-only updates too
        }
        # only keep if at least one of these six fields is non-empty
        if any([entry[k] for k in
                ["src_ip_ranges","dest_ip_ranges","ports","protocol","direction","description"]]):
            updates.append(entry)

    # --- 3) Load rules & locate files ---
    rule_map, file_map = load_all_rules()

    # --- 4) Group by file and apply ---
    updates_by_file={}
    for u in updates:
        if u["rule_name"] not in file_map:
            errors.append(f"Rule {u['idx']}: No rule named '{u['rule_name']}' found.")
            continue
        updates_by_file.setdefault(file_map[u["rule_name"]],[]).append(u)

    for path, ulist in updates_by_file.items():
        data    = json.load(open(path))
        orig    = data.get("auto_firewall_rules",[])
        new_rules=[]
        for i,rule in enumerate(orig,1):
            matched = [u for u in ulist if u["rule_name"]==rule["name"]]
            if not matched:
                new_rules.append(rule)
                continue
            u = matched[0]
            to_up=rule.copy(); to_up["_update_index"]=i
            updated = update_rule_fields(to_up, u, new_reqid, u.get("carid") or None)
            errs = validate_rule(updated, idx=u["idx"])
            if errs:
                errors.extend(errs)
            else:
                new_rules.append(updated)
                summaries.append(make_update_summary(u["idx"], rule["name"], rule, u, updated))
        # write file only if changed
        if new_rules!=orig:
            newname = f"{new_reqid}-{os.path.basename(path)}"
            newpath = os.path.join(os.path.dirname(path), newname)
            json.dump({"auto_firewall_rules":new_rules}, open(newpath,"w"), indent=2)
            if os.path.abspath(newpath)!=os.path.abspath(path):
                os.remove(path)

    if errors:
        print_errors(errors)

    if summaries:
        with open("rule_update_summary.txt","w") as fo:
            for line in summaries:
                fo.write(line+"\n")

if __name__=="__main__":
    main()
