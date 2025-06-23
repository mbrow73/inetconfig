#!/usr/bin/env python3
import sys, json, glob, re
from ipaddress import ip_network

def die(msg):
    print(f"❌ Validation error: {msg}")

def load_existing_rules():
    existing = []
    # 1) Manual rules
    try:
        man = json.load(open("manual.auto.tfvars.json"))
        existing += man.get("manual_firewall_rules", [])
    except FileNotFoundError:
        pass

    # 2) All auto-request files
    for fn in glob.glob("firewall_requests/*.json"):
        try:
            req = json.load(open(fn))
            existing += req.get("rules", [])
        except Exception:
            print(f"⚠️ Warning: could not read {fn}", file=sys.stderr)
    return existing

def normalize(r):
    # same normalizer you already have, e.g. listify & uppercase
    proto = r["protocol"].upper()
    def to_list(val):
        if isinstance(val, list): return sorted([str(x).strip() for x in val])
        return sorted([x.strip() for x in str(val).split(",")])
    return {
        "src": to_list(r.get("src_ip_ranges") or r.get("source_ip_s_or_cidr_s", "")),
        "dst": to_list(r.get("dest_ip_ranges") or r.get("destination_ip_s_or_cidr_s", "")),
        "ports": to_list(r.get("ports") or r.get("port_s", "")),
        "proto": proto,
        "dir": r["direction"].upper()
    }

def main(parsed_file):
    data = json.load(open(parsed_file))
    errs = 0

    # Field‐level & syntax checks first
    for idx, rule in enumerate(data["rules"], start=1):
        missing = [k for k in (
            "source_ip_s_or_cidr_s",
            "destination_ip_s_or_cidr_s",
            "port_s",
            "protocol",
            "direction",
            "business_justification",
            "request_id_reqid"
          ) if not rule.get(k)]
        if missing:
            die(f"Rule#{idx} missing fields: {', '.join(missing)}")
            errs += 1
            continue
        # you can add your IP/port/dir checks here…

    # Duplicate & overlap checks
    existing = load_existing_rules()
    existing_norm = [normalize(r) for r in existing]
    for idx, r in enumerate(data["rules"], start=1):
        norm = normalize(r)
        # Duplicate
        if norm in existing_norm:
            die(f"Rule#{idx} is a duplicate of an existing rule.")
            errs += 1
        # Overlap
        for en in existing_norm:
            if norm["proto"] == en["proto"] and norm["dir"] == en["dir"]:
                # any CIDR overlap?
                if any(ip_network(a, strict=False).overlaps(ip_network(b, strict=False))
                       for a in norm["src"] for b in en["src"]) \
                   and any(ip_network(a, strict=False).overlaps(ip_network(b, strict=False))
                       for a in norm["dst"] for b in en["dst"]) \
                   and (set(norm["ports"]) & set(en["ports"])):
                    die(f"Rule#{idx} overlaps existing rule.")
                    errs += 1
                    break

    if errs == 0:
        print("✅ Validation passed")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: validate_firewall_requests.py <parsed.json>")
        sys.exit(1)
    main(sys.argv[1])
