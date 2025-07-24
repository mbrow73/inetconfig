import re
import sys
import ipaddress
import glob
import json
from collections import defaultdict

ALLOWED_PUBLIC_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),     # GCP health‑check
    ipaddress.ip_network("130.211.0.0/22"),    # GCP health‑check
    ipaddress.ip_network("199.36.153.4/30"),   # restricted googleapis
]

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
        n = int(port); return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port):
        a, b = map(int, port.split('-')); return 1 <= a <= b <= 65535
    return False

def port_is_subset(child, parent):
    def expand(p):
        s = set()
        for part in p.split(","):
            part = part.strip()
            if '-' in part:
                a, b = map(int, part.split('-'))
                s.update(range(a, b+1))
            else:
                s.add(int(part))
        return s
    return expand(child).issubset(expand(parent))

def protocol_is_subset(child, parent):
    return child == parent

def network_is_subset(child, parent):
    try:
        return ipaddress.ip_network(child, strict=False).subnet_of(
               ipaddress.ip_network(parent, strict=False))
    except Exception:
        return False

def validate_protocol(proto):
    return proto in {"tcp", "udp", "icmp", "sctp"}

def parse_rule_block(block):
    def extract(field, fallback=""):
        m = re.search(rf"{field}.*?:\s*(.+)", block, re.IGNORECASE)
        return m.group(1).strip() if m else fallback

    return {
        "src":   extract("New Source"),
        "dst":   extract("New Destination"),
        "ports": extract("New Port"),
        "proto": extract("New Protocol"),
        "direction": extract("New Direction"),
        "just":  extract("New Business Justification"),
    }

def parse_existing_rules():
    rules = []
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            data = json.load(open(path))
            for r in data.get("auto_firewall_rules", []):
                rules.append({
                    "src":   ",".join(r.get("src_ip_ranges", [])),
                    "dst":   ",".join(r.get("dest_ip_ranges", [])),
                    "ports": ",".join(r.get("ports", [])),
                    "proto": r.get("protocol"),
                    "direction": r.get("direction"),
                })
        except Exception:
            continue
    return rules

def rule_exact_match(rule, rulelist):
    for r in rulelist:
        if (rule["src"]==r["src"] and rule["dst"]==r["dst"]
         and rule["ports"]==r["ports"] and rule["proto"]==r["proto"]
         and rule["direction"]==r["direction"]):
            return True
    return False

def rule_is_redundant(rule, rulelist):
    for r in rulelist:
        if (rule["direction"]==r["direction"]
         and protocol_is_subset(rule["proto"], r["proto"])):
            srcs_child = [c.strip() for c in rule["src"].split(",")]
            srcs_parent= [p.strip() for p in r["src"].split(",")]
            dsts_child = [c.strip() for c in rule["dst"].split(",")]
            dsts_parent= [p.strip() for p in r["dst"].split(",")]
            if all(any(network_is_subset(c,p) for p in srcs_parent) for c in srcs_child) \
            and all(any(network_is_subset(c,p) for p in dsts_parent) for c in dsts_child) \
            and port_is_subset(rule["ports"], r["ports"]):
                return True
    return False

def main():
    issue_file = sys.argv[1]
    issue = open(issue_file).read()
    errors = []

    # REQID
    m_reqid = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue, re.IGNORECASE)
    reqid = m_reqid.group(1).strip() if m_reqid else None
    if not reqid or not validate_reqid(reqid):
        errors.append(f"❌ REQID must be 'REQ' plus 7–8 digits. Found: '{reqid}'")

    # CARID
    m_carid = re.search(r"CARID.*?:\s*(\d+)", issue, re.IGNORECASE)
    carid = m_carid.group(1).strip() if m_carid else None
    if not carid or not validate_carid(carid):
        errors.append(f"❌ CARID must be exactly 9 digits. Found: '{carid}'")

    # Rule blocks
    blocks = re.split(r"#### Rule", issue, flags=re.IGNORECASE)[1:]
    seen = set()
    for idx, block in enumerate(blocks, 1):
        rule = parse_rule_block(block)
        src, dst, ports, proto, direction, just = (
            rule["src"], rule["dst"], rule["ports"],
            rule["proto"], rule["direction"], rule["just"]
        )

        # presence
        if not all([src, dst, ports, proto, direction, just]):
            errors.append(f"❌ Rule {idx}: All fields must be present.")
            continue

        # protocol
        if proto != proto.lower() or not validate_protocol(proto):
            errors.append(f"❌ Rule {idx}: Protocol must be tcp, udp, icmp or sctp (lowercase).")

        # IP & CIDR rules
        for ip_field, value in [("source", src), ("destination", dst)]:
            for ip in value.split(","):
                ip = ip.strip()
                if not validate_ip(ip):
                    errors.append(f"❌ Rule {idx}: Invalid {ip_field} '{ip}'.")
                    continue
                net = ipaddress.ip_network(ip, strict=False)
                # disallow 0.0.0.0/0
                if net == ipaddress.ip_network("0.0.0.0/0"):
                    errors.append(f"❌ Rule {idx}: {ip_field.capitalize()} may not be 0.0.0.0/0.")
                # no CIDRs larger than /24
                if net.prefixlen < 24:
                    errors.append(f"❌ Rule {idx}: {ip_field.capitalize()} '{ip}' prefix /{net.prefixlen} too large (must be /24 or smaller).")
                # public IP restrictions
                if not net.is_private:
                    allowed = any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES)
                    if not allowed:
                        errors.append(f"❌ Rule {idx}: {ip_field.capitalize()} '{ip}' is public and not in allowed GCP ranges.")

        # port
        for p in ports.split(","):
            if not validate_port(p.strip()):
                errors.append(f"❌ Rule {idx}: Invalid port or range '{p.strip()}'.")

        # duplicate in this request
        key = (src, dst, ports, proto, direction)
        if key in seen:
            errors.append(f"❌ Rule {idx}: Duplicate rule in request.")
        seen.add(key)

    # global duplicates/redundancy
    existing = parse_existing_rules()
    for idx, block in enumerate(blocks, 1):
        rule = parse_rule_block(block)
        if not all([rule["src"], rule["dst"], rule["ports"], rule["proto"], rule["direction"]]):
            continue
        if rule_exact_match(rule, existing):
            errors.append(f"❌ Rule {idx}: Exact duplicate of existing rule.")
        elif rule_is_redundant(rule, existing):
            errors.append(f"❌ Rule {idx}: Redundant—covered by existing broader rule.")

    # output
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors: print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
