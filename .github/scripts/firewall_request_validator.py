import re
import sys
import ipaddress
import glob
import json
from collections import defaultdict

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

def port_is_subset(child, parent):
    """Returns True if every port in 'child' is also in 'parent'."""
    def expand(p):
        res = set()
        for part in p.split(","):
            part = part.strip()
            if '-' in part:
                a, b = map(int, part.split('-'))
                res.update(range(a, b+1))
            else:
                res.add(int(part))
        return res
    return expand(child).issubset(expand(parent))

def protocol_is_subset(child, parent):
    return child == parent

def network_is_subset(child, parent):
    try:
        return ipaddress.ip_network(child, strict=False).subnet_of(ipaddress.ip_network(parent, strict=False))
    except Exception:
        return False

def validate_protocol(proto):
    return proto in {"tcp", "udp", "icmp", "sctp"}

def parse_rule_block(block):
    def extract(field, fallback=""):
        m = re.search(rf"{field}.*?:\s*(.+)", block, re.IGNORECASE)
        return m.group(1).strip() if m else fallback

    return {
        "src": extract("New Source"),
        "dst": extract("New Destination"),
        "ports": extract("New Port"),
        "proto": extract("New Protocol"),
        "direction": extract("New Direction"),
        "just": extract("New Business Justification"),
    }

def parse_existing_rules():
    """Parse all rules in firewall-requests/*.auto.tfvars.json as a list of dicts"""
    rules = []
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            with open(path) as f:
                data = json.load(f)
                for r in data.get("auto_firewall_rules", []):
                    # Use only the first value in src_ip_ranges/dest_ip_ranges/ports for comparison (simplified for demo)
                    rules.append({
                        "src": ",".join(r.get("src_ip_ranges", [])),
                        "dst": ",".join(r.get("dest_ip_ranges", [])),
                        "ports": ",".join(r.get("ports", [])),
                        "proto": r.get("protocol"),
                        "direction": r.get("direction"),
                    })
        except Exception as e:
            continue
    return rules

def rule_exact_match(rule, rulelist):
    for r in rulelist:
        if (rule["src"] == r["src"] and
            rule["dst"] == r["dst"] and
            rule["ports"] == r["ports"] and
            rule["proto"] == r["proto"] and
            rule["direction"] == r["direction"]):
            return True
    return False

def rule_is_redundant(rule, rulelist):
    """Checks if any rule in rulelist completely covers this rule (src/dst/proto/ports/direction superset)"""
    for r in rulelist:
        if (rule["direction"] == r["direction"] and
            protocol_is_subset(rule["proto"], r["proto"])):
            # All src/dst in rule are subset of those in r
            srcs_child = [s.strip() for s in rule["src"].split(",")]
            srcs_parent = [s.strip() for s in r["src"].split(",")]
            dsts_child = [s.strip() for s in rule["dst"].split(",")]
            dsts_parent = [s.strip() for s in r["dst"].split(",")]
            srcs_covered = all(any(network_is_subset(c, p) for p in srcs_parent) for c in srcs_child)
            dsts_covered = all(any(network_is_subset(c, p) for p in dsts_parent) for c in dsts_child)
            ports_covered = port_is_subset(rule["ports"], r["ports"])
            if srcs_covered and dsts_covered and ports_covered:
                return True
    return False

def main():
    issue_file = sys.argv[1]
    with open(issue_file) as f:
        issue = f.read()

    errors = []

    # Extract REQID
    m_reqid = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue, re.IGNORECASE)
    reqid = m_reqid.group(1).strip() if m_reqid else None
    if not reqid or not validate_reqid(reqid):
        errors.append(f"❌ REQID must be in format 'REQ' followed by 7 or 8 digits (e.g. REQ1234567). Found: '{reqid}'")

    # Extract CARID
    m_carid = re.search(r"CARID.*?:\s*(\d+)", issue, re.IGNORECASE)
    carid = m_carid.group(1).strip() if m_carid else None
    if not carid or not validate_carid(carid):
        errors.append(f"❌ CARID must be exactly 9 numerical digits. Found: '{carid}'")

    # Extract Rule blocks
    rule_blocks = re.split(r"#### Rule", issue, flags=re.IGNORECASE)[1:]  # Skip the header
    seen = set()
    for idx, block in enumerate(rule_blocks, 1):
        rule = parse_rule_block(block)
        src, dst, ports, proto, direction, just = (
            rule["src"], rule["dst"], rule["ports"], rule["proto"], rule["direction"], rule["just"]
        )
        # Field presence
        if not all([src, dst, ports, proto, direction, just]):
            errors.append(f"❌ Rule {idx}: All fields must be present and non-empty.")
            continue
        # Protocol
        if proto != proto.lower() or not validate_protocol(proto):
            errors.append(f"❌ Rule {idx}: Protocol must be lowercase and one of tcp, udp, icmp, sctp. Found: '{proto}'")
        # IP validation
        for ip_field, value in [("source", src), ("destination", dst)]:
            for ip in value.split(","):
                if not validate_ip(ip.strip()):
                    errors.append(f"❌ Rule {idx}: Invalid {ip_field} IP/CIDR: '{ip.strip()}'")
        # Port validation
        for port in ports.split(","):
            if not validate_port(port.strip()):
                errors.append(f"❌ Rule {idx}: Invalid port or range: '{port.strip()}'")
        # Duplicate within request
        key = (src, dst, ports, proto, direction)
        if key in seen:
            errors.append(f"❌ Rule {idx}: Duplicate rule (source, dest, ports, proto, direction) within this request.")
        seen.add(key)

    # Global duplicate/redundant check (across all firewall-requests/*.auto.tfvars.json)
    existing_rules = parse_existing_rules()
    for idx, block in enumerate(rule_blocks, 1):
        rule = parse_rule_block(block)
        # Only check if rule fields are all present and valid
        if not all([rule["src"], rule["dst"], rule["ports"], rule["proto"], rule["direction"]]):
            continue
        if rule_exact_match(rule, existing_rules):
            errors.append(f"❌ Rule {idx}: Rule is an exact duplicate of an existing rule in the rulebase.")
        elif rule_is_redundant(rule, existing_rules):
            errors.append(f"❌ Rule {idx}: Rule is already covered (redundant) by an existing broader rule in the rulebase.")

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
