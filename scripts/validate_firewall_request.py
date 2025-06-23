#!/usr/bin/env python3
import sys, json, re, glob
from ipaddress import ip_network

def die(msg):
    print(f"❌ Validation error: {msg}")
    sys.exit(1)

# Usage: validate_firewall_request.py '<rule_json>'
if len(sys.argv) != 2:
    die("Usage: validate_firewall_request.py <rule_json>")

# Load incoming rule from issue
try:
    raw = json.loads(sys.argv[1])
except json.JSONDecodeError as e:
    die(f"Invalid JSON for rule: {e}")

# Normalize keys (strip leading underscores)
data = { k.strip('_'): v for k, v in raw.items() }

# -- 1) Check required fields
required = [
    "source_ip_s_or_cidr_s",
    "destination_ip_s_or_cidr_s",
    "port_s",
    "protocol",
    "direction",
    "business_justification",
    "request_id_reqid"
]
for key in required:
    if key not in data or not str(data[key]).strip():
        die(f"Missing required field {key}")

# -- 1a) Protocol lowercase
proto = data["protocol"]
if proto != proto.lower():
    die("Protocol must be lowercase (e.g., 'tcp', 'udp', 'icmp').")
if proto not in ("tcp", "udp", "icmp"):
    die("Protocol must be 'tcp', 'udp', or 'icmp'.")

# -- 2) Validate IP/CIDRs
for field in ("source_ip_s_or_cidr_s", "destination_ip_s_or_cidr_s"):
    for part in re.split(r'[,\s]+', data[field]):
        try:
            ip_network(part, strict=False)
        except Exception:
            die(f"Invalid CIDR/IP {part} in {field}")

# -- 3) Validate ports
port_re = re.compile(r'^\d+(-\d+)?$')
for p in re.split(r'[,\s]+', data["port_s"]):
    if not port_re.match(p) or not (0 < int(p.split('-')[0]) <= 65535):
        die(f"Invalid port or range {p}")

# -- 4) Validate direction
if data["direction"].upper() not in ("INGRESS", "EGRESS"):
    die("Direction must be INGRESS or EGRESS")

# -- 5) Validate Request ID format
if not re.match(r'^REQ\d+$', data["request_id_reqid"]):
    die("Request ID must follow REQ<digits>, e.g. REQ12345")

# -- Load existing rules from manual and auto JSON files
existing = []
# manual rules
try:
    man = json.load(open("manual.auto.tfvars.json"))
    existing.extend(man.get("manual_firewall_rules", []))
except FileNotFoundError:
    pass
# auto-generated requests
for fn in glob.glob("firewall_requests/*.json"):
    try:
        req = json.load(open(fn))
        existing.extend(req.get("rules", []))
    except Exception:
        continue

# -- Helpers for normalization

def normalize(rule):
    proto_cmp = rule.get("protocol", "").upper()
    def to_list(val):
        if isinstance(val, list): return sorted([str(v).strip() for v in val])
        return sorted([v.strip() for v in str(val).split(',')])
    return {
        "src_ip_ranges": to_list(rule.get("src_ip_ranges") or rule.get("source_ip_s_or_cidr_s")),
        "dest_ip_ranges": to_list(rule.get("dest_ip_ranges") or rule.get("destination_ip_s_or_cidr_s")),
        "ports": to_list(rule.get("ports") or rule.get("port_s")),
        "protocol": proto_cmp,
        "direction": rule.get("direction", "").upper()
    }

# -- 6) Duplicate detection
incoming = normalize(data)
for ex in existing:
    if normalize(ex) == incoming:
        die("Duplicate rule: an identical rule already exists.")

# -- 7) Overlap detection

def cidr_overlap(a, b):
    try:
        return ip_network(a, strict=False).overlaps(ip_network(b, strict=False))
    except:
        return False

def ports_set(val):
    s = set()
    parts = val if isinstance(val, list) else [v.strip() for v in str(val).split(',')]
    for p in parts:
        if '-' in p:
            lo, hi = map(int, p.split('-'))
            s.update(range(lo, hi+1))
        else:
            s.add(int(p))
    return s

new_srcs = normalize(data)["src_ip_ranges"]
new_dsts = normalize(data)["dest_ip_ranges"]
new_ports = ports_set(data["port_s"])
new_proto = data["protocol"]
new_dir = data["direction"].upper()

for ex in existing:
    ex_norm = normalize(ex)
    if ex_norm["protocol"] != new_proto.upper() or ex_norm["direction"] != new_dir:
        continue
    exist_srcs = ex_norm["src_ip_ranges"]
    exist_dsts = ex_norm["dest_ip_ranges"]
    exist_ports = ports_set(ex.get("ports") or ex.get("port_s", []))
    for ns in new_srcs:
        for es in exist_srcs:
            if cidr_overlap(ns, es):
                for nd in new_dsts:
                    for ed in exist_dsts:
                        if cidr_overlap(nd, ed) and new_ports & exist_ports:
                            die(f"Overlap detected with existing rule {ex.get('name')}")

print("✅ Validation passed")