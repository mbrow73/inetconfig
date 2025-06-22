#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def die(msg):
    print(f"❌ Validation error: {msg}")
    sys.exit(1)

if len(sys.argv) < 3:
    die("Usage: validate_firewall_request.py <rule_json> <tfvars_path>")

# Load the rule from the issue
raw = json.loads(sys.argv[1])
data = { k.strip('_'): v for k, v in raw.items() }

# Load existing rules from the tfvars file (if any)
tfvars_path = sys.argv[2]
try:
    with open(tfvars_path) as f:
        tfvars = json.load(f)
except Exception:
    tfvars = {}

existing = []
for rules_key in ['inet_firewall_rules', 'auto_firewall_rules', 'manual_firewall_rules']:
    existing.extend(tfvars.get(rules_key, []))

# -- 1) Required fields
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
    if key not in data or not data[key].strip():
        die(f"Missing required field {key}")

# -- 1a) Protocol must be lowercase in the issue template
protocol = data["protocol"]
if protocol != protocol.lower():
    die("Protocol must be specified in all lowercase (e.g., 'tcp', 'udp', 'icmp').")

if protocol not in ("tcp", "udp", "icmp"):
    die("Protocol must be 'tcp', 'udp', or 'icmp' (all lowercase).")

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

# -- 5) Validate Request ID
if not re.match(r'^REQ\d+$', data["request_id_reqid"]):
    die("Request ID must follow REQ<digits>, e.g. REQ12345")

# -- 6) Duplicate Rule Detection
def normalize_rule(r):
    # Always compare protocol in upper, but require lowercase on input for hygiene
    proto = r.get("protocol", "")
    proto_cmp = proto.upper() if proto else ""
    return {
        "src_ip_ranges": sorted([ip.strip() for ip in r.get("src_ip_ranges", r.get("source_ip_s_or_cidr_s", "")).split(",")]) if isinstance(r.get("src_ip_ranges", r.get("source_ip_s_or_cidr_s", "")), str) else sorted(r.get("src_ip_ranges", [])),
        "dest_ip_ranges": sorted([ip.strip() for ip in r.get("dest_ip_ranges", r.get("destination_ip_s_or_cidr_s", "")).split(",")]) if isinstance(r.get("dest_ip_ranges", r.get("destination_ip_s_or_cidr_s", "")), str) else sorted(r.get("dest_ip_ranges", [])),
        "ports": sorted([str(p).strip() for p in r.get("ports", r.get("port_s", "")).split(",")]) if isinstance(r.get("ports", r.get("port_s", "")), str) else sorted([str(p).strip() for p in r.get("ports", [])]),
        "protocol": proto_cmp,
        "direction": r.get("direction", "").upper()
    }

incoming = normalize_rule(data)

for exist in existing:
    if normalize_rule(exist) == incoming:
        die("Duplicate rule: functionally identical rule already exists in firewall config.")

print("✅ Validation passed")
