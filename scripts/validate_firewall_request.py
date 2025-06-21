#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def die(msg):
    print(f"❌ Validation error: {msg}")
    sys.exit(1)

def normalize_rule(rule):
    """Turn a rule into a tuple of its essential fields (excluding name/priority) for comparison."""
    return (
        tuple(sorted([ip.strip() for ip in rule.get("src_ip_ranges", [])])),
        tuple(sorted([ip.strip() for ip in rule.get("dest_ip_ranges", [])])),
        tuple(sorted([str(p).strip() for p in rule.get("ports", [])])),
        rule.get("protocol", "").upper(),
        rule.get("direction", "").upper(),
        rule.get("action", "").lower()
    )

# Parse input rule (single rule as JSON string)
raw = json.loads(sys.argv[1])
data = { k.strip('_'): v for k, v in raw.items() }

# --- Existing rules file (optional 2nd argument) ---
existing_rules = []
if len(sys.argv) > 2:
    try:
        with open(sys.argv[2]) as f:
            tfvars = json.load(f)
            existing_rules = tfvars.get("inet_firewall_rules", []) + tfvars.get("auto_firewall_rules", [])
    except Exception as e:
        print(f"⚠️ Could not parse existing rules file: {e}")

# --- Usual field validation ---
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
        die(f"Missing required field `{key}`")

for field in ("source_ip_s_or_cidr_s", "destination_ip_s_or_cidr_s"):
    for part in re.split(r'[,\s]+', data[field]):
        try:
            ip_network(part, strict=False)
        except Exception:
            die(f"Invalid CIDR/IP `{part}` in `{field}`")

port_re = re.compile(r'^\d+(-\d+)?$')
for p in re.split(r'[,\s]+', data["port_s"]):
    if not port_re.match(p) or not (0 < int(p.split('-')[0]) <= 65535):
        die(f"Invalid port or range `{p}`")

if data["protocol"].upper() not in ("TCP", "UDP", "ICMP"):
    die("Protocol must be TCP, UDP, or ICMP")
if data["direction"].upper() not in ("INGRESS", "EGRESS"):
    die("Direction must be INGRESS or EGRESS")
if not re.match(r'^REQ\d+$', data["request_id_reqid"]):
    die("Request ID must follow REQ<digits>, e.g. REQ12345")

# --- Duplicate detection ---
if existing_rules:
    # Build a normalized candidate
    candidate = {
        "src_ip_ranges": [ip.strip() for ip in data["source_ip_s_or_cidr_s"].split(",")],
        "dest_ip_ranges": [ip.strip() for ip in data["destination_ip_s_or_cidr_s"].split(",")],
        "ports": [p.strip() for p in data["port_s"].split(",")],
        "protocol": data["protocol"].upper(),
        "direction": data["direction"].upper(),
        "action": "allow"  # Adjust if you support other actions!
    }
    candidate_key = normalize_rule(candidate)
    for r in existing_rules:
        # Defensive: some rules may not have all fields
        rule_obj = {
            "src_ip_ranges": r.get("src_ip_ranges", []),
            "dest_ip_ranges": r.get("dest_ip_ranges", []),
            "ports": r.get("ports", []),
            "protocol": r.get("protocol", "").upper(),
            "direction": r.get("direction", "").upper(),
            "action": r.get("action", "allow").lower()
        }
        if normalize_rule(rule_obj) == candidate_key:
            die("This rule is a duplicate of an existing rule in the policy. Please review existing rules.")

print("✅ Validation passed")
