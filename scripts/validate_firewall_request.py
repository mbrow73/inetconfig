#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def die(msg):
    print(f"❌ Validation error: {msg}")
    sys.exit(1)

# Load the raw parsed-issue JSON for a single rule
raw = json.loads(sys.argv[1])

# Normalize keys: strip leading/trailing underscores
data = { k.strip('_'): v for k, v in raw.items() }

# ── 1) Required fields ──────────────────────────────────────────────
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

# ── 2) Validate IP/CIDRs ────────────────────────────────────────────
for field in ("source_ip_s_or_cidr_s", "destination_ip_s_or_cidr_s"):
    for part in re.split(r'[,\s]+', data[field]):
        try:
            ip_network(part, strict=False)
        except Exception:
            die(f"Invalid CIDR/IP `{part}` in `{field}`")

# ── 3) Validate ports ───────────────────────────────────────────────
port_re = re.compile(r'^\d+(-\d+)?$')
for p in re.split(r'[,\s]+', data["port_s"]):
    if not port_re.match(p) or not (0 < int(p.split('-')[0]) <= 65535):
        die(f"Invalid port or range `{p}`")

# ── 4) Validate protocol & direction ────────────────────────────────
if data["protocol"].upper() not in ("TCP", "UDP", "ICMP"):
    die("Protocol must be TCP, UDP, or ICMP")
if data["direction"].upper() not in ("INGRESS", "EGRESS"):
    die("Direction must be INGRESS or EGRESS")

# ── 5) Validate Request ID ─────────────────────────────────────────
if not re.match(r'^REQ\d+$', data["request_id_reqid"]):
    die("Request ID must follow REQ<digits>, e.g. REQ12345")

# ── 6) Check for functionally duplicate rule ───────────────────────
# Load existing rules from tfvars (if path provided)
if len(sys.argv) > 2:
    try:
        with open(sys.argv[2]) as f:
            existing = json.load(f)
            # Prefer inet_firewall_rules, fallback to auto_firewall_rules
            rules_key = 'inet_firewall_rules' if 'inet_firewall_rules' in existing else (
                'auto_firewall_rules' if 'auto_firewall_rules' in existing else None)
            existing_rules = existing.get(rules_key, []) if rules_key else []
    except Exception:
        existing_rules = []
else:
    existing_rules = []

def canonicalize(rule):
    # Accepts both "source_ip_s_or_cidr_s" and "src_ip_ranges" keys
    def get_ips(field_name):
        val = rule.get(field_name)
        if not val:
            # try alternate key
            alt = 'src_ip_ranges' if field_name.startswith('source') else 'dest_ip_ranges'
            val = rule.get(alt)
        if isinstance(val, list):
            return sorted([ip.strip().lower() for ip in val])
        return sorted([ip.strip().lower() for ip in re.split(r'[,\s]+', val or '') if ip.strip()])

    return (
        tuple(get_ips("source_ip_s_or_cidr_s")),
        tuple(get_ips("destination_ip_s_or_cidr_s")),
        tuple(sorted([p.strip() for p in (rule.get("port_s") or ','.join(rule.get("ports", []))).split(",") if p.strip()])),
        (rule.get("protocol") or rule.get("ip_protocol", "")).strip().upper(),
        rule.get("direction", "").strip().upper(),
        rule.get("action", "allow").strip().lower()  # default action is "allow"
    )

new_rule_canon = canonicalize(data)

for rule in existing_rules:
    if canonicalize(rule) == new_rule_canon:
        die("Duplicate rule detected: A functionally identical rule already exists (same src, dest, ports, protocol, direction, and action).")

print("✅ Validation passed")
