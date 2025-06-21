#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def die(msg):
    print(f"❌ Validation error: {msg}")
    sys.exit(1)

# Load the raw parsed-issue JSON
raw = json.loads(sys.argv[1])

# Normalize keys: strip leading/trailing underscores
data = { k.strip('_'): v for k, v in raw.items() }

# ── 1) Required fields ────────────────────────────────────────────────────────
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

# ── 2) Validate IP/CIDRs ──────────────────────────────────────────────────────
for field in ("source_ip_s_or_cidr_s", "destination_ip_s_or_cidr_s"):
    for part in re.split(r'[,\s]+', data[field]):
        try:
            ip_network(part, strict=False)
        except Exception:
            die(f"Invalid CIDR/IP `{part}` in `{field}`")

# ── 3) Validate ports ──────────────────────────────────────────────────────────
port_re = re.compile(r'^\d+(-\d+)?$')
for p in re.split(r'[,\s]+', data["port_s"]):
    if not port_re.match(p) or not (0 < int(p.split('-')[0]) <= 65535):
        die(f"Invalid port or range `{p}`")

# ── 4) Validate protocol & direction ──────────────────────────────────────────
if data["protocol"].upper() not in ("TCP", "UDP", "ICMP"):
    die("Protocol must be TCP, UDP, or ICMP")
if data["direction"].upper() not in ("INGRESS", "EGRESS"):
    die("Direction must be INGRESS or EGRESS")

# ── 5) Validate Request ID ────────────────────────────────────────────────────
if not re.match(r'^REQ\d+$', data["request_id_reqid"]):
    die("Request ID must follow REQ<digits>, e.g. REQ12345")

print("✅ Validation passed")
