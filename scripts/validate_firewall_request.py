#!/usr/bin/env python3
import sys, json, re
from ipaddress import ip_network

def die(msg):
    print(f"❌ Validation error: {msg}")
    sys.exit(1)

data = json.loads(sys.argv[1])

# Required keys
required = [
    "source_ip_s_or_cidrs",
    "destination_ip_s_or_cidrs",
    "ports",
    "protocol",
    "direction",
    "business_justification",
    "request_id"
]
for k in required:
    if k not in data or not data[k]:
        die(f"Missing required field `{k}`")

# Validate IP/CIDRs
for field in ("source_ip_s_or_cidrs","destination_ip_s_or_cidrs"):
    for part in re.split(r'[,\s]+', data[field]):
        try:
            ip_network(part, strict=False)
        except Exception:
            die(f"Invalid CIDR/IP `{part}` in {field}")

# Validate ports
port_re = re.compile(r'^\d+(-\d+)?$')
for p in re.split(r'[,\s]+', data["ports"]):
    if not port_re.match(p) or not (0 < int(p.split('-')[0]) <= 65535):
        die(f"Invalid port or port range `{p}`")

# Protocol & direction
if data["protocol"].upper() not in ("TCP","UDP","ICMP"):
    die("Protocol must be TCP, UDP, or ICMP")
if data["direction"].upper() not in ("INGRESS","EGRESS"):
    die("Direction must be INGRESS or EGRESS")

# REQID format
if not re.match(r'^REQ\d+$', data["request_id"]):
    die("Request ID must follow REQ<digits>, e.g. REQ12345")

print("✅ Validation passed")