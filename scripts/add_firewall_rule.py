#!/usr/bin/env python3
import sys, json
from json.decoder import JSONDecodeError

def main():
    if len(sys.argv) < 3:
        print("❌ Usage: add_firewall_rule.py '<parsed-json-string>' <tfvars-file>")
        sys.exit(1)

    raw_json = sys.argv[1]
    tfpath   = sys.argv[2]

    # 1) Load parsed input
    try:
        parsed = json.loads(raw_json)
    except JSONDecodeError as e:
        print(f"❌ Failed to parse JSON input: {e}")
        sys.exit(1)

    rules_in = parsed.get("rules")
    if not isinstance(rules_in, list) or not rules_in:
        print("❌ No 'rules' list found or it's empty in input")
        sys.exit(1)

    # 2) Load or initialize tfvars data
    try:
        with open(tfpath) as f:
            data = json.load(f)
            if not isinstance(data, dict):
                data = {}
    except (JSONDecodeError, FileNotFoundError):
        data = {}

    key = "auto_firewall_rules"
    existing = data.get(key)
    if not isinstance(existing, list):
        existing = []

    for idx, rule in enumerate(rules_in, start=1):
        max_prio = max((r.get("priority", 0) for r in existing), default=1000)
        new_prio = max_prio + 1
        rid      = rule.get("request_id_reqid")
        team     = rule.get("team_id", "UNKNOWNTEAM").upper()   # Fallback if missing
        proto    = rule.get("protocol", "").upper()
        ports    = [p.strip() for p in rule.get("port_s", "").split(",") if p.strip()]
        ports_str = "-".join(ports) if ports else "ANY"

        # Construct the rule name with Team ID
        name     = f"AUTO-{team}-{rid}-{idx}-{proto}-{ports_str}"

        new_rule = {
            "name":             name,
            "description":      rule.get("business_justification", ""),
            "direction":        rule.get("direction", "").upper(),
            "src_ip_ranges":    [ip.strip() for ip in rule.get("source_ip_s_or_cidr_s", "").split(",") if ip.strip()],
            "dest_ip_ranges":   [ip.strip() for ip in rule.get("destination_ip_s_or_cidr_s", "").split(",") if ip.strip()],
            "protocol":         proto,
            "ports":            ports,
            "enable_logging":   True,
            "action":           "allow",
            "tls_inspection":   False,
            "priority":         new_prio
        }

        existing.append(new_rule)
        print(f"✅ Appended rule {name} with priority {new_prio}")

    data[key] = existing
    with open(tfpath, "w") as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    main()
