import sys, json
from ipaddress import ip_network

# 1) Load the parsed JSON
data = json.loads(sys.argv[1])
rules_in = data["rules"]

# 2) Load existing tfvars
with open(sys.argv[2]) as f:
    tfdata = json.load(f)
tf_rules = tfdata.get("auto_firewall_rules", [])

for idx, issue in enumerate(rules_in, start=1):
    # compute priority
    max_prio = max((r.get("priority",0) for r in tf_rules), default=1000)
    prio = max_prio + 1

    # build a unique rule name, e.g. REQ12345-1, REQ12345-2
    name = f"{issue['request_id']}-{idx}"

    new_rule = {
        "name":             name,
        "description":      issue["business_justification"],
        "direction":        issue["direction"].upper(),
        "src_ip_ranges":    [ip.strip() for ip in issue["source_ip_s_or_cidr_s"].split(",")],
        "dest_ip_ranges":   [ip.strip() for ip in issue["destination_ip_s_or_cidr_s"].split(",")],
        "protocol":         issue["protocol"].upper(),
        "ports":            [p.strip() for p in issue["port_s"].split(",")],
        "enable_logging":   True,
        "action":           "allow",
        "priority":         prio
    }

    tf_rules.append(new_rule)

# 3) Write back
tfdata["auto_firewall_rules"] = tf_rules
with open(sys.argv[2], "w") as f:
    json.dump(tfdata, f, indent=2)

print(f"✅ Appended {len(rules_in)} rule(s) for {rules_in[0]['request_id']}")
