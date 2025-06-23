---
name: Firewall Rule Update/Removal Request
about: Request an update or removal of an existing firewall rule.
labels: ["firewall-update-request"]
---

### Request ID (REQID): REQxxxxxx

### CARID: xxxxxxxxx

### Action Type  
<!-- `update` or `remove` -->
Action: `update`

#### Rule 1 (Update Example)
🔹 Existing Rule Name: `AUTO-APP1-REQ12345-1-TCP-443`  
🔹 New Source IP(s) or CIDR(s): `203.0.113.55/32`  
🔹 New Destination IP(s) or CIDR(s): `10.1.2.22/32`  
🔹 New Port(s): `443`  
🔹 New Protocol: `tcp`  
🔹 New Direction: `INGRESS`  
🔹 New Business Justification: Need to restrict to a smaller range

#### Rule 2 (Removal Example)
🔹 Existing Rule Name: `AUTO-APP2-REQ99999-1-TCP-80`  
🔹 Action: `remove`

<!-- Repeat rule blocks as needed -->
