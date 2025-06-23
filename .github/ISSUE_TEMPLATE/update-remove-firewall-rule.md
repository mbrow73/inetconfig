---
name: Firewall Rule Update/Removal Request
about: Request an update or removal of existing firewall rule(s).
labels: ["firewall-update-request"]
---

### Request ID (REQID): REQxxxxxx

### CARID: xxxxxxxxx

<!-- Copy one “#### Rule” block per rule you want to change -->

#### Rule 1
🔹 Existing Rule Name: `AUTO-APP1-REQ12345-1-TCP-443`  
🔹 Action: `update`  
🔹 New Source IP(s) or CIDR(s): `203.0.113.55/32`  
🔹 New Destination IP(s) or CIDR(s): `10.1.2.22/32`  
🔹 New Port(s): `443`  
🔹 New Protocol: `tcp`  
🔹 New Direction: `INGRESS`  
🔹 New Business Justification: Need to restrict to a smaller range

#### Rule 2
🔹 Existing Rule Name: `AUTO-APP2-REQ99999-1-TCP-80`  
🔹 Action: `remove`

<!-- Repeat “#### Rule N” as needed -->