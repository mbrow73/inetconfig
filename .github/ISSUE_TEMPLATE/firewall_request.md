---
name: Firewall Rule Request
about: Request one or more GCP Network Firewall Policy rules
labels: ["firewall-request"]
---

### Request ID (REQID): REQXXXXXX


### Rules

<!-- 
  For each rule, add a “#### Rule” header and the same bullets.
  You can have as many as you like. 
-->

#### Rule 1
🔹 Source IP(s) or CIDR(s): `203.0.113.25/32`  
🔹 Destination IP(s) or CIDR(s): `10.1.2.0/24`  
🔹 Port(s): `443`  
🔹 Protocol: `TCP`  
🔹 Direction: `INGRESS`  
🔹 Business Justification: A short explanation…

#### Rule 2
🔹 Source IP(s) or CIDR(s): `10.2.3.4/32`  
🔹 Destination IP(s) or CIDR(s): `10.1.2.0/24`  
🔹 Port(s): `8443`  
🔹 Protocol: `TCP`  
🔹 Direction: `EGRESS`  
🔹 Business Justification: Another justification…
