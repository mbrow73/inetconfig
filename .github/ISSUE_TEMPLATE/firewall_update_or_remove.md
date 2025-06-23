---
name: "Firewall Rule Update/Removal Request"
about: "Request an update or removal of existing firewall rule(s)."
labels: ["firewall-update-request"]
---

### Request ID (REQID): REQ123123
### CARID: 123123

<!-- For each rule you want to update or remove, copy the section below

For remove, only Existing Rule Name and Action are required. For update, fill only the fields you want to change.
 -->

#### Rule 1
🔹 Existing Rule Name: AUTO-REQ123123-123123-TCP-443-1  
🔹 Action: update/remove  
🔹 New Source IP(s) or CIDR(s): 203.0.113.99/32   <!-- leave blank if removing -->
🔹 New Destination IP(s) or CIDR(s): 10.1.2.22/32 <!-- leave blank if removing -->
🔹 New Port(s): 443                               <!-- leave blank if removing -->
🔹 New Protocol: tcp                              <!-- leave blank if removing -->
🔹 New Direction: INGRESS                         <!-- leave blank if removing -->
🔹 New Business Justification: Changed subnet      <!-- leave blank if removing -->
