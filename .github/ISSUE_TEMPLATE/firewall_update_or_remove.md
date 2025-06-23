---
name: "Firewall Rule Update/Removal Request"
about: "Request an update or removal of existing firewall rule(s)."
labels: ["firewall-update-request"]
---

<!--
Instructions:

- To **update** a rule: Only fill in the fields you wish to update. Leave others blank.
- To **remove** a rule: Only "Existing Rule Name" and "Action" (set to `remove`) are required; leave other fields blank.
- To **update multiple rules**, copy/paste the block below and fill for each rule.

Example:
#### Rule 1
🔹 Existing Rule Name: <rule name here>
🔹 Action: update/remove
🔹 New Source IP(s) or CIDR(s):
🔹 New Destination IP(s) or CIDR(s):
🔹 New Port(s):
🔹 New Protocol:
🔹 New Direction:
🔹 New Business Justification:
-->


### Request ID (REQID): REQ123123
### CARID: 123123

#### Rule 1
🔹 Existing Rule Name: AUTO-REQ123123-123123-TCP-443-1  
🔹 Action: update/remove  
🔹 New Source IP(s) or CIDR(s): 203.0.113.99/32   <!-- leave blank if removing -->
🔹 New Destination IP(s) or CIDR(s): 10.1.2.22/32 <!-- leave blank if removing -->
🔹 New Port(s): 443                               <!-- leave blank if removing -->
🔹 New Protocol: tcp                              <!-- leave blank if removing -->
🔹 New Direction: INGRESS                         <!-- leave blank if removing -->
🔹 New Business Justification: Changed subnet      <!-- leave blank if removing -->
