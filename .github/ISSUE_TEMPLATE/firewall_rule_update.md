---
name: Firewall Rule Update Request
about: Update one or more existing firewall rules
labels: [firewall-update-request]
---

### Request ID (REQID): REQ12345  
### CARID: APP1  

_Repeat this block for each rule you want to update:_

#### Rule
🔹 **Existing Name**: `AUTO-APP1-REQ12345-1-TCP-443`  
🔹 **New Source**: `203.0.113.55/32`  
🔹 **New Destination**: `10.1.2.22/32`  
🔹 **New Ports**: `443`  
🔹 **New Protocol**: `tcp`  
🔹 **New Direction**: `INGRESS`  
🔹 **New Justification**: Need to restrict to a smaller range  
