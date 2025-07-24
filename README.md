## Rule add test cases

| #  | Scenario                          | Issue Body / Labels                                  | Expected Outcome                                                                        |  Outcome    |
| -- | --------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------- |-------------|
| 1  | **Single valid rule**             | One `#### Rule 1` block, valid IP/port/etc.          | One new `REQID.auto.tfvars.json` file with that rule; PR opens; summary bullet correct. |             |
| 2  | **Multiple valid rules**          | Two or more `#### Rule N` blocks                     | All rules in one file, each with incremented priority; PR summary lists both rules.     |             |
| 3  | **Missing REQID**                 | Omit “Request ID: …”                                 | Validation fails; comment “REQID not found”; issue closed.                              |             |
| 4  | **Missing CARID**                 | Omit “CARID: …”                                      | Validation fails; comment “CARID not found”; issue closed.                              |             |
| 5  | **Invalid IP**                    | `New Source IP: 300.300.300.300`                     | Validation fails; comment “Invalid source IP”; issue closed.                            |             |
| 6  | **Invalid port**                  | `New Port: eighty`                                   | Validation fails; comment “Invalid port or range”; issue closed.                        |             |
| 7  | **Invalid protocol**              | `New Protocol: HTTP`                                 | Validation fails; comment “Protocol must be one of tcp, udp, icmp, sctp”; issue closed. |             |
| 8  | **Invalid direction**             | `New Direction: IN`                                  | Validation fails; comment “Direction must be INGRESS or EGRESS”; issue closed.          |             |
| 9  | **Missing justification**         | Omit “New Business Justification”                    | Validation fails; comment “Justification is required”; issue closed.                    |             |
| 10 | **Duplicate REQID**               | REQID matching existing file in `firewall-requests/` | Duplicate‑REQID guard triggers; comment “Duplicate Request ID”; issue closed.           |             |
| 11 | **No firewall‑request label**     | Valid body but missing label                         | Job is skipped entirely (no PR, no errors).                                             |             |
| 12 | **Trailing whitespace in fields** | Fields have trailing spaces/tabs                     | Whitespace stripped; JSON contains clean values; no syntax errors.                      |             |
