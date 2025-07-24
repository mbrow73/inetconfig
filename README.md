## Rule add test cases

| #  | Scenario                          | Issue Body / Labels                                  | Expected Outcome                                                                        |  Outcome    |
| -- | --------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------- |-------------|
| 1  | **Single valid rule**             | One `#### Rule 1` block, valid IP/port/etc.          | One new `REQID.auto.tfvars.json` file with that rule; PR opens; summary bullet correct. |     expected        |
| 2  | **Multiple valid rules**          | Two or more `#### Rule N` blocks                     | All rules in one file, each with incremented priority; PR summary lists both rules.     |     expected        |
| 3  | **Missing REQID**                 | Omit “Request ID: …”                                 | Validation fails; comment “REQID not found”; issue closed.                              |     expected        |
| 4  | **Missing CARID**                 | Omit “CARID: …”                                      | Validation fails; comment “CARID not found”; issue closed.                              |     expected        |
| 5  | **Invalid IP**                    | `New Source IP: 300.300.300.300`                     | Validation fails; comment “Invalid source IP”; issue closed.                            |     expected        |
| 6  | **Invalid port**                  | `New Port: eighty`                                   | Validation fails; comment “Invalid port or range”; issue closed.                        |     expected        |
| 7  | **Invalid protocol**              | `New Protocol: HTTP`                                 | Validation fails; comment “Protocol must be one of tcp, udp, icmp, sctp”; issue closed. |     expected        |
| 8  | **Invalid direction**             | `New Direction: IN`                                  | Validation fails; comment “Direction must be INGRESS or EGRESS”; issue closed.          |     expected        |
| 9  | **Missing justification**         | Omit “New Business Justification”                    | Validation fails; comment “Justification is required”; issue closed.                    |     expected        |
| 10 | **Duplicate REQID**               | REQID matching existing file in `firewall-requests/` | Duplicate‑REQID guard triggers; comment “Duplicate Request ID”; issue closed.           |     expected        |
| 11 | **No firewall‑request label**     | Valid body but missing label                         | Job is skipped entirely (no PR, no errors).                                             |     expected        |
| 12 | **Trailing whitespace in fields** | Fields have trailing spaces/tabs                     | Whitespace stripped; JSON contains clean values; no syntax errors.                      |     expected        |

## Rule remove test cases

| # | Scenario                        | Issue Body / Labels                                    | Expected Outcome                                                                               |    Outcome     |
| - | ------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |----------------|
| 1 | **Remove existing rule**        | “Current Rule Name: AUTO-...-443-1”                    | File is rewritten without that rule; PR opens with summary; rule is gone.                      |    Expected    |
| 2 | **Remove non‑existent rule**    | Name that isn’t in any file                            | Validation fails; comment “No rule found with name …”; issue closed.                           |    Expected    |
| 3 | **Missing “Current Rule Name”** | Omit the field                                         | Validation fails; comment “‘Current Rule Name’ is required”; issue closed.                     |    Expected    |
| 4 | **Multiple removes**            | Two `#### Rule` blocks for removal                     | Both rules removed from their respective files; summary bullet for each; PR opens.             |    Expected    |
| 5 | **Mixed valid + invalid**       | One valid, one bogus name                              | Validation fails on the bogus one; no partial removals; comment lists both successes/failures. |    Expected    |
| 6 | **Label mismatch**              | Body valid but missing `firewall-removal-request` label | Job skipped.                                                                                  |   Expected     |


## Rule update test cases

| #  | Scenario                                | Issue Body / Labels                                    | Expected Outcome                                                                                   |     Outcome      |
| -- | --------------------------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |------------------|
| 1  | **Change a single field**               | One block: change port                                 | JSON file updated with new port; rule name/index updated; PR summary shows “Ports: `old` → `new`”. |     Expected      |
| 2  | **Change multiple fields**              | Block: change src, dest, protocol                      | All fields updated; summary has 3 bullets; PR opens.                                               |     Expected      |
| 3  | **New REQID only**                      | `New Request ID: REQ9999999`, no other changes         | Filename updated to `REQ9999999-oldfilename.json`; rule names inside only use new REQID.           |     Expected      |
| 4  | **Invalid port in update**              | `New Port: abc`                                        | Validation fails; comment lists “Invalid port”; issue closed.                                      |     Expected      |
| 5  | **Invalid protocol in update**          | `New Protocol: FTP`                                    | Validation fails; comment “Protocol must be one of…”; issue closed.                                |     Expected      |
| 6  | **Missing Current Rule Name**           | Omit that line                                         | Validation fails; comment “’Current Rule Name’ is required”; issue closed.                         |     Expected      |
| 7  | **No-op update**                        | Update block with no actual changes                    | Workflow exits 0 (maybe comment “No updates detected”), no PR.                                     |           |
| 8  | **Mixed valid + invalid update blocks** | Two blocks: one valid, one invalid                     | Validation fails as a whole; no partial file writes; comment aggregates both errors.               |           |
| 9  | **Multiple updates to same file**       | Two update blocks pointing at rules in one file        | Both rules updated in the same JSON file; PR summary lists two bullets.                            |           |
| 10 | **Label mismatch**                      | Body valid but missing `firewall-update-request` label | Job skipped.                                                                                       |           |
