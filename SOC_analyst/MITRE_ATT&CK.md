## MITRE ATT&CK Mapping

| ID | Technique | Application in the lab |
|---|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Primary technique. The scenario uses a password list against `admin`. Logs show 57 failures followed by a successful `admin` authentication from the same IP. |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Technique related to the use of valid credentials. The log records a successful `admin` authentication; the lab context allows linking this to the test, although an authentication event alone does not identify the person who logged in. |

The primary detection maps to T1110.001. The counter-reset behavior is a business logic flaw that enables the password guessing, but the authentication evidence alone does not demonstrate that mechanism. This is a known limitation of the available telemetry.
