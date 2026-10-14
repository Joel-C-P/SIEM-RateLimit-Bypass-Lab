<center><h1>SIEM RateLimit Bypass Lab</h1></center>

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1110.001%20%7C%20T1078-red)](https://attack.mitre.org/techniques/T1110/001/) [![Splunk](https://img.shields.io/badge/SIEM-Splunk%20Free%2010.4.3-green)](https://www.splunk.com/) [![Authelia](https://img.shields.io/badge/IdP-Authelia%20v3.8-blue)](https://www.authelia.com/) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=flat&logo=burpsuite&logoColor=white) ![Jira](https://img.shields.io/badge/Jira-0052CC?style=flat&logo=jira&logoColor=white) ![Python](https://img.shields.io/badge/Python 3-3776AB?style=flat&logo=python&logoColor=white)


## Overview

I created this lab to demonstrate the full lifecycle of a security incident, from the offensive exploitation of a business logic vulnerability and its detection in a SIEM, to the documentation of a reproducible response. It is designed to showcase skills relevant to a **Tier 1 SOC Analyst** role.

The lab simulates a real-world attack against **Authelia**, an open-source authentication and authorization server. The attacker (I' play a rol like a pentester) exploits a logic flaw in the rate-limiting mechanism to perform a brute-force attack against a privileged account, bypassing the IP ban by interleaving valid credentials from a low-privileged account.

The defensive phase uses **Splunk Free** to ingest Authelia JSON logs, detect the anomalous pattern, and simulate a Tier 1 triage and escalation to Tier 2.

## The Vulnerability

- **Type:** Business Logic Flaw.
- **Description:** Authelia bans an IP after 3 failed authentication attempts for 60 seconds(I configurated to got this vulnerability). However, a successful login resets the failure counter to 0. An attacker with valid low-privilege credentials can interleave them with failed attempts to reset the counter and avoid the ban indefinitely.
- **Attack pattern:** `failure, failure, success(rrhh), failure, failure, success(rrhh), ...`
- **Impact:** Unlimited brute-force against the `admin` password without triggering the IP ban. The `admin` credentials were successfully obtained.


## Lab Architecture

| Component | Technology | Role |
|---|---|---|
| **Identity Provider** | Authelia v3.8 (Docker) | Target of the attack. Generates authentication logs in JSON format. |
| **Reverse Proxy** | Caddy | Strips the `X-Forwarded-For` header so only the real IP reaches Authelia. |
| **Attacker** | Parrot Virtual Machine | Runs the Python brute-force script. |
| **SIEM** | Splunk Free 10.4.3 | Ingests Authelia logs, detects the attack pattern. |
| **Ticketing** | Jira Service Management Cloud | Receives automatic alerts from Splunk and tracks the incident. |
| **Network** | Isolated Docker network | All components run on the same isolated network. |

**IP Mapping:**
- `172.28.0.1` → Attacker (Pentester)
- `172.16.0.115` → Legitimate user `rrhh`
- `172.16.0.130` → Legitimate user `admin`

## Repository Structure

```
SIEM-RateLimit-Bypass-Lab/
├── README.md                          ← This file
├── LICENSE
├── Panel_Infrastructure/              ← Authelia + Caddy Docker setup
│   ├── README.md
│   ├── Caddyfile
│   ├── docker-compose.yml
│   └── config/
│       └── authelia/
│           ├── configuration.example.yml
│           └── users_database.example.yml
├── Pentester/                         ← Offensive phase
│   ├── README.md                      ← Attack methodology, evidence, pcap
│   ├── Content/
│   │   ├── credentials.txt
│   │   └── screenshots/
│   └── exploit/
│       ├── bypass_rate_limit.py
│       ├── dictionary.txt
│       ├── requirements.txt
│       └── attack9091.pcap
├── SOC_analyst/                       ← Defensive phase
│   ├── README.md                      ← Splunk detection, validation, alert config
│   ├── Playbook.md                    ← Tier 1 triage playbook
│   ├── MITRE_ATT&CK.md                ← MITRE mapping
│   ├── splunk.md                      ← Splunk setup
│   ├── incident_report.md             ← Incident report
│   └── Screenshots/
└── docs/
    ├── incident_report.md
```

## Attack Phase (Pentester)

The attack exploits the counter-reset logic flaw in Authelia. I build in script with Python to automates a brute-force attack against `admin`, inserting valid `rrhh` credentials every 2 failed attempts to reset the ban counter. And I made use of Burpsuite to get the necesary values of the requests

**Key results:**
- 86 POST requests captured.
- 57 failed attempts against `admin`.
- 28 successful logins with `rrhh` (counter resets).
- 1 successful login with `admin`.
- Total time: 28.74 seconds.
- Bans triggered: 0.

**Credential found:** `admin:BestBoss123`

**[Full attack documentation](./Pentester/README.md)**

## Defense Phase (SOC Analyst)

The defense uses Splunk Free to ingest Authelia JSON logs and detect the attack pattern. The detection query identifies, from the same IP and within a rolling 60-second window:

- At least 6 authentication failures for `admin`.
- At least 3 successful authentications for `rrhh`.

The alert is configured to run every minute and automatically create a Jira ticket via the Splunk Add-On for Jira Cloud.

**Detection validation:**
- The pattern was validated with simulated events (8 failures, 4 successes across 2 minutes).
- The pattern was confirmed in real Authelia logs (57 failures, 28 successes, 1 admin success).
- The original `admin` success event was reviewed in Splunk.

**[Full detection documentation](./SOC_analyst/README.md)**

## Triage and Escalation

The Tier 1 triage follows a structured playbook. Key findings:

- The detection identified the attacker IP `172.28.0.1`.
- The counter reset pattern was confirmed in the original events.
- A successful `admin` authentication was confirmed at 14:24:40 UTC.
- The case was escalated to Tier 2 with **High priority** due to possible account compromise.

 **[Read the Tier 1 Playbook ](./SOC_analyst/Playbook.md)**
 **[Read the Incident Report ](./SOC_analyst/incident_report.md)**

## MITRE ATT&CK Mapping

| ID | Tactic | Technique | Confidence |
|---|---|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Credential Access | Password Guessing | High |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Initial Access | Valid Accounts | Medium |

**[Read the full MITRE mapping ](./SOC_analyst/MITRE_ATT&CK.md)**


## Splunk Setup

Splunk Free 10.4.3 is used to ingest Authelia JSON logs. A custom index (`management_panel`) is created via CLI due to Splunk Free limitations.

 **[Read the Splunk setup ](./SOC_analyst/splunk.md)**


## Key Takeaways

1. **Business logic flaws are often more dangerous than technical vulnerabilities.** The counter-reset behavior was not a bug in the code, but a design decision that enabled the attack.
2. **Detecting brute-force with counter reset requires correlation, not just thresholds.** A simple rate-limit alert would not catch this attack because the attacker never exceeded the ban threshold.
3. **A successful 1FA authentication does not prove compromise.** It proves the credentials were valid, but not that the attacker accessed the panel or performed subsequent actions.
4. **Tier 1 triage is about validation and escalation, not about proving the vulnerability.** The Tier 1's job is to confirm the evidence, document the findings, and escalate with a clear rationale.


## Recommendations

To prevent this attack in a production environment:

- **Fix the rate-limiting logic:** a successful login from one account should not reset the counter for another account.
- **Enforce MFA:** even if the password is guessed, the attacker cannot complete the second factor.
- **Implement CAPTCHA:** after 3 failed attempts, add a CAPTCHA to slow down automated attacks.
- **Monitor failure + success sequences:** detect the pattern even if it does not exceed the ban threshold.
- **Restrict Authelia access:** place it behind a VPN or IP allowlist.


## References

- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [Authelia Documentation](https://www.authelia.com/)
- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)

## Author

**Joel C. P.** — SOC Analyst

