# SIEM RateLimit Bypass Lab

>⚠️ Warning
> Own isolated lab. It does not attack real systems.
> For educational and defensive research purposes only.
> See the point of view of a pentester and SOC analyst.

## Description
Hi, I'm Joel. I put a lot of effort into emulating this scenario, and I hope it helps you learn more about this area, just as it did for me, so i emulated an attack and defense case, the brute-force attack will be against an admin login panel protected by **Authelia**, exploiting a business logic flaw in the rate limiting. The attack is then analyzed from a SIEM, in my case I will use **Wazuh**, with which I generate detection rules and the incident is documented.

## 📄 Incident documentation

- [Full incident report](docs/incident_report.md)
- [Attack timeline](docs/timeline.md)

## Repository structure

- `Panel_Infrastructure/` — How to set up the lab
- `Pentester/` — Attack scripts and wordlists bypass
- `SOC_analyst/` — SIEM (Wazuh) rules, queries, and analysis
- `docs/` — Incident report and documentation

## Status

🚧 Under construction.
