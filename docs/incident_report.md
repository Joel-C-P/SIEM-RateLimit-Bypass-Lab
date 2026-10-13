Tier 1 assessment - Escalation to Tier 2

Case: SOC-1  
Alert: Suspicious authentication pattern detected  
Service: Authelia authentication  
Tier 1 analyst: tester  
Recommended priority: High, according to the simulated lab playbook  
Disposition: Escalation recommended — possible account compromise

Triage performed according to Playbook.md

Activity maps to T1110.001 (Password Guessing) and T1078 (Valid Accounts).

Activity maps in  MITRE_ATT&CK.md
Summary

Splunk generated an authentication alert for source IP 172.28.0.1. An attached detection result reports the following activity within a rolling 60-second window:

    57 failed first-factor authentication attempts against admin.

    28 successful first-factor authentications for rrhh.

    1 successful first-factor authentication for admin.

The result timestamp is 2026-10-10 17:34:47 UTC (_time=1791653687). This identifies the detection result, not necessarily the start of the activity.

Repeated failures against admin, combined with successful authentications for both accounts from the same recorded IP, warrant further investigation for possible password guessing and account compromise.
Evidence and validation status

    Splunk automatically created SOC-1 through the Jira Cloud integration.

    The ticket contains the detection results, including the source IP and authentication counters.

    The case is assigned to tester and is under investigation.

    Original-event screenshots documented in the repository relate to the 2026-10-08 validation run. They provide detection-validation context but do not independently confirm the events associated with this October 10 case.

    Review of the original events for the October 10 execution remains pending.

The counters above come from one detection-result row. Counters from overlapping windows have not been added together.
Tier 1 assessment

Working hypothesis: suspicious password-guessing activity with possible compromise of admin panel.

High priority is recommended because the alert reports a successful first-factor authentication for the targeted account alongside repeated failures. Business impact and the account's actual privileges remain unconfirmed.

A successful first-factor authentication does not establish completion of MFA, access to the protected panel, or subsequent malicious activity.

These logs do not establish that a rate-limit counter was reset or that a specific bypass mechanism was used.
Context and limitations

    172.28.0.1 is the source recorded by the application.

    A shared recorded IP does not by itself prove that all events came from the same person or device.

    Expected activity for admin and rrhh has not yet been established for this execution.

    No matching authorized-test notification has been established within the simulated analyst scenario.

    The available evidence does not establish the full scope, business impact, or post-authentication activity.

Requested Tier 2 investigation

    Validate the October 10 original events and confirm the authentication sequence and counts.

    Correlate application and proxy/network logs to determine the originating host.

    Check whether the activity matches expected account use or a known authorized test.

    Investigate MFA completion, session creation, protected-resource access, and activity after the admin authentication.

    Assess whether other accounts or sources are affected.

    Determine whether containment is required and coordinate any action through the authorized response process.

Actions taken and handoff

Tier 1 reviewed the attached alert results and documented the escalation rationale. No IP blocking, account disabling, session revocation, or configuration changes have been performed as part of this triage.

Lab handoff: This is a simulated escalation to Tier 2. No real Tier 2 recipient or acceptance is recorded. The incident remains unresolved pending further investigation.
