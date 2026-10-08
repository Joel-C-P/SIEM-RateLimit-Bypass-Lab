# Playbook: Rate Limit Bypass via Credential Rotation

## 1. Objective

Investigate an Authelia authentication alert and determine
whether it corresponds to expected activity, an authorized test,
or suspicious activity that requires escalation.

## 2. Detection condition

The search detects, from the same IP and within a 60-second sliding window:

- At least 6 authentication failures for `example_admin`.
- At least 3 successful authentications for `example_another_valid_acount`.

It also shows successful authentications for `example_admin`.
These are not required to trigger the detection.

The accounts and thresholds correspond to this lab.

## 3. Open and log the case

Upon receiving the alert:

1. Check whether there is a ticket for the same activity.
2. Create a Jira ticket if one does not exist.
3. Record:
   - Alert name and time received.
      - Investigated interval and time zone.
         - Source IP and accounts involved.
            - Detection counters.
               - Link or reference to the Splunk search.
               4. Mark the case as under investigation.

               Update the ticket during the analysis.

## 4. Validate the evidence

In Splunk:

1. Review the original events that triggered the detection.
2. Confirm IP, user, result, and time for each relevant event.
3. Verify that the fields are extracted correctly.
4. Review the chronological sequence of failures and successes.
5. If there is an `example_admin` success, locate its original event.

Do not add up the counters from all rows of the detection:
the windows overlap and contain shared events.

A successful first-factor authentication does not, by itself,
prove access to the panel or subsequent activity.

## 5. Check the context

- Identify what host or component the IP represents.
- Check whether a proxy or NAT may group several users.
- Check whether the source is usual for the affected accounts.
- Check whether there is an authorized test that matches
  the source, accounts, and time.
  - Review nearby events to identify continuity
    or additional affected accounts.

    Private lab IPs are investigated using
    the inventory and internal logs.

## 6. Decision and priority

Simulated criteria for this lab:

| Situation | Decision |
|---|---|
| Authorized test confirmed and matching the events | Document as expected detection from an authorized test. |
| Extraction or duplication errors | Document the issue and forward it to fix the detection. |
| Suspicious pattern without success of the target account | Investigate the context and escalate if suspicion persists. Initial priority medium. |
| Suspicious pattern with success of the target account and no authorized explanation | Escalate with high priority due to possible compromise. |

Priority may increase if ongoing malicious activity
or relevant impact is confirmed.

These criteria are a simulated lab policy.

## 7. Escalate to Tier 2

Escalation must include:

- Summary of the activity.
- IP, accounts, and interval with time zone.
- Original evidence and search results.
- Checks performed and their results.
- Priority and justification.
- Pending questions and reason for escalation.

It is not necessary to prove the vulnerability in order to escalate.

Do not state that there was a counter reset, panel access,
or subsequent actions if the evidence does not support it.

Tier 1 will not perform blocks, account deactivations,
or configuration changes without prior authorization from a supervisor.

## 8. Log the outcome

In Jira, record:

- Case classification and justification.
- Attached evidence.
- Actions taken.
- Status: escalated or closed.
- Escalation recipient, if applicable.

If an escalation is simulated without a real Tier 2,
state it explicitly in the ticket.
Upon receiving the alert:

1. Check whether there is a ticket for the same activity.
2. Create a Jira ticket if one does not exist.
3. Record:
   - Alert name and time received.
   - Investigated interval and time zone.
   - Source IP and accounts involved.
   - Detection counters.
   - Link or reference to the Splunk search.
4. Mark the case as under investigation.

Update the ticket during the analysis.

## 4. Validate the evidence

In Splunk:

1. Review the original events that triggered the detection.
2. Confirm IP, user, result, and time for each relevant event.
3. Verify that the fields are extracted correctly.
4. Review the chronological sequence of failures and successes.
5. If there is an `example_admin` success, locate its original event.

Do not add up the counters from all rows of the detection:
the windows overlap and contain shared events.

A successful first-factor authentication does not, by itself,
prove access to the panel or subsequent activity.

## 5. Check the context

- Identify what host or component the IP represents.
- Check whether a proxy or NAT may group several users.
- Check whether the source is usual for the affected accounts.
- Check whether there is an authorized test that matches
  the source, accounts, and time.
- Review nearby events to identify continuity
  or additional affected accounts.

Private lab IPs are investigated using
the inventory and internal logs.

## 6. Decision and priority

Simulated criteria for this lab:

| Situation | Decision |
|---|---|
| Authorized test confirmed and matching the events | Document as expected detection from an authorized test. |
| Extraction or duplication errors | Document the issue and forward it to fix the detection. |
| Suspicious pattern without success of the target account | Investigate the context and escalate if suspicion persists. Initial priority medium. |
| Suspicious pattern with success of the target account and no authorized explanation | Escalate with high priority due to possible compromise. |

Priority may increase if ongoing malicious activity
or relevant impact is confirmed.

These criteria are a simulated lab policy.

## 7. Escalate to Tier 2

Escalation must include:

- Summary of the activity.
- IP, accounts, and interval with time zone.
- Original evidence and search results.
- Checks performed and their results.
- Priority and justification.
- Pending questions and reason for escalation.

It is not necessary to prove the vulnerability in order to escalate.

Do not state that there was a counter reset, panel access,
or subsequent actions if the evidence does not support it.

Tier 1 will not perform blocks, account deactivations,
or configuration changes without prior authorization from a supervisor.

## 8. Record the result

In Jira, record:

- Case classification and justification.
- Attached evidence.
- Actions taken.
- Status: escalated or closed.
- Escalation recipient, if applicable.

If an escalation is simulated without a real Tier 2,
state it explicitly in the ticket.

## Important rules

- Do not block the IP without authorization.
- Do not disable the account without authorization.
- Do not modify detection rules during an active investigation.
- Do not close the ticket without documenting the reason.
- Do not state that there was a counter reset, panel access, or subsequent actions if the evidence does not support it.
- Do not add up the counters from all rows of the detection: the windows overlap and contain shared events.

