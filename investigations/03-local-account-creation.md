# Investigation 03: Local account creation

**Scope:** Synthetic Windows Security-style events in Azure Data Explorer, table `SecurityLabEvents`. Both query blocks were validated in ADX on 5 October 2026. This is a simulated lab investigation using the existing 367-event dataset.

## Hunting question and detection

Which local user accounts were created, who requested their creation, and did the activity follow the logon sequence found in Investigation 02?

Windows event `4720` records user account creation. `SubjectUserName` identifies the account requesting creation; `TargetUserName` identifies the new account. For local accounts, `TargetDomainName` contains the computer name.

The overview query returns all `4720` events. The local account query uses `TargetDomainName =~ Computer`, a comparison that ignores case. This works with the short computer names in this normalized lab dataset. `CreatedBy` and `NewAccount` are output aliases for the original creator and target fields. `EventID` is stored as text.

## Evidence

The overview returned **three account creation events**; the local account query returned **two**. All timestamps below are UTC.

| Timestamp | Computer | Created by | New account | Target domain | Scope |
|---|---|---|---|---|---|
| 2026-09-28 11:30:00 | WIN11-02 | labadmin | testuser | WIN11-02 | Local |
| 2026-09-29 12:00:00 | DC-01 | helpdesk | newhire | LAB | Domain |
| 2026-09-30 09:05:00 | WIN11-01 | alex | svc_support | WIN11-01 | Local |

The local account query excludes `newhire` because it belongs to the `LAB` domain, outside this query's local account scope.

On 30 September, [Investigation 02](02-success-after-failed-logons.md) found six failed logons for `alex` on `WIN11-01`, followed by a successful logon at **09:03:00** from `10.0.0.50`. The account creation event records `alex` creating `svc_support` on the same computer at **09:05:00**, two minutes later.

## Assessment and ATT&CK hypothesis

`svc_support` is the priority follow-up lead because its creation follows the failed-then-successful logon sequence. This is a temporal association using the same host and account name. The dataset lacks account SIDs and logon-session identifiers, so it does not prove that the account creation used that specific logon session.

**MITRE ATT&CK:** [T1136.001 - Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/), under Persistence, is the hunting hypothesis. Account creation alone does not establish unauthorized access or persistence. The account's name does not prove its purpose, and these records do not establish privileged group membership.

`testuser` may be expected administrative or testing activity, but the creator's name alone does not verify authorization. Both local creations require contextual review in a real environment.

## Follow-up and detection limits

- Verify an approved change, account owner, business purpose and whether the creation was expected. Review group membership and subsequent use of the new account.
- Review process activity on `WIN11-01` around the successful logon and account creation; continue this lab with PowerShell process creation.
- Normal administration, service setup and test accounts can produce matching events. This query identifies local account creation, not maliciousness.
- The name comparison needs adjustment for other schemas, such as fully qualified computer names paired with short account-domain names. Missing or ambiguous fields require further validation.
- This lab does not include the full native Windows event schema or deployed scheduled alerting.

## Portfolio evidence

- [All account creation events](../screenshots/12-account-creation-overview.png)
- [Local account creation results](../screenshots/13-local-account-creation.png)
- [Overview and local account queries](../queries/03-local-account-creation.kql)

## References

- [Microsoft: Windows Security event 4720 and account fields](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720)
- [Microsoft: KQL case-insensitive equality operator](https://learn.microsoft.com/en-us/kusto/query/equals-operator)
- [MITRE ATT&CK: Create Account - Local Account](https://attack.mitre.org/techniques/T1136/001/)
