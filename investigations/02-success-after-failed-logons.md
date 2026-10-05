# Investigation 02: Successful logon after repeated failures

**Scope:** Synthetic Windows Security-style events in Azure Data Explorer, table `SecurityLabEvents`. Both query blocks were validated in ADX on 5 October 2026. This is a simulated lab investigation using the existing 367-event dataset.

## Hunting question and detection

Did a successful logon follow at least five failures for the same computer, target domain, account, source IP and logon type during the preceding ten minutes?

Windows event `4625` records a failed logon; `4624` records a successful logon. `EventID` is stored as text in this table.

The detection defines separate failure and success subqueries with `let`, then uses `join kind=inner` to retain every matching pair. It keeps failures at or after `SuccessTime - 10m` and strictly before `SuccessTime`. Each successful event is grouped separately using `SuccessEventId`, taken from `LabEventId`.

This is a rolling window before each success. The detection scans the imported dataset without restricting the account, IP or event date. The separate timeline query pivots to the specific finding from Investigation 01.

## Evidence

The timeline returned **seven events**. The detection returned **one qualifying successful logon**. Events occurred on **30 September 2026; all times below are UTC**.

| Computer | Account | Source IP | Failures | First failure | Last failure | Success |
|---|---|---|---:|---|---|---|
| WIN11-01 | alex | 10.0.0.50 | 6 | 09:00:00 | 09:02:30 | 09:03:00 |

All seven events have logon type `10`, meaning remote interactive logon, such as Remote Desktop. The six failures show `Status = 0xC000006D` and `SubStatus = 0xC000006A`, indicating incorrect-password failures. The success occurred **30 seconds after the final failure**.

## Assessment and ATT&CK hypothesis

The correlation establishes the sequence in the synthetic records and identifies an account and host for further investigation. Repeated failures followed by success can be consistent with password guessing. A user correcting mistyped credentials or an application retrying stale credentials can produce similar activity.

**MITRE ATT&CK:** [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/), under Credential Access, remains a hunting hypothesis. The events do not reveal attempted password values, establish malicious intent or confirm account compromise.

## Follow-up and detection limits

- In a real SOC, verify the source device, account owner and whether the remote logon was expected. Review activity after the success for account changes and process execution.
- Continue this lab with local account creation and process activity on `WIN11-01` after 09:03 UTC.
- Five failures and ten minutes are initial lab thresholds that require tuning. Slow or distributed attempts, changing source IPs or changing logon types can evade this matching logic.
- Duplicate ingestion can inflate counts. The lab uses a unique `LabEventId` for each source event; ingestion should also be checked for duplicates.
- A failure can match more than one later success. The output represents qualifying success events, not a count of distinct attacks.
- These are manually run ADX queries. Scheduled alerting and incident response have not been deployed.

## Portfolio evidence

- [Failed and successful logon timeline](../screenshots/10-failed-then-success-timeline.png)
- [Correlation detection result](../screenshots/11-failed-then-success-detection.png)
- [Timeline and detection queries](../queries/02-success-after-failed-logons.kql)

## References

- [Microsoft: Windows Security event 4624 and logon types](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft: Windows Security event 4625 and failure codes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft: KQL inner join](https://learn.microsoft.com/en-us/kusto/query/join-inner)
- [Microsoft: KQL let statement](https://learn.microsoft.com/en-us/kusto/query/let-statement)
- [MITRE ATT&CK: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
