# Investigation 01: Multiple failed Windows logons

**Scope:** Synthetic Windows Security-style events in Azure Data Explorer, table `SecurityLabEvents`. Queries validated on 4 October 2026. This is a simulated lab investigation.

## Hunting question and detection

Did the same account receive at least five failed logons from the same source IP on the same computer within a fixed 10-minute window?

The query filters `WindowsSecurity` event `4625`, groups by computer, target domain, target username, source IP and timestamp bin, and applies a threshold of five failures. `EventID` is stored as text in this table.

## Evidence

Both groups occurred on **30 September 2026; all times below are UTC**.

| Computer | Account | Source IP | Failures | First to last failure | Logon type |
|---|---|---|---:|---|---|
| WIN11-01 | alex | 10.0.0.50 | 6 | 09:00:00-09:02:30 | 10: remote interactive |
| WIN-SRV-01 | labadmin | 10.0.0.60 | 7 | 11:10:00-11:12:00 | 3: network |

The overview returned **two groups**. A follow-up query returned **13 individual events**. Every inspected event had `Status = 0xC000006D` (logon failure involving invalid authentication information) and `SubStatus = 0xC000006A` (incorrect password).

## Assessment and ATT&CK hypothesis

Both groups warrant triage. The remote interactive failures for `alex` support investigating possible credential guessing. The network failures for `labadmin` could also involve guessing, saved incorrect credentials or automated retries. The events do not establish intent or account compromise.

**MITRE ATT&CK:** [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/), under Credential Access, is the hunting hypothesis. Failed authentication records do not reveal whether different passwords were tried.

## Follow-up and detection limits

- Correlate with successful event `4624` using computer, domain, username, source IP and event order.
- In a real SOC, confirm whether the source systems and activity are expected; review saved credentials and scheduled tasks.
- Mistyped passwords and stale credentials can produce similar results. Logon type alone does not establish malicious activity.
- Fixed bins can split a burst across a boundary. Slow or distributed guessing can evade this threshold. Duplicate ingestion can inflate counts; five is an initial lab threshold.

## Portfolio evidence

- [Detection overview](../screenshots/08-failed-logons-overview.png)
- [Individual event details](../screenshots/09-failed-logons-details.png)
- [Detection and investigation queries](../queries/01-multiple-failed-logons.kql)

## References

- [Microsoft: Windows Security event 4625, logon types and failure codes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft: KQL bin()](https://learn.microsoft.com/en-us/kusto/query/bin-function)
- [MITRE ATT&CK: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
