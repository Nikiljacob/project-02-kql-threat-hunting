# Investigation 04: Encoded PowerShell

**Scope:** Synthetic Sysmon-style process creation records in Azure Data Explorer, table `SecurityLabEvents`. The detection was validated in ADX, and decoder output was verified in local Windows PowerShell, on 5 October 2026. This is a simulated lab investigation.

## Hunting question and detection

Which PowerShell processes use an encoded command, what do the decoded commands contain, and how does their context affect triage?

Sysmon event `1` records process creation. The query filters `powershell.exe` image paths and command lines containing `-EncodedCommand` or `-enc`. The regex uses `(?i)` to ignore case, allowing the mixed-case `-eNc` comparison example to match. It returns the timestamp, computer, user, parent image and command line. `EventID` is stored as text in this table.

PowerShell's encoded-command parameter expects Base64 representing UTF-16LE text. The separate decoder converts Base64 to bytes with `FromBase64String`, then returns readable text with `Encoding.Unicode.GetString`. The investigation decoded the contents for inspection.

## Evidence

The ADX query returned **two process creation events**. Both payloads decoded successfully. All event timestamps below are UTC.

| Timestamp | Computer | User | Parent image | Parameter | Decoded command |
|---|---|---|---|---|---|
| 2026-09-29 16:10:00 | WIN11-02 | WIN11-02\labadmin | C:\Windows\explorer.exe | -eNc | `Write-Output 'Approved maintenance check'` |
| 2026-09-30 09:07:00 | WIN11-01 | WIN11-01\alex | C:\Windows\System32\cmd.exe | -EncodedCommand | `Write-Output 'KQL-Lab-Demo'` |

Both decoded commands output a literal message. These are intentionally harmless demonstration payloads in the synthetic dataset.

The `alex` event follows the successful logon at **09:03:00** from [Investigation 02](02-success-after-failed-logons.md) and local `svc_support` account creation at **09:05:00** from [Investigation 03](03-local-account-creation.md). PowerShell appears at **09:07:00**, two minutes after account creation, with `cmd.exe` recorded as its parent image.

## Assessment and ATT&CK hypothesis

Encoded-command use warrants inspection, but the decoded contents here are simple text-output commands. The surrounding `alex` activity remains a follow-up lead because of the preceding logon sequence and account creation. The records do not establish malicious execution.

The maintenance-themed comparison on `WIN11-02` demonstrates that an encoded command can be ordinary administrative activity. Its printed message is not evidence of an approved change. Likewise, `cmd.exe` as a parent is context for review, not a maliciousness test.

**MITRE ATT&CK:** [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/), under Execution, describes the potential misuse being investigated. This lab demonstrates detection and triage of PowerShell usage with benign payloads, rather than confirming adversarial PowerShell execution.

## Follow-up and detection limits

- In a real SOC, verify the expected task and account owner, examine the complete command line and process ancestry, and review activity after the process starts.
- Continue this lab with rare process execution on `WIN11-01` after 09:07 UTC.
- Administrative scripts and software deployment can use encoded commands. Decode and inspect content before making a maliciousness assessment.
- The rule covers `powershell.exe` and the two parameter spellings used here. It does not cover every abbreviation, argument formatting variation, renamed executable, `pwsh.exe` or embedded PowerShell host.
- Host, user and timing provide temporal context. The reduced schema lacks the session and parent-process identifiers needed to prove the complete causal chain between all earlier events.

## Portfolio evidence

- [Encoded PowerShell detection results](../screenshots/14-encoded-powershell-detection.png)
- [Decoded payload text](../screenshots/15-encoded-powershell-decoded.png)
- [KQL detection](../queries/04-encoded-powershell.kql)
- [Payload decoder](../queries/04-decode-powershell.ps1)

## References

- [Microsoft: Sysmon event 1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft: PowerShell encoded-command format](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)
- [Microsoft: Encoding.Unicode uses UTF-16LE](https://learn.microsoft.com/en-us/dotnet/api/system.text.encoding.unicode)
- [Microsoft: Convert.FromBase64String](https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string)
- [Microsoft: Write-Output](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/write-output)
- [MITRE ATT&CK: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
