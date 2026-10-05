# Investigation 05: Rare process execution

**Scope:** Synthetic Sysmon-style process creation records in Azure Data Explorer, table `SecurityLabEvents`. Both queries were validated in ADX on 5 October 2026. This is a simulated lab investigation.

## Hunting question and detection

Which executable paths appear only once on a particular computer, and which execution contexts deserve further investigation?

The 367-record dataset contains 131 Sysmon-style event `1` process creation records. Query A groups those records by `Computer` and `Image`, counts executions, and retains groups with exactly one observation. `FirstSeen` and `LastSeen` describe the imported dataset, whose event timestamps span 24–30 September 2026.

Query B creates the same rare computer/path list with `let`, then uses an explicit `join kind=inner` on both fields to recover the original event's user, parent image, command line and process identifier. `EventID` is stored as text in this table.

Rarity here means one observation per computer and executable path within this dataset. It is a limited baseline, not evidence that a program has never run before or that it is rare across an organization.

## Evidence

Both ADX queries returned **two rows**. Full paths and command lines were also cross-checked against the source CSV. All timestamps below are UTC.

| Timestamp | Computer | Executable path | Executions | User |
|---|---|---|---|---|
| 2026-09-30 09:10:00 | WIN11-01 | `C:\Users\alex\AppData\Local\Temp\sync-helper.exe` | 1 | `WIN11-01\alex` |
| 2026-09-30 14:05:00 | WIN11-02 | `C:\Windows\System32\whoami.exe` | 1 | `WIN11-02\sam` |

For each row, `FirstSeen` and `LastSeen` equal the listed timestamp because there is one matching process creation event.

### WIN11-01: sync-helper.exe

- **Parent image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Command line:** `"C:\Users\alex\AppData\Local\Temp\sync-helper.exe"`
- **ProcessGuid:** `b8d52208-b0ac-4027-84e5-c8bb576f5035`
- **Source event:** `LAB-000335`

This is the higher-priority follow-up lead in the lab: the process appears once, runs from Alex's Temp directory and records PowerShell as its parent image. It occurs at **09:10 UTC**, three minutes after the encoded PowerShell event on the same computer and user in [Investigation 04](04-encoded-powershell.md).

The earlier encoded command decoded to the harmless text-output command `Write-Output 'KQL-Lab-Demo'`. The shared parent executable path and timing do not establish that this exact PowerShell process launched the helper. The reduced schema lacks `ParentProcessGuid` for that attribution.

### WIN11-02: whoami.exe

- **Parent image:** `C:\Windows\System32\cmd.exe`
- **Command line:** `whoami.exe /all`
- **ProcessGuid:** `3862e6a1-bd4c-4fec-8aae-adc26d2985e9`
- **Source event:** `LAB-000364`

Microsoft documents `whoami /all` as displaying the current access token's user identity, security identifiers, groups and privileges. This record is consistent with an identity or permissions check and supplies a comparison example: a legitimate utility can also be rare in a small dataset.

Its path and command line alone do not verify the executable's authenticity or the user's intent. In an operational investigation, expected user activity would still need to be checked.

## Assessment and ATT&CK

Prioritize the `sync-helper.exe` record for contextual follow-up, including its subsequent network activity. The combined rarity, Temp location and PowerShell parent support that triage choice; they do not confirm malware.

No ATT&CK technique is assigned solely from process rarity. The available evidence does not establish how the helper arrived, its contents or its purpose. PowerShell usage is discussed separately in Investigation 04.

## Follow-up and detection limits

- Correlate network events with the helper's **Computer and ProcessGuid** in Investigation 06. A process identifier can support a more precise link than matching only an executable name or nearby timestamp.
- In a real SOC, check the expected task, file hash, signature, file origin and detailed process ancestry. These file-verification fields are absent from this teaching dataset.
- Small samples can make ordinary utilities, installers and administrative tasks look rare. A production hunt needs a defined observation window and a representative baseline.
- Counts represent recorded process events. Missing collection and duplicate ingestion can alter the result.
- Grouping uses the recorded image path exactly; differences in case or path representation can split observations for the same Windows executable.
- The helper's name is fictional, and these records are synthetic. This exercise demonstrates a hunting method and evidence assessment.

## Portfolio evidence

- [Rare process overview](../screenshots/16-rare-process-overview.png)
- [Rare process details](../screenshots/17-rare-process-details.png)
- [KQL overview and details queries](../queries/05-rare-processes.kql)

## References

- [Microsoft: Sysmon process creation and ProcessGuid](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft: KQL summarize](https://learn.microsoft.com/en-us/kusto/query/summarize-operator?view=microsoft-fabric)
- [Microsoft: KQL inner join](https://learn.microsoft.com/en-us/kusto/query/join-inner?view=microsoft-fabric)
- [Microsoft: whoami and the /all parameter](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
