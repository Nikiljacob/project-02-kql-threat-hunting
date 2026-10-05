# Primary references

These sources support event meanings, language behavior and platform instructions. Findings, timestamps and counts come from the supplied synthetic CSV and the validated lab outputs. References were checked while preparing the final documentation on 5 October 2026.

## Platform and reproduction

- [Microsoft: Create a free ADX cluster](https://learn.microsoft.com/en-us/azure/data-explorer/start-for-free-web-ui)
- [Microsoft: Ingest a local file](https://learn.microsoft.com/en-us/azure/data-explorer/get-data-file)
- [Microsoft: Native ADX dashboards](https://learn.microsoft.com/en-us/azure/data-explorer/azure-data-explorer-dashboards)
- [Microsoft: Dashboard parameters](https://learn.microsoft.com/en-us/azure/data-explorer/dashboard-parameters)
- [Microsoft: .create table](https://learn.microsoft.com/en-us/kusto/management/create-table-command?view=microsoft-fabric)
- [Microsoft: getschema](https://learn.microsoft.com/en-us/kusto/query/getschema-operator?view=microsoft-fabric)

## Events and interpretation

- [Microsoft: Windows Security event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft: Windows Security event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft: Windows Security event 4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720)
- [Microsoft Sysinternals: Sysmon events 1 and 3, process identifiers](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft: PowerShell encoded-command format](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)
- [Microsoft: whoami](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
- [RFC 5737: Documentation IPv4 addresses](https://www.rfc-editor.org/rfc/rfc5737.txt)

## Query behavior

- [Microsoft: KQL bin](https://learn.microsoft.com/en-us/kusto/query/bin-function)
- [Microsoft: KQL summarize](https://learn.microsoft.com/en-us/kusto/query/summarize-operator?view=microsoft-fabric)
- [Microsoft: KQL inner join](https://learn.microsoft.com/en-us/kusto/query/join-inner?view=microsoft-fabric)
- [Microsoft: KQL let statement](https://learn.microsoft.com/en-us/kusto/query/let-statement?view=microsoft-fabric)
- [Microsoft: Case-insensitive equality](https://learn.microsoft.com/en-us/kusto/query/equals-operator)
- [Microsoft: KQL ipv4_is_private](https://learn.microsoft.com/en-us/kusto/query/ipv4-is-private-function?view=microsoft-fabric)

## ATT&CK hypotheses

- [MITRE: T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE: T1136.001 - Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [MITRE: T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)

The mappings describe relevant investigation hypotheses; they are not labels establishing malicious behavior in this lab.
