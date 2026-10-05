# Investigation 06: Rare network destinations and process correlation

**Scope:** Synthetic Sysmon-style network and process creation records in Azure Data Explorer, table `SecurityLabEvents`. All three queries were validated in ADX on 5 October 2026. This is a simulated lab investigation.

## Hunting question and detection

Which outbound destination combinations have few recorded connections, and can their process context explain which ones deserve further investigation?

The 367-record dataset contains 131 Sysmon-style event `3` network records. Query A selects records with `Initiated == true`, representing connections initiated by the recorded computer, and excludes private RFC1918 destinations with `ipv4_is_private(DestinationIp) == false`. It counts events by destination IP, port and protocol, retaining groups with **three or fewer connections** across the imported dataset.

Query B uses an explicit inner join on those three destination fields to recover the individual network events, including computer, user, process image and `ProcessGuid`.

Query C is a focused pivot to `198.51.100.77:4444`, selected after reviewing A and B. It joins network records to process creation records using **Computer and ProcessGuid**, and requires each connection timestamp to be at or after the matched process start. The creation record's parent is named `ProcessParentImage` to keep it distinct from the network record's empty `ParentImage` field.

The imported table stores `EventID` as text, `Initiated` as boolean and `DestinationPort` as a numeric value.

## Evidence

Query A returned **two destination groups**, Query B returned **four network events**, and the final process correlation returned **three rows**. Full process paths and identifiers were also cross-checked against the source CSV. All timestamps below are UTC.

| Destination IP | Port | Protocol | Connections | First seen | Last seen |
|---|---|---|---|---|---|
| 203.0.113.25 | 443 | tcp | 1 | 2026-09-30 08:40:00 | 2026-09-30 08:40:00 |
| 198.51.100.77 | 4444 | tcp | 3 | 2026-09-30 09:10:10 | 2026-09-30 09:12:10 |

### Comparison: browser connection

The single connection to `203.0.113.25:443` was recorded on `WIN11-02` under `WIN11-02\sam`:

- **Image:** `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
- **ProcessGuid:** `6866186b-2ec6-4942-89bd-3cf084c799b5`
- **Source network event:** `LAB-000322`

This provides a browser comparison example. Its low event count alone is not evidence of a malicious connection. The recorded port and image do not independently verify TLS, application contents, binary authenticity or user approval.

### Follow-up lead: sync-helper.exe connections

The three connections to `198.51.100.77:4444` were recorded on `WIN11-01` under `WIN11-01\alex`. Their shared `ProcessGuid` matched the helper's process creation event from [Investigation 05](05-rare-processes.md).

- **Process image:** `C:\Users\alex\AppData\Local\Temp\sync-helper.exe`
- **Process start:** 2026-09-30 09:10:00 UTC
- **Process parent image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **ProcessGuid:** `b8d52208-b0ac-4027-84e5-c8bb576f5035`
- **Source process creation event:** `LAB-000335`

| Connection timestamp | Matched process start | Destination | Source network event |
|---|---|---|---|
| 2026-09-30 09:10:10 | 2026-09-30 09:10:00 | 198.51.100.77:4444 | LAB-000337 |
| 2026-09-30 09:11:10 | 2026-09-30 09:10:00 | 198.51.100.77:4444 | LAB-000338 |
| 2026-09-30 09:12:10 | 2026-09-30 09:10:00 | 198.51.100.77:4444 | LAB-000339 |

The first connection is ten seconds after process creation. The three recorded connections have two intervals of sixty seconds. This short sequence is a periodicity clue for follow-up, rather than sufficient evidence of sustained beaconing.

## Assessment and ATT&CK

The helper is the higher-priority lead in this lab because its network events combine with the earlier rare Temp-path execution and PowerShell parent context. The process identifier links these connections to the helper instance more precisely than the executable name or timing alone.

Potential command-and-control activity is an investigative hypothesis. A destination port, three connection events and short periodicity do not establish malicious intent or an application protocol. No specific ATT&CK technique is assigned solely from this flow metadata.

The helper's process parent path does not establish that the exact encoded PowerShell instance from [Investigation 04](04-encoded-powershell.md) launched it; the reduced schema lacks `ParentProcessGuid`. That earlier encoded payload was a harmless text-output command.

Both destination IPs fall within RFC 5737 ranges reserved for documentation: `198.51.100.0/24` and `203.0.113.0/24`. They are simulated destinations in this dataset, not real malicious indicators.

## Follow-up and detection limits

- In an operational SOC, verify the expected application and destination, review process ancestry and file provenance, and examine relevant DNS, proxy, firewall and packet evidence when available.
- Rarity is measured across this small imported sample. A production hunt needs a defined observation window, representative baseline and environment-specific thresholds.
- The filter excludes RFC1918 private destinations. A `false` result from `ipv4_is_private` does not establish public routability; other special address ranges need separate treatment.
- This hunt covers selected outbound IPv4 records. It omits inbound activity, private-range destinations, IPv6 addresses and values the IPv4 function cannot parse.
- An inner join retains only events with a matching process creation record. Missing starts can leave relevant connections out of the correlated view; duplicate creation records can multiply matches.
- Counts represent logged network events, not transferred bytes, commands or confirmed compromises. The dataset has no network payload, DNS or TLS evidence.
- The records and helper executable name are synthetic. The demonstrated outcome is validated KQL triage and process-to-network correlation.

## Portfolio evidence

- [Rare destination overview](../screenshots/18-rare-network-destinations.png)
- [Individual network events](../screenshots/19-rare-network-details.png)
- [Process-to-network correlation](../screenshots/20-network-process-correlation.png)
- [KQL overview, details and correlation queries](../queries/06-rare-network-destinations.kql)

## References

- [Microsoft: Sysmon events 1 and 3, and ProcessGuid correlation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft: KQL ipv4_is_private and RFC1918 ranges](https://learn.microsoft.com/en-us/kusto/query/ipv4-is-private-function?view=microsoft-fabric)
- [Microsoft: KQL inner join](https://learn.microsoft.com/en-us/kusto/query/join-inner?view=microsoft-fabric)
- [RFC 5737: IPv4 address blocks reserved for documentation](https://www.rfc-editor.org/rfc/rfc5737.txt)
