# Validation and detection limits

The six original hunt files contain **12 independently runnable query blocks**, manually executed in ADX on **4-5 October 2026**. The source CSV, supplied results and final dashboard agree on the counts below. Dataset diagnostics and the local verifier are additional reproduction aids; they are not evidence of deployed alerting.

## Dataset baseline

| Check | Expected result |
|---|---|
| Total records | 367 |
| Columns in CSV | 23 |
| Unique `LabEventId` values | 367 |
| First / last event (UTC) | 2026-09-24 07:00:00 / 2026-09-30 15:01:00 |
| Windows Security 4624 / 4625 / 4720 | 65 / 37 / 3 |
| Sysmon-style 1 / 3 | 131 / 131 |
| Synthetic provenance | `IsSynthetic=true` on every record |

The checksum and full reference schema are in [data/README.md](../data/README.md).

## Query output matrix

| Case / block | Output unit | Expected count | Identifying result |
|---|---|---:|---|
| 01 A | Failure group | 2 | `alex`: 6; `labadmin`: 7 |
| 01 B | Failure event | 13 | Six + seven inspected failures |
| 02 A | Logon event | 7 | Six failures followed by one success |
| 02 B | Qualifying success | 1 | `alex`, WIN11-01, 09:03 UTC |
| 03 A | Account creation | 3 | `testuser`, `newhire`, `svc_support` |
| 03 B | Local account creation | 2 | `testuser`, `svc_support` |
| 04 | Process creation | 2 | `-eNc` comparison; `-EncodedCommand` on WIN11-01 |
| 05 A | Rare host/path pair | 2 | Temp helper; System32 `whoami.exe` |
| 05 B | Process creation | 2 | The same two records with context |
| 06 A | Destination IP/port/protocol group | 2 | TCP 443: 1; TCP 4444: 3 |
| 06 B | Network event | 4 | Browser: 1; helper: 3 |
| 06 C | Matched network/process pair | 3 | The three helper connections |

There are **12 rows in this matrix**, one for each independently runnable block. Several blocks include internal `let` statements that must run with the final expression. Counts represent the returned outputs, not distinct attacks or execution steps.

## Comparison and boundary checks

| Example | Observed outcome | What it demonstrates |
|---|---|---|
| `alex` has six failures, then success | Qualifies for the rolling failure-to-success hunt | Positive matching sequence |
| `labadmin` has seven failures without matching later success | Present in case 01, absent from case 02 result | Failures alone do not satisfy the correlation |
| `sam` has three failures, then success | Below the threshold of five | A success does not make every retry sequence qualify |
| Domain account `newhire` | Present in the all-creation overview; excluded by the local query | Scope depends on the recorded domain/host names |
| Two encoded text-output commands | Both match and decode to harmless literal messages | Encoding alone is not maliciousness |
| `whoami.exe /all` | Rare, just like the helper | Rarity alone is not a verdict |
| Browser TCP 443 record | Matches the rare-destination hunt | A low count also captures comparison activity |
| Incoming network record | Excluded by `Initiated == true` | This hunt's scope is recorded outbound activity |

These are controlled examples inside one small teaching dataset. They do not provide a representative false-positive rate, precision, recall or a production benchmark.

## Detection design and limits

| Hunt | Lab logic | Main limitation / tuning need |
|---|---|---|
| Repeated failures | At least 5 per computer/domain/account/source in a fixed 10-minute bin | Bin boundaries split bursts; slow or distributed attempts can evade the threshold |
| Success after failures | At least 5 matching failures in the 10 minutes strictly before each success; include logon type | Changed matching fields can break the association; a failure can qualify more than one success |
| Local account creation | Event 4720 and case-insensitive domain-to-short-host comparison | Other naming conventions need normalization; creation does not establish privilege or authorization |
| Encoded PowerShell | Sysmon-style event 1, `powershell.exe`, two encoded-parameter spellings | Other abbreviations, hosts, names and formatting are outside coverage |
| Rare process paths | One recorded execution per computer/image path in the snapshot | Sparse samples and exact path/case differences distort rarity |
| Rare destinations | At most 3 outbound IPv4 records per IP/port/protocol outside RFC1918 | RFC1918 filtering does not establish public routability; other ranges and IPv6 need separate handling |

Duplicate ingestion can inflate counts throughout. An inner process join excludes network records with missing creation events; duplicate starts can multiply matches. The final correlation aliases the creation-side `ParentImage` to `ProcessParentImage`, avoiding a collision with the network event's empty field.[1]

## Evidence strength

**Established within the supplied records:** the six-failure/success sequence, the account creation timestamp, the decoded literal texts, the rare host/path pairs, and the helper-to-network match on Computer + ProcessGuid.

**Investigative inference:** the Temp helper deserves contextual follow-up because of its location, parent image and network activity. The three connection timestamps supply only two 60-second intervals.

**Not established:** unauthorized access, malware identity, sustained beaconing, application protocol, data transfer contents, privileged group membership, or the exact earlier PowerShell instance launching the helper. Account names and nearby timestamps cannot replace missing session IDs or `ParentProcessGuid`.

Both rare destination IPs are within documentation ranges defined by RFC 5737.[2] Their use here does not identify real malicious infrastructure. The IPv4 private-range function tests RFC1918 membership rather than all reserved address categories.[3]

## ATT&CK mapping rationale

| Evidence being investigated | Relevant hypothesis | Qualification |
|---|---|---|
| Repeated failures and later success | [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Attempted password values and intent are unknown |
| Local `svc_support` account creation | [T1136.001 - Local Account](https://attack.mitre.org/techniques/T1136/001/) | Creation is observed; adversarial persistence is not established |
| PowerShell process and encoded parameter | [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Potential misuse context; both decoded commands are harmless |
| Rare path or destination port alone | No specific technique assigned | Insufficient behavioral evidence |

## Future work

With suitable permissions and richer telemetry, future work could validate parent/session identifiers, add DNS and file provenance, test thresholds against a larger labeled baseline, and deploy scheduled detections with operational handling. Those extensions are outside this completed lab.

## References

1. [Microsoft: KQL inner join](https://learn.microsoft.com/en-us/kusto/query/join-inner?view=microsoft-fabric)
2. [RFC 5737: Documentation address blocks](https://www.rfc-editor.org/rfc/rfc5737.txt)
3. [Microsoft: ipv4_is_private](https://learn.microsoft.com/en-us/kusto/query/ipv4-is-private-function?view=microsoft-fabric)
