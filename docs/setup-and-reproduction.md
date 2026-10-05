# Setup and reproduction

This guide recreates the completed lab in an **Azure Data Explorer free cluster** using the supplied CSV. It does not require a Sentinel workspace, Cloud Shell, live endpoint agents or an Azure subscription. Microsoft documents free-cluster creation without a credit card or Azure subscription.[1]

## 1. Create the database

Open [Azure Data Explorer](https://dataexplorer.azure.com), go to **My cluster**, and create a free cluster. Use a cluster display name such as `KQLThreatHuntingLab` and a database name of `ThreatHuntingLab`. If your free cluster already exists, use its existing database.[1]

These are reproduction steps. The original lab already has its data and dashboard; completing the documentation does not require importing the records again.

## 2. Import the CSV once

In **Query**, right-click the target database and choose **Get data**. Select **Local file**, choose `data/kql-lab-events.csv`, and use a new table named `SecurityLabEvents`. On the inspection step, choose CSV and **First row header**, then check names and types before selecting **Finish**.[2]

The complete [reference schema](../data/README.md) has 23 columns. The important representations for these queries are:

| Column | Required representation |
|---|---|
| `TimeGenerated` | `datetime` |
| `EventSource`, `EventID`, `LogonType` | `string` |
| `ProcessGuid` | `guid` |
| `DestinationPort`, `ProcessId` | Numeric; the reference uses `long` |
| `Initiated`, `IsSynthetic` | `bool` |
| Other supplied fields | `string` |

For a new table, edit inferred types during inspection. In an existing table, the ingestion wizard cannot change the type of an existing column.[2] An optional `.create table` reference is in [schema-reference.kql](../data/schema-reference.kql); it creates an empty table and does not alter an existing table.[3]

Confirm that the header is not treated as an event. Importing the same file again appends duplicate records and can inflate hunt counts. The source identifiers `LAB-000001` through `LAB-000367` are unique in the CSV.

## 3. Validate the dataset

Select `ThreatHuntingLab` in the query editor. Run each block of [00-dataset-validation.kql](../queries/00-dataset-validation.kql) separately. The overview is:

```kusto
SecurityLabEvents
| summarize TotalEvents = count(),
            FirstEvent = min(TimeGenerated),
            LastEvent = max(TimeGenerated)
```

Expected: **367**, **2026-09-24 07:00:00 UTC**, **2026-09-30 15:01:00 UTC**. The duplicate-ID diagnostic should return no rows, and all 367 records should have `IsSynthetic == true`.

Use `SecurityLabEvents | getschema` to inspect the table's actual schema.[4] `EventID` values are quoted in the hunt files, for example `EventID == "4625"`. Empty fields in the CSV represent attributes unavailable or inapplicable to that event type.

Optional local verification, if Python 3 is already available:

```text
python scripts/verify_dataset.py
```

The verifier uses only Python's standard library. It checks the supplied CSV's checksum, row count, unique IDs, event totals and six headline findings. It does not execute KQL or measure production detection performance.

## 4. Run the six hunts

Run the six numbered files in order, selecting **one complete query block at a time**. A file may contain overview and follow-up blocks. For a block using `let`, select all of its `let` definitions and its final expression together, including the semicolons.[5]

The original hunt queries can remain in read-only protected mode. The optional table-creation command is a separate management operation for an empty reproduction environment.

| File | Main output | Follow-up |
|---|---|---|
| [01](../queries/01-multiple-failed-logons.kql) | 2 failure groups | 13 individual failures |
| [02](../queries/02-success-after-failed-logons.kql) | 1 qualifying success | 7-event timeline |
| [03](../queries/03-local-account-creation.kql) | 2 local creations | 3 creations of either scope |
| [04](../queries/04-encoded-powershell.kql) | 2 encoded PowerShell events | Inspect decoded payload text |
| [05](../queries/05-rare-processes.kql) | 2 rare host/path pairs | 2 detailed process records |
| [06](../queries/06-rare-network-destinations.kql) | 2 rare destination groups | 4 network events; 3 process-correlated rows |

These queries scan the historical dataset. Leave `TimeGenerated` at its supplied values; do not replay all records at the same timestamp. Using a recent `ago()` filter would eventually exclude the snapshot.

For PowerShell inspection, [04-decode-powershell.ps1](../queries/04-decode-powershell.ps1) converts the two literal Base64 strings into UTF-16LE text. The expected outputs are `Write-Output 'Approved maintenance check'` and `Write-Output 'KQL-Lab-Demo'`. The decoder displays text; it does not run those decoded strings.

## 5. Import the dashboard

Follow [dashboards/README.md](../dashboards/README.md). Set the JSON template's `clusterUri` to your own cluster URI and keep its database as `ThreatHuntingLab`. Import the configured template and save it. The seven tiles should show the overview plus the six headline hunt results.

The public template uses a placeholder URI. The original working dashboard was executed successfully in the owner's cluster; the placeholder version needs your data-source configuration before it can query.

## Troubleshooting

| Symptom | Check |
|---|---|
| Table not found | Select the correct database; confirm the name is exactly `SecurityLabEvents` |
| Wrong counts | Confirm 367 rows, no duplicate `LabEventId`, correct first-row header handling and original timestamps |
| Type or comparison error | Inspect `getschema`; compare the fields above with the reference |
| `let` name not found | Select the whole query block, including every definition and the final expression |
| Dashboard connection fails | Replace the placeholder with your cluster URI and confirm database access |
| Parent field appears empty after a join | Use the final query's `ProcessParentImage` alias for the creation-side field |

## Sources

1. [Microsoft: Create a free ADX cluster](https://learn.microsoft.com/en-us/azure/data-explorer/start-for-free-web-ui)
2. [Microsoft: Get data from a local file](https://learn.microsoft.com/en-us/azure/data-explorer/get-data-file)
3. [Microsoft: .create table](https://learn.microsoft.com/en-us/kusto/management/create-table-command?view=microsoft-fabric)
4. [Microsoft: getschema](https://learn.microsoft.com/en-us/kusto/query/getschema-operator?view=microsoft-fabric)
5. [Microsoft: let statement](https://learn.microsoft.com/en-us/kusto/query/let-statement?view=microsoft-fabric)
