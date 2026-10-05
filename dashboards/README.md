# Native ADX dashboard template

The completed dashboard contains **seven table tiles**: a dataset overview and one headline result for each hunt. It was displayed successfully against the original 367-event table on 5 October 2026. Its source export uses native dashboard **schema version 84**.

## Configure and import

1. Open [project02-threat-hunting-dashboard-template.json](project02-threat-hunting-dashboard-template.json) in a text editor.
2. Replace `https://your-cluster.region.kusto.windows.net/` in `dataSources[0].clusterUri` with the **Cluster URI shown by your own ADX cluster**. This is a placeholder, not a working public data source. Keep `database` as `ThreatHuntingLab`, or change it to the database containing your `SecurityLabEvents` table.
3. Save the JSON as UTF-8.
4. In ADX **Dashboards**, choose **New dashboard > Import dashboard from file**, select the configured file and create the dashboard. To update an existing dashboard, use **File > Replace dashboard with file**, choose the configured JSON and **Save changes**.[1]
5. Confirm the overview shows **367 events**. Hunt tiles 01-06 should return **2, 1, 2, 2, 2, 2 rows** respectively.

The query filters, grouping and matching come from the validated hunt blocks. Some table projections omit secondary columns to make the overview easier to scan; the complete original queries and detailed results remain in `queries/` and `investigations/`.

The unused default time-range parameter was removed. Tiles query the entire fixed lab snapshot. None of the queries depend on `_startTime`, `_endTime` or a recent `ago()` interval.

## Publication and local use

The portable template contains no account identity or original cluster URI. The previously imported working dashboard can remain in the local project folder. The publication package includes the portable template so readers configure their own data source.

![Validated seven-tile dashboard](../screenshots/21-threat-hunting-dashboard.png)

## Reference

1. [Microsoft: ADX dashboards, export and file import](https://learn.microsoft.com/en-us/azure/data-explorer/azure-data-explorer-dashboards)
