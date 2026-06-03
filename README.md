# Primary

## Rapid7 InsightAppSec workbook query modifications

Use these snippets when updating a Microsoft Sentinel or Azure Workbook that
renders Rapid7 InsightAppSec findings from a custom log table such as
`InsightAppSec_CL`.

### Create the Rapid7 InsightAppSec LAW table with PowerShell

Use this Azure PowerShell script to create a Log Analytics Workspace custom
table for Rapid7 InsightAppSec data. The schema includes the columns used by
the workbook queries below, including status, severity, app, vulnerability ID,
and last-discovered fields.

Replace the subscription, resource group, workspace, and table name values
before running the script in Azure Cloud Shell or an authenticated local
PowerShell session.

```powershell
Connect-AzAccount

$subscriptionId = "<subscription-id>"
$resourceGroupName = "<resource-group-name>"
$workspaceName = "<log-analytics-workspace-name>"
$tableName = "Rapid7InsightAppSecV2_CL"

Set-AzContext -SubscriptionId $subscriptionId

# Custom table names created through PowerShell/API must include the _CL suffix.
if ($tableName -notlike "*_CL") {
    throw "Custom Log Analytics table name must end with _CL."
}

$tablePayload = @"
{
  "properties": {
    "schema": {
      "name": "$tableName",
      "columns": [
        { "name": "TimeGenerated", "type": "DateTime" },
        { "name": "RecordType_s", "type": "String" },
        { "name": "AppName_s", "type": "String" },
        { "name": "AppDescription_s", "type": "String" },
        { "name": "AppUuid_g", "type": "Guid" },
        { "name": "AppUuid_s", "type": "String" },
        { "name": "Severity_s", "type": "String" },
        { "name": "Status_s", "type": "String" },
        { "name": "Vuln_status_s", "type": "String" },
        { "name": "VulnerabilityStatus_s", "type": "String" },
        { "name": "Vuln_uuid_g", "type": "Guid" },
        { "name": "Vuln_uuid_s", "type": "String" },
        { "name": "Vuln_lastDiscovered_t", "type": "DateTime" },
        { "name": "Vuln_lastDiscovered_s", "type": "String" },
        { "name": "AttackType_s", "type": "String" },
        { "name": "ModuleName_s", "type": "String" },
        { "name": "VulnerabilityTitle_s", "type": "String" },
        { "name": "Cvss_d", "type": "Real" },
        { "name": "ScanId_s", "type": "String" }
      ]
    }
  }
}
"@

$tablePath = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/tables/$tableName?api-version=2021-12-01-preview"

try {
    Invoke-AzRestMethod -Method PUT -Path $tablePath -Payload $tablePayload
    Invoke-AzRestMethod -Method GET -Path $tablePath
}
catch {
    Write-Host "Failed to create or read table $tableName." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    if ($_.ErrorDetails.Message) {
        Write-Host $_.ErrorDetails.Message -ForegroundColor Yellow
    }

    throw
}
```

After the table is created, confirm it exists:

```kql
Rapid7InsightAppSecV2_CL
| take 10
```

### Deduplicated one-year unreviewed/new rollup

Use this query for the `Rapid7InsightAppSecV1_CL` workbook rollup when you only
want unique vulnerabilities that are `UNREVIEWED` or `NEW` and were last
discovered within the past year.

```kql
let Deduped =
Rapid7InsightAppSecV1_CL
| where column_ifexists("RecordType_s", "DATA") != "SCHEMA_SEED"
| extend
    AppDescriptionOriginal = tostring(column_ifexists("AppDescription_s", "")),
    SeverityRaw = tostring(column_ifexists("Severity_s", "")),
    StatusRaw = case(
        isnotempty(tostring(column_ifexists("Vuln_status_s", ""))), tostring(column_ifexists("Vuln_status_s", "")),
        isnotempty(tostring(column_ifexists("Status_s", ""))), tostring(column_ifexists("Status_s", "")),
        tostring(column_ifexists("VulnerabilityStatus_s", ""))
    ),
    VulnUuidGuid = tostring(column_ifexists("Vuln_uuid_g", "")),
    VulnUuidString = tostring(column_ifexists("Vuln_uuid_s", "")),
    VulnLastDiscoveredDate = column_ifexists("Vuln_lastDiscovered_t", datetime(null)),
    VulnLastDiscoveredString = tostring(column_ifexists("Vuln_lastDiscovered_s", ""))
| extend
    AppDescription = trim(@"[\s]+", AppDescriptionOriginal),
    AppDescriptionKey = toupper(trim(@"[\s]+", AppDescriptionOriginal)),
    Severity = toupper(trim(@"[\s]+", SeverityRaw)),
    Status = toupper(trim(@"[\s]+", StatusRaw)),
    VulnerabilityID = case(
        isnotempty(VulnUuidGuid), VulnUuidGuid,
        isnotempty(VulnUuidString), VulnUuidString,
        ""
    ),
    Vuln_lastDiscovered = coalesce(
        VulnLastDiscoveredDate,
        todatetime(VulnLastDiscoveredString)
    )
| where Vuln_lastDiscovered >= ago(365d)
| where Severity in ("CRITICAL", "HIGH", "MEDIUM")
| where Status in ("UNREVIEWED", "NEW")
| where isnotempty(AppDescriptionKey)
| where isnotempty(VulnerabilityID)
| summarize arg_max(TimeGenerated, *) by AppDescriptionKey, VulnerabilityID;
Deduped
| summarize
    AppDescription = any(AppDescription),
    Critical = countif(Severity == "CRITICAL"),
    High = countif(Severity == "HIGH"),
    Medium = countif(Severity == "MEDIUM"),
    Total = count()
    by AppDescriptionKey
| project
    AppDescription,
    Critical,
    High,
    Medium,
    Total
| order by Critical desc, High desc, Medium desc
```

### Deduplicated one-year status counts

Use this query when the workbook needs a count by InsightAppSec status with no
duplicate vulnerability IDs. The `VulnerabilityID` value is normalized before
deduplication so GUID/string casing or whitespace differences do not create
separate rows.

```kql
let AllStatuses = datatable(Status:string, SortOrder:int)
[
    "UNREVIEWED", 1,
    "IGNORED", 2,
    "FALSE_POSITIVE", 3,
    "VERIFIED", 4,
    "REMEDIATED", 5,
    "DUPLICATE", 6,
    "NEW", 7
];
let Deduped =
Rapid7InsightAppSecV1_CL
| where column_ifexists("RecordType_s", "DATA") != "SCHEMA_SEED"
| extend
    StatusRaw = toupper(trim(@"[\s]+", tostring(column_ifexists("Status_s", "")))),
    VulnUuidGuid = tostring(column_ifexists("Vuln_uuid_g", "")),
    VulnUuidString = tostring(column_ifexists("Vuln_uuid_s", "")),
    VulnLastDiscoveredDate = column_ifexists("Vuln_lastDiscovered_t", datetime(null)),
    VulnLastDiscoveredString = tostring(column_ifexists("Vuln_lastDiscovered_s", ""))
| extend
    Status = case(
        StatusRaw in ("FALSE POSITIVE", "FALSE-POSITIVE", "FALSE_POSITIVE"), "FALSE_POSITIVE",
        StatusRaw in ("UNREVIEWED", "UNREVIEWED_OPEN", "OPEN"), "UNREVIEWED",
        StatusRaw == "IGNORED", "IGNORED",
        StatusRaw == "VERIFIED", "VERIFIED",
        StatusRaw == "REMEDIATED", "REMEDIATED",
        StatusRaw == "DUPLICATE", "DUPLICATE",
        StatusRaw == "NEW", "NEW",
        StatusRaw
    ),
    VulnerabilityIDRaw = case(
        isnotempty(VulnUuidGuid), VulnUuidGuid,
        isnotempty(VulnUuidString), VulnUuidString,
        ""
    ),
    Vuln_lastDiscovered = coalesce(
        VulnLastDiscoveredDate,
        todatetime(VulnLastDiscoveredString)
    )
| extend VulnerabilityID = toupper(trim(@"[\s]+", VulnerabilityIDRaw))
| where Vuln_lastDiscovered >= ago(365d)
| where isnotempty(VulnerabilityID)
| where Status in ("UNREVIEWED", "IGNORED", "FALSE_POSITIVE", "VERIFIED", "REMEDIATED", "DUPLICATE", "NEW")
| summarize arg_max(TimeGenerated, *) by VulnerabilityID;
let Counts =
Deduped
| summarize Count = count() by Status;
AllStatuses
| join kind=leftouter Counts on Status
| project
    Status,
    Count = coalesce(Count, 0),
    SortOrder
| order by SortOrder asc
```

### Deduplicated top unreviewed vulnerability types

Use this query when the workbook needs the top vulnerability types by severity,
limited to unique `UNREVIEWED` vulnerabilities discovered within the past year.

```kql
let Deduped =
Rapid7InsightAppSecV1_CL
| where column_ifexists("RecordType_s", "DATA") != "SCHEMA_SEED"
| extend
    AttackType = tostring(column_ifexists("AttackType_s", "")),
    ModuleName = tostring(column_ifexists("ModuleName_s", "")),
    Severity = toupper(trim(@"[\s]+", tostring(column_ifexists("Severity_s", "")))),
    StatusRaw = toupper(trim(@"[\s]+", tostring(column_ifexists("Status_s", "")))),
    VulnUuidGuid = tostring(column_ifexists("Vuln_uuid_g", "")),
    VulnUuidString = tostring(column_ifexists("Vuln_uuid_s", "")),
    VulnLastDiscoveredDate = column_ifexists("Vuln_lastDiscovered_t", datetime(null)),
    VulnLastDiscoveredString = tostring(column_ifexists("Vuln_lastDiscovered_s", ""))
| extend
    Status = case(
        StatusRaw in ("UNREVIEWED", "UNREVIEWED_OPEN", "OPEN"), "UNREVIEWED",
        StatusRaw
    ),
    VulnerabilityIDRaw = case(
        isnotempty(VulnUuidGuid), VulnUuidGuid,
        isnotempty(VulnUuidString), VulnUuidString,
        ""
    ),
    Vuln_lastDiscovered = coalesce(
        VulnLastDiscoveredDate,
        todatetime(VulnLastDiscoveredString)
    )
| extend
    VulnerabilityID = toupper(trim(@"[\s]+", VulnerabilityIDRaw)),
    VulnerabilityType = trim(@"[\s]+", iff(isnotempty(AttackType), AttackType, ModuleName))
| where Vuln_lastDiscovered >= ago(365d)
| where isnotempty(VulnerabilityID)
| where isnotempty(VulnerabilityType)
| summarize arg_max(TimeGenerated, *) by VulnerabilityID;
Deduped
| where Status == "UNREVIEWED"
| summarize Count = count_distinct(VulnerabilityID) by VulnerabilityType, Severity
| order by Count desc
| take 20
```

### Deduplicated V2 top unreviewed applications

Use this query when the workbook needs the top applications by unique
`UNREVIEWED` vulnerabilities from `Rapid7InsightAppSecV2_CL`.

```kql
let LatestByAppVulnerability =
Rapid7InsightAppSecV2_CL
| where column_ifexists("RecordType_s", "DATA") != "SCHEMA_SEED"
| extend
    AppName = trim(@"[\s]+", tostring(column_ifexists("AppName_s", ""))),
    AppID = tostring(column_ifexists("AppUuid_g", column_ifexists("AppUuid_s", ""))),
    StatusRaw = toupper(trim(@"[\s]+", case(
        isnotempty(tostring(column_ifexists("Vuln_status_s", ""))), tostring(column_ifexists("Vuln_status_s", "")),
        isnotempty(tostring(column_ifexists("Status_s", ""))), tostring(column_ifexists("Status_s", "")),
        tostring(column_ifexists("VulnerabilityStatus_s", ""))
    ))),
    VulnUuidGuid = tostring(column_ifexists("Vuln_uuid_g", "")),
    VulnUuidString = tostring(column_ifexists("Vuln_uuid_s", "")),
    VulnLastDiscoveredDate = column_ifexists("Vuln_lastDiscovered_t", datetime(null)),
    VulnLastDiscoveredString = tostring(column_ifexists("Vuln_lastDiscovered_s", ""))
| extend
    Status = case(
        StatusRaw in ("UNREVIEWED", "UNREVIEWED_OPEN", "OPEN"), "UNREVIEWED",
        StatusRaw
    ),
    VulnerabilityIDRaw = case(
        isnotempty(VulnUuidGuid), VulnUuidGuid,
        isnotempty(VulnUuidString), VulnUuidString,
        ""
    ),
    Vuln_lastDiscovered = coalesce(
        VulnLastDiscoveredDate,
        todatetime(VulnLastDiscoveredString)
    )
| extend
    AppKey = iff(isnotempty(AppID), toupper(trim(@"[\s]+", AppID)), toupper(AppName)),
    VulnerabilityID = toupper(trim(@"[\s]+", VulnerabilityIDRaw))
| where Vuln_lastDiscovered >= ago(30d)
| where isnotempty(AppName)
| where AppName !in~ ("other", "others", "unknown", "not available", "n/a", "null")
| where isnotempty(AppKey)
| where isnotempty(VulnerabilityID)
| summarize arg_max(TimeGenerated, *) by AppKey, VulnerabilityID;
let TopApps =
LatestByAppVulnerability
| where Status == "UNREVIEWED"
| summarize
    AppName = any(AppName),
    TotalVulnerabilities = count_distinct(VulnerabilityID)
    by AppKey
| project AppName, TotalVulnerabilities
| top 10 by TotalVulnerabilities desc;
TopApps
| order by TotalVulnerabilities asc
```

### Deduplicated unreviewed critical severity count

Use this query when the workbook needs the web application vulnerability
severity tile for unique critical vulnerabilities whose latest status is
`UNREVIEWED`.

```kql
let LatestByVulnerability =
Rapid7InsightAppSecV1_CL
| where column_ifexists("RecordType_s", "DATA") != "SCHEMA_SEED"
| extend
    Severity = toupper(trim(@"[\s]+", tostring(column_ifexists("Severity_s", "")))),
    StatusRaw = toupper(trim(@"[\s]+", case(
        isnotempty(tostring(column_ifexists("Vuln_status_s", ""))), tostring(column_ifexists("Vuln_status_s", "")),
        isnotempty(tostring(column_ifexists("Status_s", ""))), tostring(column_ifexists("Status_s", "")),
        tostring(column_ifexists("VulnerabilityStatus_s", ""))
    ))),
    VulnUuidGuid = tostring(column_ifexists("Vuln_uuid_g", "")),
    VulnUuidString = tostring(column_ifexists("Vuln_uuid_s", "")),
    VulnLastDiscoveredDate = column_ifexists("Vuln_lastDiscovered_t", datetime(null)),
    VulnLastDiscoveredString = tostring(column_ifexists("Vuln_lastDiscovered_s", ""))
| extend
    Status = case(
        StatusRaw in ("UNREVIEWED", "UNREVIEWED_OPEN", "OPEN"), "UNREVIEWED",
        StatusRaw
    ),
    VulnerabilityIDRaw = case(
        isnotempty(VulnUuidGuid), VulnUuidGuid,
        isnotempty(VulnUuidString), VulnUuidString,
        ""
    ),
    Vuln_lastDiscovered = coalesce(
        VulnLastDiscoveredDate,
        todatetime(VulnLastDiscoveredString)
    )
| extend
    Status = trim(@"[\s]+", Status),
    VulnerabilityID = toupper(trim(@"[\s]+", VulnerabilityIDRaw))
| where Vuln_lastDiscovered >= ago(180d)
| where isnotempty(VulnerabilityID)
| summarize arg_max(TimeGenerated, *) by VulnerabilityID;
LatestByVulnerability
| where Severity == "CRITICAL"
| where Status == "UNREVIEWED"
| summarize Critical = count_distinct(VulnerabilityID)
```

### Deduplicated unreviewed high severity count

Use this query when the workbook needs the web application vulnerability
severity tile for unique high vulnerabilities whose latest status is
`UNREVIEWED`.

```kql
let LatestByVulnerability =
Rapid7InsightAppSecV1_CL
| where column_ifexists("RecordType_s", "DATA") != "SCHEMA_SEED"
| extend
    Severity = toupper(trim(@"[\s]+", tostring(column_ifexists("Severity_s", "")))),
    StatusRaw = toupper(trim(@"[\s]+", case(
        isnotempty(tostring(column_ifexists("Vuln_status_s", ""))), tostring(column_ifexists("Vuln_status_s", "")),
        isnotempty(tostring(column_ifexists("Status_s", ""))), tostring(column_ifexists("Status_s", "")),
        tostring(column_ifexists("VulnerabilityStatus_s", ""))
    ))),
    VulnUuidGuid = tostring(column_ifexists("Vuln_uuid_g", "")),
    VulnUuidString = tostring(column_ifexists("Vuln_uuid_s", "")),
    VulnLastDiscoveredDate = column_ifexists("Vuln_lastDiscovered_t", datetime(null)),
    VulnLastDiscoveredString = tostring(column_ifexists("Vuln_lastDiscovered_s", ""))
| extend
    Status = case(
        StatusRaw in ("UNREVIEWED", "UNREVIEWED_OPEN", "OPEN"), "UNREVIEWED",
        StatusRaw
    ),
    VulnerabilityIDRaw = case(
        isnotempty(VulnUuidGuid), VulnUuidGuid,
        isnotempty(VulnUuidString), VulnUuidString,
        ""
    ),
    Vuln_lastDiscovered = coalesce(
        VulnLastDiscoveredDate,
        todatetime(VulnLastDiscoveredString)
    )
| extend
    Status = trim(@"[\s]+", Status),
    VulnerabilityID = toupper(trim(@"[\s]+", VulnerabilityIDRaw))
| where Vuln_lastDiscovered >= ago(180d)
| where isnotempty(VulnerabilityID)
| summarize arg_max(TimeGenerated, *) by VulnerabilityID;
LatestByVulnerability
| where Severity == "HIGH"
| where Status == "UNREVIEWED"
| summarize High = count_distinct(VulnerabilityID)
```

### Normalize InsightAppSec findings

Start workbook queries with a normalized source block so each visual can reuse
the same application, vulnerability, severity, status, and scan fields.

```kql
let AppFilter = "{AppName}";
let SeverityFilter = dynamic({Severity});
let StatusFilter = dynamic({Status});
let InsightAppSecFindings =
    InsightAppSec_CL
    | extend Payload = todynamic(coalesce(
        column_ifexists("RawData", ""),
        column_ifexists("RawData_s", ""),
        column_ifexists("Properties", "")
    ))
    | extend
        AppName = coalesce(
            tostring(Payload.app.name),
            tostring(Payload.application.name),
            tostring(Payload.appName),
            tostring(column_ifexists("appName_s", ""))
        ),
        VulnerabilityTitle = coalesce(
            tostring(Payload.vulnerability.title),
            tostring(Payload.title),
            tostring(column_ifexists("vulnerabilityTitle_s", ""))
        ),
        Severity = toupper(coalesce(
            tostring(Payload.vulnerability.severity),
            tostring(Payload.severity),
            tostring(column_ifexists("severity_s", ""))
        )),
        Status = toupper(coalesce(
            tostring(Payload.vulnerability.status),
            tostring(Payload.status),
            tostring(column_ifexists("status_s", ""))
        )),
        ScanId = coalesce(
            tostring(Payload.vulnerability.scans[0].id),
            tostring(Payload.scan.id),
            tostring(column_ifexists("scanId_s", ""))
        ),
        Cvss = todouble(coalesce(
            tostring(Payload.vulnerability.cvss),
            tostring(Payload.cvss),
            tostring(column_ifexists("cvss_d", ""))
        ))
    | where isempty(AppFilter) or AppName contains AppFilter
    | where array_length(SeverityFilter) == 0 or set_has_element(SeverityFilter, Severity)
    | where array_length(StatusFilter) == 0 or set_has_element(StatusFilter, Status);
```

### Active findings widget

Use the normalized block above, then append this query for a table of findings
that still need triage or remediation:

```kql
InsightAppSecFindings
| where Status in ("UNREVIEWED", "VERIFIED")
| project TimeGenerated, AppName, VulnerabilityTitle, Severity, Status, Cvss, ScanId
| order by case(Severity == "HIGH", 1, Severity == "MEDIUM", 2, Severity == "LOW", 3, 4) asc,
          Cvss desc,
          TimeGenerated desc
```

### Application risk rollup widget

Use the normalized block above, then append this query for application-level
workbook tiles or grids:

```kql
InsightAppSecFindings
| summarize
    TotalFindings = count(),
    HighFindings = countif(Severity == "HIGH"),
    MediumFindings = countif(Severity == "MEDIUM"),
    LowFindings = countif(Severity == "LOW"),
    InformationalFindings = countif(Severity == "INFORMATIONAL"),
    LatestFinding = max(TimeGenerated)
    by AppName
| order by HighFindings desc, MediumFindings desc, TotalFindings desc
```

### Rapid7 API-backed query filters

If a workbook parameter calls the InsightAppSec API directly, update the
Vulnerability resource query to use Rapid7's filter syntax:

```text
vulnerability.severity IN ['HIGH','MEDIUM'] AND vulnerability.status IN ['UNREVIEWED','VERIFIED']
```

For scan-scoped workbook panels, include the scan identifier:

```text
vulnerability.scans.id='{ScanId}' AND vulnerability.severity IN ['HIGH','MEDIUM']
```

For application-scoped panels, filter by application name instead of scan ID:

```text
app.name CONTAINS '{AppName}' AND vulnerability.status IN ['UNREVIEWED','VERIFIED']
```
