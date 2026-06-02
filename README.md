# Primary

## Rapid7 InsightAppSec workbook query modifications

Use these snippets when updating a Microsoft Sentinel or Azure Workbook that
renders Rapid7 InsightAppSec findings from a custom log table such as
`InsightAppSec_CL`.

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
| where Status == "UNREVIEWED"
| where isnotempty(VulnerabilityID)
| where isnotempty(VulnerabilityType)
| summarize arg_max(TimeGenerated, *) by VulnerabilityID;
Deduped
| summarize Count = count() by VulnerabilityType, Severity
| order by Count desc
| take 20
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
