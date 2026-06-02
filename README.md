# Primary

## Rapid7 InsightAppSec workbook query modifications

Use these snippets when updating a Microsoft Sentinel or Azure Workbook that
renders Rapid7 InsightAppSec findings from a custom log table such as
`InsightAppSec_CL`.

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
