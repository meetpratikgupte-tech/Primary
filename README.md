# Primary

## Consolidated Sentinel vulnerability dashboard query

Use `queries/sentinel-consolidated-vulnerability-severity.kql` in Microsoft
Sentinel Logs or a Sentinel workbook query to combine the three dashboard
queries into one result set.

The consolidated query preserves the existing classification logic and returns
one table with these columns:

| Area | Metric | Critical | High | Medium | Total |
| --- | --- | ---: | ---: | ---: | ---: |
| Severity of servers | Unique CVEs | count | count | count | count |
| Web application vulnerability severity | Unique vulnerabilities | count | count | count | count |
| Device recommendations | Server Count | count | count | count | count |
| Device recommendations | Recommendation Count | count | count | count | count |

Use the `Critical`, `High`, and `Medium` columns directly in workbook tiles,
grids, or charts.

## Extract Azure Criticality 5 assets

Use one of these options to list assets tagged or labeled as
`automatedCriticality:5`. MDE Advanced Hunting covers Defender device assets;
Azure Resource Graph covers Azure resource tags.

### MDE Advanced Hunting

Use `queries/mde-criticality5-assets.kql` in Microsoft Defender XDR Advanced
Hunting to extract MDE device assets that have the `automatedCriticality:5`
manual or dynamic tag:

```kql
let CriticalityTag = "automatedCriticality:5";
DeviceInfo
| where Timestamp > ago(30d)
| extend ManualTagsText = tostring(DeviceManualTags)
| extend DynamicTagsText = tostring(DeviceDynamicTags)
| where ManualTagsText contains CriticalityTag
    or DynamicTagsText contains CriticalityTag
| summarize arg_max(Timestamp, *) by DeviceId
| project
    Timestamp,
    DeviceName,
    DeviceId,
    AadDeviceId,
    OSPlatform,
    OSVersion,
    MachineGroup,
    OnboardingStatus,
    SensorHealthState,
    ExposureLevel,
    RiskScore,
    DeviceManualTags,
    DeviceDynamicTags,
    PublicIP,
    LoggedOnUsers
| order by DeviceName asc
```

### PowerShell export from MDE

Run the MDE query through the Defender Advanced Hunting API and export the
results:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
Connect-AzAccount
./scripts/Export-MdeCriticality5Assets.ps1 `
  -OutputPath mde-criticality5-assets.csv `
  -Format Csv
```

The signed-in account or app token needs Defender XDR
`AdvancedHunting.Read.All`. If you already have a Defender API token, pass it
with `-AccessToken`.

### PowerShell export from Azure Resource Graph

Use this option when the `automatedCriticality:5` label is on Azure resource
tags and you want to stay in PowerShell:

```powershell
Install-Module Az.ResourceGraph -Scope CurrentUser
Connect-AzAccount
./scripts/Export-AzureCriticality5Assets.ps1 `
  -OutputPath azure-criticality5-assets.csv `
  -Format Csv
```

To limit the export to specific subscriptions:

```powershell
./scripts/Export-AzureCriticality5Assets.ps1 `
  -SubscriptionId "00000000-0000-0000-0000-000000000000","11111111-1111-1111-1111-111111111111"
```

### Preview the first 1000 matches

Run this from an authenticated Azure CLI session:

```bash
az graph query \
  --first 1000 \
  --query "data" \
  -o table \
  -q "$(cat queries/azure-criticality5-assets.kql)"
```

### Export all matches to CSV or JSON

The export script wraps the same query, follows Resource Graph skip tokens, and
writes results to a file:

```bash
bash scripts/export_azure_criticality5_assets.sh \
  --output criticality5-assets.csv \
  --format csv
```

Use `--format json` to write the extracted records as JSON instead.
