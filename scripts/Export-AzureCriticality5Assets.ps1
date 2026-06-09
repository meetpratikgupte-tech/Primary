#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputPath = "azure-criticality5-assets.csv",

    [ValidateSet("Csv", "Json")]
    [string]$Format = "Csv",

    [string]$QueryPath = "",

    [int]$PageSize = 1000,

    [string[]]$SubscriptionId = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-RepositoryRoot {
    $scriptDirectory = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDirectory "..")).Path
}

function Get-PropertyValue {
    param(
        [object]$InputObject,
        [string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-ResourceGraphRows {
    param([object]$Response)

    $data = Get-PropertyValue -InputObject $Response -PropertyName "Data"
    if ($null -ne $data) {
        return @($data)
    }

    return @($Response)
}

if ($PageSize -lt 1) {
    throw "PageSize must be a positive integer."
}

if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
    throw @"
Search-AzGraph is required.

Install the Azure Resource Graph PowerShell module and sign in:
  Install-Module Az.ResourceGraph -Scope CurrentUser
  Connect-AzAccount
"@
}

$repositoryRoot = Get-RepositoryRoot
if ([string]::IsNullOrWhiteSpace($QueryPath)) {
    $QueryPath = Join-Path $repositoryRoot "queries/azure-criticality5-assets.kql"
}

if (-not (Test-Path -LiteralPath $QueryPath)) {
    throw "Query file not found: $QueryPath"
}

$query = Get-Content -LiteralPath $QueryPath -Raw
$allRows = New-Object System.Collections.Generic.List[object]
$skipToken = $null
$pageNumber = 1

do {
    $parameters = @{
        Query = $query
        First = $PageSize
    }

    if ($SubscriptionId.Count -gt 0) {
        $parameters.Subscription = $SubscriptionId
    }

    if (-not [string]::IsNullOrWhiteSpace($skipToken)) {
        $parameters.SkipToken = $skipToken
    }

    Write-Verbose "Querying Azure Resource Graph page $pageNumber"
    $response = Search-AzGraph @parameters
    $rows = Get-ResourceGraphRows -Response $response

    foreach ($row in $rows) {
        if ($null -ne $row) {
            $allRows.Add($row)
        }
    }

    $skipToken = Get-PropertyValue -InputObject $response -PropertyName "SkipToken"
    if ([string]::IsNullOrWhiteSpace($skipToken)) {
        $skipToken = Get-PropertyValue -InputObject $response -PropertyName "skipToken"
    }
    if ([string]::IsNullOrWhiteSpace($skipToken)) {
        $skipToken = Get-PropertyValue -InputObject $response -PropertyName '$skipToken'
    }
    $pageNumber++
} while (-not [string]::IsNullOrWhiteSpace($skipToken))

if ($Format -eq "Json") {
    $allRows | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
} else {
    $exportRows = foreach ($row in $allRows) {
        $copy = [ordered]@{}
        foreach ($property in $row.PSObject.Properties) {
            if ($property.Value -is [System.Collections.IDictionary] -or $property.Value -is [array]) {
                $copy[$property.Name] = $property.Value | ConvertTo-Json -Compress -Depth 20
            } else {
                $copy[$property.Name] = $property.Value
            }
        }
        [pscustomobject]$copy
    }

    $exportRows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
}

Write-Host "Wrote $($allRows.Count) records to $OutputPath"
