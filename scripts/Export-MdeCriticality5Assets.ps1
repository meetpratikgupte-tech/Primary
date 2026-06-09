#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputPath = "mde-criticality5-assets.csv",

    [ValidateSet("Csv", "Json")]
    [string]$Format = "Csv",

    [string]$QueryPath = "",

    [string]$AccessToken = "",

    [ValidateSet("Global", "GCC", "GCCHigh", "DoD")]
    [string]$Cloud = "Global"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-RepositoryRoot {
    $scriptDirectory = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDirectory "..")).Path
}

function Get-DefenderApiBaseUrl {
    param([string]$CloudName)

    switch ($CloudName) {
        "Global" { return "https://api.security.microsoft.com" }
        "GCC" { return "https://api-gcc.security.microsoft.us" }
        "GCCHigh" { return "https://api-gov.security.microsoft.us" }
        "DoD" { return "https://api-gov.security.microsoft.us" }
        default { throw "Unsupported cloud: $CloudName" }
    }
}

function Get-DefenderAccessToken {
    param([string]$ResourceUrl)

    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        $tokenResult = Get-AzAccessToken -ResourceUrl $ResourceUrl
        if ($tokenResult.Token) {
            if ($tokenResult.Token -is [System.Security.SecureString]) {
                $credential = [System.Net.NetworkCredential]::new("", $tokenResult.Token)
                return $credential.Password
            }

            return [string]$tokenResult.Token
        }
    }

    throw @"
No access token was provided and Get-AzAccessToken is not available.

Authenticate with Az.Accounts and retry:
  Connect-AzAccount

Or pass a Defender for Endpoint API token explicitly:
  -AccessToken '<token>'

The token needs AdvancedHunting.Read.All permission for the Defender XDR API.
"@
}

$repositoryRoot = Get-RepositoryRoot
if ([string]::IsNullOrWhiteSpace($QueryPath)) {
    $QueryPath = Join-Path $repositoryRoot "queries/mde-criticality5-assets.kql"
}

if (-not (Test-Path -LiteralPath $QueryPath)) {
    throw "Query file not found: $QueryPath"
}

$apiBaseUrl = Get-DefenderApiBaseUrl -CloudName $Cloud
$query = Get-Content -LiteralPath $QueryPath -Raw

if ([string]::IsNullOrWhiteSpace($AccessToken)) {
    $AccessToken = Get-DefenderAccessToken -ResourceUrl $apiBaseUrl
}

$headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

$body = @{
    Query = $query
} | ConvertTo-Json -Depth 5

$uri = "$apiBaseUrl/api/advancedhunting/run"
Write-Verbose "Running MDE Advanced Hunting query against $uri"

$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
$results = @($response.Results)

if ($Format -eq "Json") {
    $results | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
} else {
    $results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
}

Write-Host "Wrote $($results.Count) records to $OutputPath"
