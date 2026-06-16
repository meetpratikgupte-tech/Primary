# Primary

## Cursor Cloud specific instructions

### What this repo is

This repository is a collection of **security analytics artifacts** for Microsoft
cloud security tooling — not a runnable client/server application. There is **no
build system, no test suite, no linter config, no CI, and no dependency
manifests**.

The checked-out `main` branch is intentionally a near-empty placeholder
(`README.md` only). The substantive content lives in feature branches and is made
up of:

- `queries/*.kql` — Kusto (KQL) queries meant to be pasted into Microsoft Sentinel
  Logs / Workbooks or Defender XDR Advanced Hunting.
- `scripts/Export-*.ps1` — PowerShell exporters (require `Az.Accounts` /
  `Az.ResourceGraph` and `Connect-AzAccount`).
- `scripts/export_azure_criticality5_assets.sh` — Bash exporter that wraps
  `az graph query`, follows Resource Graph skip tokens, and formats results to
  CSV/JSON via embedded `python3`.

### Running / testing

- There is nothing to `build`, `lint`, or `test` via tooling — these commands do
  not exist. Validation is manual.
- True end-to-end runs of the KQL queries and PowerShell/Bash exporters require a
  **live Microsoft tenant** (Azure subscription + `az login` / `Connect-AzAccount`,
  Defender XDR `AdvancedHunting.Read.All`, a Sentinel/Log Analytics workspace).
  These credentials are **not** available in the cloud VM, so cloud agents cannot
  exercise the real cloud calls.
- The only piece that can be exercised locally without a tenant is the Bash
  exporter's argument parsing + skip-token paging loop + CSV/JSON formatting. Do
  this by putting a stub `az` (that prints a sample Resource Graph `{"data": [...],
  "skipToken": ...}` payload) earlier on `PATH`, then running
  `scripts/export_azure_criticality5_assets.sh --output out.csv --format csv`.
  `python3` is already installed; the Bash exporter needs nothing else.

### Tooling versions present in the base image

`python3` (3.12), `bash` (5.2), `node` (22), and `git` are preinstalled. The
Azure CLI (`az`) and PowerShell (`pwsh`) are **not** installed; install them only
if you actually need to talk to a live tenant (and you have credentials).
