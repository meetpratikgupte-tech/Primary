# Primary

## Extract Azure Criticality 5 assets

Use Azure Resource Graph to list every Azure resource tagged or labeled as
`automatedCriticality:5`.

### One-off Azure CLI query

Run this from an authenticated Azure CLI session:

```bash
az graph query \
  --first 1000 \
  --query "data" \
  -o table \
  -q "$(cat queries/azure-criticality5-assets.kql)"
```

### Export to CSV or JSON

The export script wraps the same query and writes results to a file:

```bash
bash scripts/export_azure_criticality5_assets.sh \
  --output criticality5-assets.csv \
  --format csv
```

Use `--format json` to write the extracted records as JSON instead.
