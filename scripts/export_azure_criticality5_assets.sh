#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Export Azure resources labeled automatedCriticality:5 using Azure Resource Graph.

Usage:
  bash scripts/export_azure_criticality5_assets.sh [options]

Options:
  --output PATH              Output file path. Defaults to criticality5-assets.csv.
  --format csv|json          Output format. Defaults to csv.
  --query-file PATH          KQL query file. Defaults to queries/azure-criticality5-assets.kql.
  --page-size NUMBER         Resource Graph page size. Defaults to 1000.
  --subscriptions IDS        Optional comma-separated subscription IDs to query.
  -h, --help                 Show this help text.

Prerequisites:
  - Authenticated Azure CLI session: az login
  - Resource Graph command available: az graph query
  - python3
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

output_path="criticality5-assets.csv"
format="csv"
query_file="${repo_root}/queries/azure-criticality5-assets.kql"
page_size="1000"
subscriptions_csv=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output_path="${2:?Missing value for --output}"
      shift 2
      ;;
    --format)
      format="${2:?Missing value for --format}"
      shift 2
      ;;
    --query-file)
      query_file="${2:?Missing value for --query-file}"
      shift 2
      ;;
    --page-size)
      page_size="${2:?Missing value for --page-size}"
      shift 2
      ;;
    --subscriptions)
      subscriptions_csv="${2:?Missing value for --subscriptions}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$format" != "csv" && "$format" != "json" ]]; then
  echo "--format must be either csv or json" >&2
  exit 2
fi

if [[ ! "$page_size" =~ ^[0-9]+$ || "$page_size" -lt 1 ]]; then
  echo "--page-size must be a positive integer" >&2
  exit 2
fi

if [[ ! -f "$query_file" ]]; then
  echo "Query file not found: $query_file" >&2
  exit 2
fi

if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI is required. Install it and authenticate with az login." >&2
  exit 127
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to format Resource Graph results." >&2
  exit 127
fi

query="$(<"$query_file")"
tmp_dir="$(mktemp -d)"
records_file="${tmp_dir}/records.ndjson"
page_file="${tmp_dir}/page.json"
trap 'rm -rf "$tmp_dir"' EXIT

declare -a az_args=(graph query --first "$page_size" -q "$query" -o json)

if [[ -n "$subscriptions_csv" ]]; then
  IFS=',' read -r -a subscriptions <<< "$subscriptions_csv"
  az_args+=(--subscriptions "${subscriptions[@]}")
fi

skip_token=""
page_number=1

while :; do
  page_args=("${az_args[@]}")
  if [[ -n "$skip_token" ]]; then
    page_args+=(--skip-token "$skip_token")
  fi

  echo "Querying Azure Resource Graph page ${page_number}..." >&2
  az "${page_args[@]}" > "$page_file"

  python3 - "$page_file" "$records_file" <<'PY'
import json
import sys

page_path, records_path = sys.argv[1], sys.argv[2]
with open(page_path, encoding="utf-8") as page_handle:
    payload = json.load(page_handle)

records = payload.get("data") or []
with open(records_path, "a", encoding="utf-8") as records_handle:
    for record in records:
        records_handle.write(json.dumps(record, separators=(",", ":")) + "\n")
PY

  skip_token="$(python3 - "$page_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as page_handle:
    payload = json.load(page_handle)

for key in ("skipToken", "skip_token", "$skipToken"):
    value = payload.get(key)
    if value:
        print(value)
        break
PY
)"

  if [[ -z "$skip_token" ]]; then
    break
  fi

  page_number=$((page_number + 1))
done

python3 - "$records_file" "$output_path" "$format" <<'PY'
import csv
import json
import sys

records_path, output_path, output_format = sys.argv[1], sys.argv[2], sys.argv[3]
records = []

try:
    with open(records_path, encoding="utf-8") as records_handle:
        records = [json.loads(line) for line in records_handle if line.strip()]
except FileNotFoundError:
    records = []

if output_format == "json":
    with open(output_path, "w", encoding="utf-8") as output_handle:
        json.dump(records, output_handle, indent=2)
        output_handle.write("\n")
else:
    fieldnames = [
        "name",
        "type",
        "id",
        "subscriptionId",
        "resourceGroup",
        "location",
        "automatedCriticality",
        "tags",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as output_handle:
        writer = csv.DictWriter(output_handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row = dict(record)
            if isinstance(row.get("tags"), (dict, list)):
                row["tags"] = json.dumps(row["tags"], separators=(",", ":"))
            writer.writerow(row)

print(f"Wrote {len(records)} records to {output_path}", file=sys.stderr)
PY
