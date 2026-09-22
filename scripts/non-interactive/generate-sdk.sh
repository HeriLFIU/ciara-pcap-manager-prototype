#!/usr/bin/env bash
# Regenerate the shared Python SDK from the backend's OpenAPI schema.
#
# The schema is dumped straight from the FastAPI application, so no server has
# to be running and the result is identical on a laptop and in CI. Two
# documents come out of the export:
#
#   openapi.json        the published contract, committed to the repository
#   <temp>/openapi.json the same contract with the binary-payload shim that
#                       openapi-python-client needs (see ciara_pcap_api.openapi)
#
# Everything under packages/sdk is overwritten. Never hand-edit it.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

config="scripts/non-interactive/sdk-generator.yaml"
output="packages/sdk"
codegen_schema="$(mktemp -d)/openapi.json"
trap 'rm -rf "$(dirname "$codegen_schema")"' EXIT

echo "==> Exporting the published contract to openapi.json"
uv run ciara-pcap-openapi --output openapi.json

echo "==> Exporting the code-generation contract"
uv run ciara-pcap-openapi --output "$codegen_schema" --for-codegen

echo "==> Regenerating $output"
rm -rf "$output"
uv tool run --from openapi-python-client openapi-python-client generate \
    --path "$codegen_schema" \
    --meta uv \
    --output-path "$output" \
    --config "$config" \
    --overwrite

# The generator leaves its own ruff cache behind.
rm -rf "$output/.ruff_cache"

echo "==> Relocking the workspace"
uv lock

echo "==> Done. Review the diff under $output before committing."
