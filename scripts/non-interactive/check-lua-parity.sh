#!/usr/bin/env bash
# Check that the Python decoder and the Wireshark Lua dissector agree.
#
# Runs tshark with tools/wireshark/int_extension_fullframe_v7.lua over a
# capture, then compares every decoded field with the Python decoder
# (scripts/check_lua_parity.py). Uses a local tshark when there is one;
# otherwise runs tshark from Alpine Linux in podman or docker.
#
#   bash scripts/non-interactive/check-lua-parity.sh                 # the bundled sample
#   bash scripts/non-interactive/check-lua-parity.sh path/to/capture.pcap
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

capture="${1:-samples/student_sample_50000.pcap}"
lua="tools/wireshark/int_extension_fullframe_v7.lua"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp "$capture" "$work/capture.pcap"
cp "$lua" "$work/dissector.lua"

fields=()
while IFS= read -r field; do
    fields+=(-e "$field")
done < <(uv run python scripts/check_lua_parity.py --fields)

tshark_args=(-X lua_script:/w/dissector.lua -r /w/capture.pcap -T fields
    -E separator=/t -E occurrence=a -E aggregator=';' "${fields[@]}")

if command -v tshark >/dev/null 2>&1; then
    echo "==> Running the local tshark"
    local_args=("${tshark_args[@]}")
    local_args[1]="lua_script:$work/dissector.lua"
    local_args[3]="$work/capture.pcap"
    tshark "${local_args[@]}" >"$work/fields.tsv"
else
    engine="$(command -v podman || command -v docker || true)"
    if [ -z "$engine" ]; then
        echo "error: needs tshark, podman or docker on PATH" >&2
        exit 2
    fi
    echo "==> Running tshark in alpine:3.20 with $(basename "$engine")"
    "$engine" run --rm -v "$work":/w:Z docker.io/library/alpine:3.20 \
        sh -c "apk add --no-cache tshark >/dev/null 2>&1 && tshark $(printf '%q ' "${tshark_args[@]}") > /w/fields.tsv"
fi

echo "==> Comparing with the Python decoder"
uv run python scripts/check_lua_parity.py "$capture" "$work/fields.tsv"
