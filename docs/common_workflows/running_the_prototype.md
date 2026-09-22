# Running the prototype

```bash
uv sync
```

Installs the core library, the backend, the generated SDK, the shared client,
the CLI and the GUI into one virtual environment from one lockfile.

## Prerequisite: a libpcap runtime

| Platform | Install                                          |
| -------- | ------------------------------------------------ |
| Windows  | [Npcap](https://npcap.com/#download)             |
| macOS    | Already present                                  |
| Linux    | `apt install libpcap0.8` / `dnf install libpcap` |

Verify:

```bash
uv run python -c "from ciara_pcap_manager_prototype.pcap.compat import ensure_capture_backend as e; e(); import nfstream; print('capture backend OK')"
```

On Windows, a machine that once had WinPcap carries a stale `wpcap.dll` in
`System32` that shadows Npcap. The project works around it automatically; see
[the architecture notes](../architecture.md#the-windows-packet-capture-runtime)
for the mechanism and the permanent fix.

## 1. Backend

```bash
uv run ciara-pcap-api
```

Serves <http://127.0.0.1:8000>, docs at `/docs`, schema at
`/api/v1/openapi.json`.

Use `ciara-pcap-api` or `python -m ciara_pcap_api`, **not** `uvicorn` directly.
Those entry points prepare the packet-capture runtime before any worker process
is spawned; `uvicorn` on its own does not.

Configuration comes from the environment or a `.env` file:

| Variable                                | Default          | Meaning                                         |
| --------------------------------------- | ---------------- | ----------------------------------------------- |
| `CIARA_PCAP_HOST` / `_PORT`             | `127.0.0.1:8000` | Bind address                                    |
| `CIARA_PCAP_STORAGE_DIR`                | `.data/captures` | Where uploads are written                       |
| `CIARA_PCAP_MAX_UPLOAD_BYTES`           | 2 GiB            | Upload size limit                               |
| `CIARA_PCAP_EXTRACTION_WORKERS`         | `2`              | Concurrent extractions                          |
| `CIARA_PCAP_EXTRACTION_TIMEOUT_SECONDS` | `300`            | Kill a parse that overruns                      |
| `CIARA_PCAP_N_DISSECTIONS`              | `20`             | Packets per flow given to nDPI; `0` disables it |
| `CIARA_PCAP_MAX_FLOWS_PER_CAPTURE`      | `0`              | Flow cap per capture; `0` means no limit        |
| `CIARA_PCAP_NPCAP_DIR`                  | discovered       | Override the Npcap location                     |

## 2. CLI

```bash
uv run ciara-pcap analyze samples/synthetic.pcap
uv run ciara-pcap health                    # is the backend up?
uv run ciara-pcap jobs                      # list analysis jobs
uv run ciara-pcap flows <job-id>            # re-read a finished job
uv run ciara-pcap analyze x.pcap --json     # pipe into jq
uv run ciara-pcap analyze x.pcap --limit 0  # print every flow
uv run ciara-pcap -v analyze x.pcap         # log SDK and HTTP activity
```

Point it elsewhere with `--api-url` or `CIARA_PCAP_API_URL`.

## 3. Desktop client

```bash
uv run ciara-pcap-gui
```

**File → Open capture…**, pick a `.pcap`, and the flows appear in a sortable,
filterable table. The window stays responsive throughout: the upload, the
polling and the paging are coroutines on the Qt event loop via `qasync`.

Set `CIARA_PCAP_API_URL` to pre-fill the backend address, or edit it in the
toolbar. On Windows, `launch.bat` starts the backend and the GUI together.

## Regenerating the SDK

Required after any change to a route or a Pydantic model:

```bash
bash scripts/non-interactive/generate-sdk.sh
```

Rewrites `openapi.json` and everything under `packages/sdk`, then relocks the
workspace. Review the diff — an unexpected SDK change means the public contract
changed. Never hand-edit the generated package.

## Test captures

`samples/synthetic.pcap` is generated, and the generator is readable source:

```bash
uv run python tests/support/pcap_factory.py samples/synthetic.pcap
```

Real captures work too: anything `tcpdump -w` or Wireshark produces, in classic
libpcap or pcapng format.

## Checks

```bash
uv run pytest tests                   # unit suite, parallel
uv run pytest tests/integration -n 0  # the NFStream tests, serially
uv run ruff check . && uv run ruff format --check .
uv run pyright
```

The integration tests need `-n 0`. NFStream starts its own `multiprocessing`
workers, and inside an xdist worker those inherit the execnet stdio channel that
worker uses to talk to the controller, which then loses the node
(`[gw0] node down: Not properly terminated`). The failure is in the harness, not
the code — the same tests pass consistently with `-n 0`, so
`tests/integration/conftest.py` skips them under xdist rather than shipping a
flaky suite. Run it as a separate CI job.

Tests marked `capture_backend` also skip themselves when no libpcap runtime is
present, so a machine without Npcap still gets a green suite.

## Profiling

Extraction is the only CPU-bound stage:

```bash
make profile                              # Scalene web UI
make profile PCAP=path/to/big.pcap
make profile-export                       # JSON into .reports/
```
