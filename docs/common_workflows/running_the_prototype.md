# Running the prototype

```bash
uv sync
```

Installs the core library, the backend, the generated SDK, the shared client,
the CLI and the desktop app into one virtual environment from one lockfile.
No packet-capture runtime (libpcap, Npcap) is needed: the core reads pcap and
pcapng files itself.

## 1. Backend

```bash
uv run ciara-pcap-api
```

Serves <http://127.0.0.1:8000>, interactive docs at `/docs`, schema at
`/api/v1/openapi.json`. Settings come from the environment or a `.env` file;
the table is in the [user guide](../user-guide.md#settings).

## 2. CLI

```bash
uv run ciara-pcap analyze samples/student_sample_50000.pcap
uv run ciara-pcap analyze x.pcap --csv flows.csv   # save every flow in codebook order
uv run ciara-pcap analyze x.pcap --json            # pipe into jq
uv run ciara-pcap analyze x.pcap --limit 0         # print every flow
uv run ciara-pcap health                           # is the backend up?
uv run ciara-pcap jobs                             # list analysis jobs
uv run ciara-pcap flows <job-id>                   # re-read a finished job
uv run ciara-pcap -v analyze x.pcap                # log SDK and HTTP activity
```

Point it elsewhere with `--api-url` or `CIARA_PCAP_API_URL`.

## 3. Desktop app

```bash
uv run ciara-pcap-gui
```

Open a capture with **Open capture…**, Ctrl+O or drag and drop. See the
[user guide](../user-guide.md#desktop-app) for a tour. Set `CIARA_PCAP_API_URL`
to pre-fill the backend address. On Windows, `launch.bat` starts the backend
and the app together.

## 4. Offline, without a backend

```bash
uv run ciara-pcap-inspect samples/student_sample_50000.pcap
uv run ciara-pcap-inspect samples/student_sample_50000.pcap --inspect 2
uv run ciara-pcap-inspect samples/student_sample_50000.pcap --csv flows.csv
```

## Regenerating the SDK

Required after any change to a route or a Pydantic model:

```bash
make sdk     # or: bash scripts/non-interactive/generate-sdk.sh
```

Rewrites `openapi.json` and everything under `packages/sdk`, then relocks the
workspace. Review the diff: an unexpected SDK change means the public contract
changed. Never hand-edit the generated package.

## Captures

| File                                | What it is                                                                                                                             |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `samples/student_sample_50000.pcap` | 50,000 frames recorded at the telemetry collector: the reference sample                                                                |
| `samples/synthetic.pcap`            | 13 hand-built frames: a TCP handshake to FIN, a SYN/RST, a UDP exchange with one report out of time order, and one non-telemetry frame |

The synthetic sample is generated from readable source:

```bash
make sample   # or: uv run python tests/support/pcap_factory.py samples/synthetic.pcap
```

A capture must contain INT telemetry reports (outer UDP to port 5900 by
default) to produce flows; frames that are not reports are counted as skipped.

## Checks

```bash
make verify                            # everything CI checks: hooks on all files, tests, benchmarks
uv run pytest tests                    # the full suite, in parallel
uv run pytest tests/integration        # the 50,000-frame sample and the worker process
make lua-parity                        # decoder vs the Wireshark Lua dissector
```

## Profiling

Extraction is the only CPU-bound stage:

```bash
make profile                                                   # Scalene web UI on the synthetic sample
uv run scalene run src/ciara_pcap_manager_prototype/pcap/profile.py --- samples/student_sample_50000.pcap
```
