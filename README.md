# CIARA PCAP Prototype

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Tooling](https://img.shields.io/badge/tooling-uv%20%7C%20ruff%20%7C%20pyright-orange)

Builds bidirectional flows from the **inner packets** of In-band Network
Telemetry (INT) captures. Every frame recorded at the telemetry collector is a
switch-to-collector report (the outer "cover" packet, UDP port 5900) wrapping
the user packet the switch observed plus the switch's INT measurements. The
prototype decodes each report, discards the envelope, and turns the inner
packets into flows with the 99 features of the PIPELINE_V2 feature codebook.

![Desktop app: flows](docs/images/gui-flows.png)

## Quick start

Requires [uv](https://docs.astral.sh/uv/). No libpcap or Npcap is needed.

```bash
make setup                     # uv sync + git hooks (once per clone)

# Offline, no server:
uv run ciara-pcap-inspect samples/student_sample_50000.pcap
uv run ciara-pcap-inspect samples/student_sample_50000.pcap --inspect 1
uv run ciara-pcap-inspect samples/student_sample_50000.pcap --csv flows.csv

# Backend + clients:
uv run ciara-pcap-api                                   # http://127.0.0.1:8000, docs at /docs
uv run ciara-pcap analyze samples/student_sample_50000.pcap
uv run ciara-pcap-gui                                   # desktop app
```

On the bundled 50,000-frame sample: 50,000 inner packets decoded, 15,458
flows (10,383 TCP, 5,075 UDP). The decoder agrees with the team's Wireshark
Lua dissector on 1,100,000 out of 1,100,000 compared fields
(`make lua-parity`).

## Documentation

Start with **[How it works](docs/how-it-works.md)**; the
[documentation index](docs/README.md) lists everything.

| Document                                   | For                                                              |
| ------------------------------------------ | ---------------------------------------------------------------- |
| [How it works](docs/how-it-works.md)       | the whole system in one read: packets, layers, flows, interfaces |
| [Packet anatomy](docs/packet-anatomy.md)   | one real frame, byte by byte                                     |
| [INT telemetry](docs/int-telemetry.md)     | INT and telemetry report headers, from the P4.org specifications |
| [Lua dissector](docs/lua-dissector.md)     | using the Wireshark dissector and how it maps to the Python code |
| [Flow generation](docs/flow-generation.md) | keys, segments, every feature formula, interpretations, limits   |
| [User guide](docs/user-guide.md)           | the desktop app, the CLI, the offline tool, settings             |
| [Developer guide](docs/developer-guide.md) | making changes and proving them                                  |
| [Architecture](docs/architecture.md)       | packages, boundaries, design reasons                             |
| [Decision records](docs/adr/README.md)     | why the big choices were made                                    |

## How it fits together

| Path              | Contents                                                                                        |
| ----------------- | ----------------------------------------------------------------------------------------------- |
| `src/`            | Core: pcap reader, INT decoder, flow generator, domain models. No web, GUI or native libraries. |
| `packages/api`    | FastAPI backend: upload returns `202` with a job id; parsing runs in a worker process           |
| `packages/sdk`    | **Generated** typed HTTP client — never hand-edit                                               |
| `packages/client` | The upload-then-poll workflow, formatting and CSV export shared by both clients                 |
| `packages/cli`    | `ciara-pcap` command line                                                                       |
| `packages/gui`    | PySide6 desktop app                                                                             |
| `tools/wireshark` | The team's Lua dissector                                                                        |
| `tests/`          | `unit/` and `integration/`; synthetic INT frames are built from readable source                 |

## Development

```bash
make verify      # the local CI gate: every hook on every file, all tests, benchmarks
make test        # tests only
make lua-parity  # decoder vs Wireshark Lua dissector (tshark, podman or docker)
make sdk         # regenerate openapi.json and the SDK after an API change
make help        # everything else
```

Commits follow [Conventional Commits](docs/concepts/conventional_commits.md);
the hooks installed by `make setup` enforce that. [AGENTS.md](AGENTS.md) is the
operating manual for AI coding agents.

This project was generated from a Copier template and stays linked to it via
`.copier-answers.yml` — never edit that file by hand. See the
[Copier workflow](docs/common_workflows/copier_template.md).

## License

No license file is distributed with this project.
