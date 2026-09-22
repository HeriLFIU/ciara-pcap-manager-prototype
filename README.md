# CIARA PCAP Prototype

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Tooling](https://img.shields.io/badge/tooling-uv%20%7C%20ruff%20%7C%20pyright-orange)

Extracts bidirectional flow metadata from offline packet captures. A FastAPI
backend parses captures with NFStream; a Typer CLI and a PySide6 desktop client
drive it through a generated SDK.

## Setup

Requires [uv](https://docs.astral.sh/uv/), and a `libpcap` runtime for
NFStream — [Npcap](https://npcap.com/#download) on Windows, `libpcap` on Linux,
already present on macOS.

```bash
uv sync          # one lockfile, one .venv, every package editable
make setup       # the above, plus git hooks (run once per clone)
```

## Use it

```bash
uv run ciara-pcap-api                          # backend on :8000, docs at /docs
uv run ciara-pcap analyze samples/synthetic.pcap
uv run ciara-pcap-gui                          # desktop client
```

On Windows, `launch.bat` starts the backend and the GUI together and reaps both
on exit.

```text
synthetic.pcap   succeeded
Flows             2
Packets           10
Bytes             667 B
Top applications  DNS (1), HTTP (1)

                                 Flows (2 of 2)
 #  Source           Destination        Proto  Application  Pkts  Bytes  Server name
 0  10.0.0.1:5001    93.184.216.34:80   TCP    HTTP            8  509 B  example.com
 1  10.0.0.1:40000   8.8.8.8:53         UDP    DNS             2  158 B  example.com
```

Full command reference, configuration and SDK regeneration:
**[docs/common_workflows/running_the_prototype.md](docs/common_workflows/running_the_prototype.md)**.

## How it fits together

Uploading a capture returns `202 Accepted` with a job id. NFStream parses it in
an isolated, time-limited worker process while clients poll the job and page
through the flows. Neither client hand-writes an HTTP request: both go through
`ciara-pcap-sdk`, generated from the backend's own OpenAPI 3.1 schema, so a
contract change breaks them at type-check time instead of in production.

| Path              | Contents                                                                   |
| ----------------- | -------------------------------------------------------------------------- |
| `src/`            | Domain models, NFStream pipeline, job abstractions. No web or GUI imports. |
| `packages/api`    | FastAPI application                                                        |
| `packages/sdk`    | **Generated** typed HTTP client — never hand-edit                          |
| `packages/client` | The upload-then-poll workflow shared by both clients                       |
| `packages/cli`    | Typer command line interface                                               |
| `packages/gui`    | PySide6 desktop client                                                     |
| `tests/`          | `unit/` runs anywhere; `integration/` parses real captures                 |

**[docs/architecture.md](docs/architecture.md)** has the system diagram, a
file-by-file breakdown, and the reasoning behind each boundary.

## Development

```bash
make test        # unit suite, parallel
make lint        # ruff, pyright, codespell, shellcheck via prek
make format      # ruff check --fix and ruff format
make analyze     # coverage and benchmarks into .reports/
```

`make help` lists every target. Commits follow
[Conventional Commits](docs/concepts/conventional_commits.md); the hooks
installed by `make setup` enforce that, and Release Please cuts releases from it.

After changing a route or a Pydantic model, regenerate the SDK:

```bash
bash scripts/non-interactive/generate-sdk.sh
```

Review the diff. An unexpected change under `packages/sdk` means you changed
the public contract.

## Documentation

- [Architecture](docs/architecture.md) — diagram, layout, design decisions
- [Running the prototype](docs/common_workflows/running_the_prototype.md) — every command and setting
- [AGENTS.md](AGENTS.md) — operating manual for AI coding agents
- [Tooling](docs/tooling.md) — what each tool in the pipeline is for

Workflows: [uv](docs/common_workflows/uv_package_manager.md) ·
[ruff](docs/common_workflows/ruff_linting_formatting.md) ·
[pytest](docs/common_workflows/pytest_unit_testing.md) ·
[pyright](docs/common_workflows/pyright_typechecking.md) ·
[prek hooks](docs/common_workflows/prek_quality_checks.md) ·
[commitizen](docs/common_workflows/commit_authoring_commitizen.md) ·
[Release Please](docs/common_workflows/release_please.md) ·
[CI lifecycle](docs/common_workflows/ci_lifecycle.md) ·
[CI feedback](docs/common_workflows/ci_feedback.md) ·
[Makefile](docs/common_workflows/makefile_shortcuts.md) ·
[Scalene](docs/common_workflows/scalene_profiling.md) ·
[Copier template](docs/common_workflows/copier_template.md)

This project was generated from a Copier template and stays linked to it via
`.copier-answers.yml` — never edit that file by hand. `copier update` pulls in
later template improvements; see the
[Copier workflow](docs/common_workflows/copier_template.md).

## License

No license file is distributed with this project.
