# Makefile Shortcuts

## 🛠️ Local Developer Commands

Memorizing commands is very difficult.
Here you have a lot of common workflows/commands made easy and accessible to use.

<!-- Deliberately a list, not a table: several rows are conditional on the
     answers given to the template, and a Markdown table's column padding
     depends on its widest row. A list stays `mdformat`-clean for every
     combination. -->

- `make setup` — Hydrates the uv environment and installs git hooks.
- `make lint` — Runs the full suite of prek hooks across all local files.
- `make format` — Performs a lightning-fast auto-format using Ruff.
- `make typecheck` — Executes Pyright in isolated strict mode.
- `make test` — Runs the Pytest suite locally.
- `make profile` — Launches the local Scalene profiler and opens the live web GUI.
- `make lock` — Resolves dependencies and updates the `uv.lock` file.
- `make update-hooks` — Updates every prek hook to its latest release.
- `make clean` — Wipes caches and test artifacts.

## 📊 Expensive Analysis

These are deliberately excluded from `make lint` and the commit hooks. Run them
when you need evidence, not on every change. See
[Reading CI & Profiler Feedback](ci_feedback.md).

- `make report` — Full suite with coverage and JUnit XML, written to `.reports/`.
- `make bench` — Micro-benchmarks only, serial, recorded as `.reports/benchmark.json`.
- `make analyze` — `report` and `bench` together, the full local evidence pass.
