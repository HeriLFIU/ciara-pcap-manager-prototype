# Developer guide

How to work on the prototype: set it up, find your way around, make the common
kinds of change, and prove a change is good before it is merged.

## Set up

Requires [uv](https://docs.astral.sh/uv/). No native packet-capture library is
needed: the core reads pcap and pcapng itself.

```bash
make setup          # uv sync + git hooks; or see AGENTS.md §3.4 without make
uv run ciara-pcap-inspect samples/student_sample_50000.pcap   # smoke test, no server
```

The desktop app and its tests need the Qt runtime libraries. On Debian or
Ubuntu, if `python -c "import PySide6.QtWidgets"` fails with
`libEGL.so.1: cannot open shared object file`, install them:

```bash
sudo apt install libegl1 libgl1 libxkbcommon0 libfontconfig1
```

Without them `tests/unit/test_gui_window.py` is skipped with that reason, and
everything else still runs.

## Where things are

| You want to change…                      | Look in                                                       |
| ---------------------------------------- | ------------------------------------------------------------- |
| how a frame is decoded                   | `src/ciara_pcap_manager_prototype/telemetry/decoder.py`       |
| the decoded header records               | `src/…/telemetry/layers.py`                                   |
| packet-row columns (codebook §1)         | `src/…/flows/packet.py`                                       |
| flow keys, segments, termination         | `src/…/flows/generator.py`                                    |
| a flow feature formula (codebook §3)     | `src/…/flows/segment.py`                                      |
| the `Flow` contract / CSV column order   | `src/…/domain/flows.py`                                       |
| reading pcap / pcapng                    | `src/…/pcap/reader.py`                                        |
| settings and their environment variables | `src/…/config.py`, `packages/api/…/core/config.py`            |
| HTTP routes                              | `packages/api/src/ciara_pcap_api/api/routes/`                 |
| the client workflow, formatting, CSV     | `packages/client/src/ciara_pcap_client/`                      |
| CLI commands and tables                  | `packages/cli/src/ciara_pcap_cli/`                            |
| a page of the desktop app                | `packages/gui/src/ciara_pcap_gui/pages/`                      |
| colours and widget styles                | `packages/gui/src/ciara_pcap_gui/theme.py`                    |
| test fixtures (synthetic INT frames)     | `tests/support/pcap_factory.py`, `tests/support/factories.py` |

[Architecture](architecture.md) explains the boundaries between them.

## Common changes

### Add or change a flow feature

1. Write the failing test in `tests/unit/test_flow_features.py` (test first:
   see AGENTS.md).
1. Add the field to `Flow` in `domain/flows.py`, **in codebook order**, and
   compute it in `FlowSegment.to_flow` (`flows/segment.py`).
1. Add it to `FLOW_CSV_COLUMNS` in `packages/client/…/export.py` and to a group
   in `packages/gui/…/features.py`.
1. If the codebook changes, update `docs/reference/feature_codebook.md` too.
   `tests/unit/test_export.py` fails until the codebook, the model and the
   client list agree, and `tests/unit/test_gui_models.py` fails until the
   detail panel shows the new column.
1. Regenerate the contract: `make sdk`.
1. Update [Flow generation](flow-generation.md).

### Decode another INT field

1. Add a case to `tests/unit/test_decoder.py`, building the frame with
   `tests/support/pcap_factory.py` (`Hop`, `int_header`, `tcp_report`).
1. Extend `IntHop` in `telemetry/layers.py` and `_decode_hop` in
   `telemetry/decoder.py`.
1. If the Lua dissector shows the field, add it to `TSHARK_FIELDS` in
   `scripts/check_lua_parity.py` and run `make lua-parity`.

### Add a page to the desktop app

1. Create `packages/gui/src/ciara_pcap_gui/pages/<name>.py` with a `Page`
   subclass: set `title` and `subtitle`, build widgets in `__init__`, redraw in
   `refresh()` from `self.state` (the loaded job and flows).
1. Append the class to `PAGES` in `pages/__init__.py`. The sidebar button, the
   header title and the Ctrl+N shortcut follow automatically.
1. If the page needs the backend, emit a signal and handle it in
   `main_window.py`; pages never make network calls. `HistoryPage` is the
   example.
1. Style with object names defined in `theme.py` (`Card`, `PrimaryButton`,
   `SectionTitle`, `role="muted"`…), not inline stylesheets. Colour a
   categorical value with a `Tone` from `tones.py`: a `Pill` label, a
   `PillDelegate` on a table column whose `Column` has a `tone`, or a
   breakdown bar. A new colour token needs its contrast pairs in
   `tests/unit/test_gui_window.py`.
1. Do not add descendant rules such as `QFrame#Card QLabel { … }` to the
   stylesheet: they outrank a label's own `QLabel#Name` rule and erase its
   background. Keep each `border-radius` under half the widget's height; Qt
   ignores a larger one and draws square corners.
1. Test it in `tests/unit/test_gui_window.py`.

### Change the API or a model

Run `make sdk`. It rewrites `openapi.json` and everything under
`packages/sdk` with a pinned generator version. Never edit either by hand.
`tests/unit/test_domain.py` fails if `openapi.json` is stale.

## Prove it before merging

```bash
make verify
```

runs, locally, what CI runs: every pre-commit hook on every file (ruff,
pyright strict, markdown, YAML, TOML, shell, spelling, secrets…), the full test
suite with coverage, and one pass over the benchmarks. A pull request is ready
when `make verify` passes. If you touched the decoder, also run
`make lua-parity`.

Useful narrower loops:

```bash
uv run pytest tests/unit/test_flow_features.py -n 0 --no-cov   # one file, fast
uv run pytest tests -k reorder                                 # by name
uv run ruff check --fix . && uv run ruff format .
uv run pyright
make bench                                                     # benchmarks to .reports/
```

## Working rules

These are in [AGENTS.md](../AGENTS.md) for coding agents and apply to people
too:

- **Test first.** Reproduce a bug or specify a feature as a failing test, then
  change the code.
- **Every finding becomes a check.** When a review or an incident finds a
  defect, add the test, lint rule or document line that would have caught it.
- **Do not weaken a gate to pass it.** No blanket `noqa`, lowered thresholds
  or skipped tests; fix the cause. A `noqa` names its rule and says why.
- **Generated files are regenerated, never edited**: `openapi.json`,
  `packages/sdk/`, `uv.lock`, `samples/synthetic.pcap`.
- **Verify facts against the source.** Header layouts cite the P4.org
  specifications; behaviour claims about the data cite a measurement or a
  test.
- **Record decisions.** A choice that is hard to reverse or that the codebook
  leaves open gets an [architecture decision record](adr/README.md).
