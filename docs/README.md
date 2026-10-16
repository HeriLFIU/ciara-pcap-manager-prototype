# Documentation

## Reading order

If you are new, read these in order:

1. **[How it works](how-it-works.md)** — the whole system in one read: what
   the captures contain, which packets are kept, how flows are built, how the
   results reach the user, and how we know they are right.
1. **[Packet anatomy](packet-anatomy.md)** — one real frame from the sample,
   byte by byte.
1. **[INT telemetry](int-telemetry.md)** — the INT and telemetry report
   headers, field by field, with references to the P4.org specifications.
1. **[Flow generation](flow-generation.md)** — flow keys, segments, every
   feature formula, the points where the codebook was interpreted, and known
   limits.

## By task

| Task                                         | Document                                                           |
| -------------------------------------------- | ------------------------------------------------------------------ |
| Use the desktop app, the CLI or offline tool | [User guide](user-guide.md)                                        |
| Look at captures in Wireshark                | [Lua dissector](lua-dissector.md)                                  |
| Change the code                              | [Developer guide](developer-guide.md)                              |
| Understand package boundaries                | [Architecture](architecture.md)                                    |
| Run every service locally                    | [Running the prototype](common_workflows/running_the_prototype.md) |
| Know why something was decided               | [Decision records](adr/README.md)                                  |
| Look up a feature definition                 | [Feature codebook](reference/feature_codebook.md)                  |
| Tooling (uv, ruff, pyright, hooks, CI)       | [Tooling](tooling.md) and `common_workflows/`                      |

## Reference material

- [`reference/feature_codebook.md`](reference/feature_codebook.md): the
  PIPELINE_V2 feature codebook. The tests read section 6 of this file and fail
  if the code's column order differs.
- [`../tools/wireshark/int_extension_fullframe_v7.lua`](../tools/wireshark/int_extension_fullframe_v7.lua):
  the Wireshark dissector the decoder is checked against.
- P4.org specifications used for the header layouts:
  [INT v1.0](https://github.com/p4lang/p4-applications/blob/master/docs/INT_v1_0.pdf)
  and
  [Telemetry Report v1.0](https://github.com/p4lang/p4-applications/blob/master/docs/telemetry_report_v1_0.pdf).
