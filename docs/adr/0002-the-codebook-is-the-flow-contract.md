# 0002. The feature codebook is the flow contract

- Status: Accepted
- Date: 2026-10-15

## Context

The team describes its flow features in `PIPELINE_V2_FEATURE_CODEBOOK.md`,
including an exact export column order (section 6). Downstream work (models,
labels) consumes CSV in that layout.

## Decision

`Flow` in `domain/flows.py` declares exactly the codebook's 99 generator
columns, under the codebook's names and in its export order, and the CSV
writers emit that order. The codebook is kept in the repository at
`docs/reference/feature_codebook.md`. Where the codebook leaves a choice open,
the choice is listed in `docs/flow-generation.md` (section 5).

## Consequences

- `tests/unit/test_export.py` parses the codebook file and fails unless the
  model, the client column list and section 6 agree; the GUI test fails unless
  every column has a place in the detail panel.
- Three column names contain capitals (`total_Bps`, `fwd_Bps`, `bwd_Bps`); they
  carry a documented `noqa` for the naming rule.
- The codebook's enricher (section 4) and labels (section 5) are not
  implemented; see `docs/flow-generation.md`.
