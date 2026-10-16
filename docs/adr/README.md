# Architecture decision records

One file per decision that is hard to reverse, changes a contract, or settles
something the specification or the codebook leaves open. Records are never
rewritten after they are accepted: a later record supersedes an earlier one
and both say so.

| Record                                                | Decision                                              | Status   |
| ----------------------------------------------------- | ----------------------------------------------------- | -------- |
| [0001](0001-decode-inner-packets-in-python.md)        | Decode the inner packets with our own Python decoder  | Accepted |
| [0002](0002-the-codebook-is-the-flow-contract.md)     | The feature codebook is the flow contract             | Accepted |
| [0003](0003-restore-capture-time-order.md)            | Restore capture-time order before building flows      | Accepted |
| [0004](0004-report-flags-follow-the-specification.md) | Report flags follow the specification, not the Lua    | Accepted |
| [0005](0005-gui-pages-are-views.md)                   | Desktop pages are views; the window is the controller | Accepted |

## Template

Copy this into `NNNN-short-title.md`:

```markdown
# NNNN. Title in the imperative

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD

## Context

What forces the decision: the problem, the constraints, the evidence.

## Decision

What we do, stated so that someone can check whether the code follows it.

## Consequences

What becomes easier, what becomes harder, and what must now be kept true.
```
