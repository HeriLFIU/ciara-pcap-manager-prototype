# Pull request

## What and why

<!-- One paragraph: the change and the reason for it. Link the issue. -->

## How it was verified

<!-- Paste the commands you ran and their real results. -->

- [ ] `make verify` passes locally (hooks on every file, full suite, benchmarks)
- [ ] `make lua-parity` passes, if the decoder or the capture format changed
- [ ] New behaviour has a test that failed before the change
- [ ] `make sdk` was run, if a route or a model changed
- [ ] Docs updated (`docs/`), including `docs/flow-generation.md` for any feature or interpretation change
- [ ] Skipped hooks or checks are named here, with the reason
