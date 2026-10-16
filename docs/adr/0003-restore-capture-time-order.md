# 0003. Restore capture-time order before building flows

- Status: Accepted
- Date: 2026-10-15

## Context

The sample interleaves three report streams. Each is in time order, but they
lag one another by up to 115 ms, so 22,220 of 50,000 frames are read after a
frame with a later timestamp. Flow orientation (the first packet), duration
and the codebook's wrap-aware INT inter-arrival depend on order: in file
order, 146 INT inter-arrival values wrap from a small negative difference to
nearly 2^32 ns.

Sorting the whole capture would need memory proportional to its size.

## Decision

Insert a bounded reorder buffer between the packet rows and the flow
generator. It holds packets for a window of capture time (default 1 s,
`CIARA_PCAP_REORDER_WINDOW_SECONDS`, 0 disables it) and releases them in
timestamp order, breaking ties by file position. Packets read out of order and
packets that lagged beyond the window are counted in the decode report.

## Consequences

- On the sample, wrapped INT inter-arrival values drop from 146 to 8; the
  remaining 8 compare timestamps from two different switches, which reordering
  cannot fix (documented in `docs/flow-generation.md`).
- Memory grows with the packets that arrive within one window.
- A capture whose streams lag by more than the window shows a non-zero
  `packets_late`, which tells the user to raise the window.
