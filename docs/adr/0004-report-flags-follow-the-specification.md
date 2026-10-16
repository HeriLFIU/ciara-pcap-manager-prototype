# 0004. Report flags follow the specification, not the Lua

- Status: Accepted
- Date: 2026-10-15

## Context

P4.org Telemetry Report Format v1.0 §3.2 lays out the report's first word as
`Ver(4) Length(4) NProt(3) RepMdBits(6) Reserved(6) D Q F hw_id(6)`. The Lua
dissector reads D, Q and F one bit to the right of those positions and
RepMdBits from bits 12–17. On every sampled report the flag byte is `0x40`:
the Lua calls it the Queue bit; the specification reads it as F (tracked
flow), which matches the reports carrying INT (§3.4).

## Decision

The decoder reads the report flags and RepMdBits at the specification's bit
positions. Everything else follows the Lua. The Lua file is kept as delivered,
and `docs/lua-dissector.md` describes the difference and the fix.

## Consequences

- `ciara-pcap-inspect` shows `flow=1` where Wireshark with the Lua shows
  *Queue Bit: True* for the same frame.
- The flags feed no flow feature and are not part of the parity check, so the
  flows are unaffected.
