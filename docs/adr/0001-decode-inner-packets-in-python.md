# 0001. Decode the inner packets with our own Python decoder

- Status: Accepted
- Date: 2026-10-15

## Context

The captures are recordings of a telemetry collector's link. Each frame is a
switch-to-collector UDP datagram (port 5900) carrying a telemetry report, the
observed user packet, and its INT metadata. The first prototype used NFStream,
a general flow meter that keys flows on the outermost headers. On the
50,000-frame sample it produced three flows, one per reporting switch, and no
flow of the user traffic.

The inner packet cannot be found by a generic tool: the IPv4 and UDP length
fields are stale (the collector truncates the packet and appends INT), and the
INT shim sits after the first 20 TCP bytes regardless of the TCP data offset.
The team's Wireshark Lua dissector encodes these rules. NFStream also required
a native libpcap/Npcap runtime and a Windows DLL workaround.

## Decision

Replace NFStream with a pure-Python pipeline in the core package: a pcap and
pcapng reader, a decoder that mirrors the Lua dissector's walk over the full
captured frame, and a flow generator over the inner packets only. The Lua
dissector is the reference: `scripts/non-interactive/check-lua-parity.sh`
compares the two field by field.

## Consequences

- The sample yields 15,458 flows of the user traffic; the parity check reports
  0 differences over 1,100,000 fields.
- No native capture library: installation is `uv sync` on every platform, and
  the Npcap DLL workaround (`pcap/compat.py`, `pcap/_bootstrap/`) is gone.
- nDPI application labels (`application_name` and similar) are no longer
  produced; they were not part of the feature codebook.
- Parsing is CPU-bound Python, about 1.6 s for the 50,000-frame sample on the
  development machine; it still runs in a worker process per capture.
- A change to the capture format must be made in both the Lua and the decoder,
  and the parity script must pass.
