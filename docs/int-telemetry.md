# INT telemetry and telemetry reports

Reference for the two header families the decoder reads. Field layouts are
taken from the P4.org Applications Working Group specifications, version 1.0:

- *In-band Network Telemetry (INT) Dataplane Specification, Version 1.0*
  (2018-04-21):
  <https://github.com/p4lang/p4-applications/blob/master/docs/INT_v1_0.pdf>
- *Telemetry Report Format Specification, Version 1.0* (2018-04-20):
  <https://github.com/p4lang/p4-applications/blob/master/docs/telemetry_report_v1_0.pdf>

Section numbers below refer to those documents.

## What INT is

In-band Network Telemetry lets switches record, inside the packets they
forward, measurements about how each packet was handled: which switch and
ports it used, when it arrived and left, how long it waited and how full the
queue was. An **INT source** adds an INT header that lists what to measure;
every INT-capable switch on the path (a **hop**) pushes its own record onto a
stack; an **INT sink** removes the data and sends it to a collector.

The captures in this project hold the sink's output: **telemetry reports**,
each carrying a copy of the observed packet's headers followed by the INT
stack.

## Telemetry report header (Report v1.0 §3.2)

A report travels in an ordinary UDP datagram (§3.1). The destination port is
deployment-specific; here it is **5900**. The 16-byte header follows the UDP
header:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver |Length |NProt| RepMdBits |  Reserved |D|Q|F|   hw_id     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Switch id                           |
|                        Sequence Number                        |
|                       Ingress Timestamp                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field             | Width | Meaning                                                                       |
| ----------------- | ----: | ----------------------------------------------------------------------------- |
| Ver               |     4 | 1 for this specification                                                      |
| Length            |     4 | header length in 4-byte words, optional metadata included (4 = 16 bytes here) |
| NProt             |     3 | what follows: 0 Ethernet, 1 IPv4, 2 IPv6 (always 0 in the sample)             |
| RepMdBits         |     6 | which optional report metadata is present (always 0 in the sample)            |
| D                 |     1 | a packet matching a drop watchlist was dropped                                |
| Q                 |     1 | congestion on a monitored queue                                               |
| F                 |     1 | report for a tracked flow; may carry embedded telemetry metadata (§3.4)       |
| hw_id             |     6 | hardware subsystem (for example a line card) inside the switch                |
| Switch id         |    32 | unique switch identifier                                                      |
| Sequence Number   |    32 | per (switch id, hw_id) report counter, to detect lost reports                 |
| Ingress Timestamp |    32 | switch-local time the packet was received, in nanoseconds                     |

Every report in the sample has F = 1 and carries an INT stack. That is
consistent with §3.4: "If the Tracked Flow Association bit is set to 0, then
there will not be any embedded telemetry metadata in the report."

§3.5 ("Parsing Considerations", Figure 5) shows the layout these captures
use: a report that embeds a flat packet carrying INT over TCP/UDP.

## INT shim header for TCP/UDP (INT v1.0 §4.6.1)

With INT over TCP/UDP, "a shim header is inserted following TCP/UDP header";
the INT metadata header and stack follow the shim. The specification allows
the INT data to come before or after TCP options, consistently within one
network; in these captures it comes right after the fixed 20-byte TCP header.

```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |   Reserved    |    Length     |    DSCP   |R R|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type**: which INT header follows (1 in the sample).
- **Length**: total length of shim + metadata header + stack, in 4-byte words.
  The stack length is therefore `(Length − 3) × 4` bytes (§4.7: "subtracting
  the total INT fixed header sizes (12 bytes)").
- **DSCP**: optionally the packet's original DSCP.

## INT metadata header (INT v1.0 §4.7)

```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver |Rep|C|E|M|      Reserved       | Hop ML  |RemainingHopCnt|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Instruction Bitmap       |           Reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   INT Metadata Stack (each hop inserts Hop ML x 4 bytes)      |
```

| Field               | Width | Meaning                                                 |
| ------------------- | ----: | ------------------------------------------------------- |
| Ver                 |     4 | 1                                                       |
| Rep                 |     2 | replication requested                                   |
| C                   |     1 | this packet is a replica                                |
| E                   |     1 | a hop could not add metadata: remaining hop count was 0 |
| M                   |     1 | a hop could not add metadata: it would exceed the MTU   |
| Hop ML              |     5 | per-hop metadata length in 4-byte words                 |
| Remaining Hop Count |     8 | how many more hops may add metadata                     |
| Instruction Bitmap  |    16 | which metadata each hop records (below)                 |

### Instruction bits and the hop record

Each hop records the requested fields **in bit order**, each in one 4-byte
word (bit 6 takes two words in v1.0):

| Bit | Field (v1.0)                                     | Decoded? |
| --: | ------------------------------------------------ | :------: |
|   0 | Switch ID                                        |   yes    |
|   1 | Ingress port ID (16 bits) + egress port ID (16)  |   yes    |
|   2 | Hop latency                                      |   yes    |
|   3 | Queue ID (8 bits) + queue occupancy (24 bits)    |   yes    |
|   4 | Ingress timestamp                                |   yes    |
|   5 | Egress timestamp                                 |   yes    |
|   6 | Level-2 ingress + egress port IDs (4 bytes each) | counted  |
|   7 | Egress port TX utilisation                       | counted  |
|  15 | Checksum complement                              |    no    |

The sample always uses `0xFC00`: bits 0–5, six words per hop, matching Hop ML
6\.

Rules from §4.7 that matter when reading the data:

- **The stack is pushed**: "the most recently added metadata appears at the
  top of the stack". Hop 1 in the decoder's output is the last switch on the
  path. The packet-level INT columns of the codebook come from hop 1.
- **All-ones means "not available"**: a switch that cannot provide a value
  writes `0xFFFFFFFF`. Every sampled hop has a hop-latency word of
  `0xFFFFFFFF`, so the hop latency is taken as egress minus ingress timestamp,
  computed modulo 2³² to survive a counter wrap. This is the Lua dissector's
  rule too.
- **Timestamps and latencies are 32-bit nanosecond values.** The counter wraps
  every 2³² ns ≈ 4.295 s. Timestamps from different switches come from
  different clocks and are not comparable with one another.

## How the decoder bounds the INT data

1. The shim and metadata header (12 bytes) must be captured, and the shim
   length must be at least 3 words; otherwise the packet has no INT.
1. Stack length = `min((shim length − 3) × 4, bytes captured after the metadata header)`.
1. The stack is split into `stack length ÷ (Hop ML × 4)` whole hops.
1. A hop whose instruction bits need more words than Hop ML allows is invalid:
   it is dropped and decoding stops there.

## Where this project differs from the specifications

Both differences come from the team's Lua dissector, which the prototype
matches field for field; neither changes any value in the sample.

- **Instruction bits 8–15 are not read.** Only the first instruction byte is
  decoded. In the sample the second byte is always zero.
- **Bit 6 is counted as one word.** The Lua names it "Queue ID + Congestion
  Status" and consumes 4 bytes; v1.0 defines it as level-2 port IDs taking 8
  bytes. Because bit 6 comes after every decoded field, this can only affect
  whether a hop is rejected as too long for Hop ML, never a decoded value.
  Bit 6 is never set in the sample.

One difference goes the other way: for the report flags, the prototype follows
the specification rather than the Lua. See
[Lua dissector](lua-dissector.md#known-differences-from-the-specifications).
