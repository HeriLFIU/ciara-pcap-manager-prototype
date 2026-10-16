# Packet anatomy: one frame, byte by byte

This walks through the first frame of `samples/student_sample_50000.pcap`.
Every value below is what the decoder and the Wireshark Lua dissector both
read from it. Reproduce the decode with:

```bash
uv run ciara-pcap-inspect samples/student_sample_50000.pcap --inspect 1
```

```text
frame 0  t=1789396500.041360617  357 bytes captured
  OUTER  94.8.56.51:6002 -> 10.236.153.185:5900 UDP vlan 21
  REPORT v1 switch 24 seq 2908611534 ingress_ts 3679456570 drop=0 queue=0 flow=1
  INNER  203.49.118.225:443 -> 187.84.112.102:14598 TCP vlan 501 ip_len 1326 (captured 277)
         tcp data offset 5 flags 0x18
  INT    shim type 1 length 9 words dscp 0
         md v1 hop_ml 6 words remaining 9 instructions 0xfc (switch id, ingress+egress port, hop latency, queue id+occupancy, ingress timestamp, egress timestamp)
         stack 24 of 24 declared bytes, 1 hop(s)
      hop 1
        switch id           24
        ingress port        24
        egress port         18
        queue id            0
        queue occupancy     21
        ingress timestamp   3679454501
        egress timestamp    3679456041
        hop latency (wire)  4294967295
        hop latency (ns)    1540
```

## The bytes

Offsets are from the first byte of the frame. The frame is 357 bytes long;
the meaningful part ends at byte 155 and the rest is zero padding.

```text
offset  bytes                                              layer
     0  5a72d5def69e 765d7e174cf1                          outer Ethernet: destination, source MAC
    12  8100 0015                                          802.1Q tag: VLAN 21
    16  0800                                               EtherType: IPv4
    18  45 00 014f 0000 4000 40 11 febd                    outer IPv4 header (proto 17 = UDP)
    30  5e083833 0aec99b9                                  94.8.56.51 -> 10.236.153.185
    38  1772 170c 013b 0000                                outer UDP: 6002 -> 5900, length 315
    46  14 00 00 40                                        report: Ver 1, Length 4 words, NProt 0, flags
    50  00000018                                           report: switch id 24
    54  ad5de3ce                                           report: sequence number 2908611534
    58  db500d3a                                           report: ingress timestamp 3679456570 ns
    62  5a94d5852798 ca285288e9e0                          inner Ethernet: destination, source MAC
    74  8100 01f5                                          802.1Q tag: VLAN 501
    78  0800                                               EtherType: IPv4
    80  45 5c 052e 15af 4000 3e 06 b3f1                    inner IPv4 header (total length 1326, proto 6 = TCP)
    92  cb3176e1 bb547066                                  203.49.118.225 -> 187.84.112.102
   100  01bb 3906 ade42d94 de5489a6 50 18 0119 0000 0000   inner TCP: 443 -> 14598, offset 5, flags PSH+ACK
   120  01 00 09 00                                        INT shim: type 1, length 9 words, DSCP 0
   124  10 00 06 09 fc00 0000                              INT metadata header
   132  00000018                                           hop 1: switch id 24
   136  0018 0012                                          hop 1: ingress port 24, egress port 18
   140  ffffffff                                           hop 1: hop latency = "not available"
   144  00 000015                                          hop 1: queue id 0, queue occupancy 21
   148  db500525                                           hop 1: ingress timestamp 3679454501 ns
   152  db500b29                                           hop 1: egress timestamp 3679456041 ns
   156  00 … 00                                            201 bytes of zero padding to the end of the frame
```

## Reading it layer by layer

### Outer packet: the envelope

Bytes 0–45 are an ordinary Ethernet + VLAN + IPv4 + UDP packet from the
reporting switch (`94.8.56.51`, source port 6002) to the collector
(`10.236.153.185`, port 5900). Port 5900 is what marks the frame as a
telemetry report.

Its IPv4 Total Length is 335, which would end the packet at byte 353, but 357
bytes were captured. This mismatch is present in all 50,000 frames, and it is
why the decoder never uses outer length fields to decide where data ends.

### Telemetry report header

Bytes 46–61. The layout is the P4.org Telemetry Report Format v1.0:

| Field             | Bits | Value in this frame | Meaning                                             |
| ----------------- | ---: | ------------------- | --------------------------------------------------- |
| Ver               |    4 | 1                   | report format version 1                             |
| Length            |    4 | 4                   | header length in 4-byte words: 16 bytes             |
| NProt             |    3 | 0                   | an Ethernet frame follows                           |
| RepMdBits         |    6 | 0                   | no optional report metadata                         |
| Reserved          |    6 | 0                   |                                                     |
| D, Q, F           |    3 | 0, 0, 1             | F = report for a tracked flow (INT may be embedded) |
| hw_id             |    6 | 0                   | hardware subsystem within the switch                |
| Switch id         |   32 | 24                  | which switch generated the report                   |
| Sequence number   |   32 | 2908611534          | per-switch report counter (detects lost reports)    |
| Ingress timestamp |   32 | 3679456570          | switch-local time, nanoseconds                      |

### Inner packet: the user traffic

Bytes 62 onwards are the packet the switch observed: Ethernet, VLAN 501, IPv4
from `203.49.118.225` to `187.84.112.102`, then TCP from port 443 to port 14598
with PSH and ACK set. This is what becomes a flow.

Two details make this layer unusual:

- **The packet is truncated.** Its IPv4 Total Length says 1,326 bytes, but only
  277 bytes from the IPv4 header to the end of the frame were captured, and
  most of those are INT data and padding rather than payload. The prototype
  records this as `inner_ip_truncated_vs_declared` and counts packet sizes
  with the declared length (the codebook's `inner_ip_len`), which is the size
  the packet had on the wire.
- **Only the first 20 TCP bytes are present.** In this frame the data offset
  is 5 (20 bytes) anyway, but in 18,547 sampled TCP packets it is 8 (32
  bytes) while the INT shim still starts right after byte 20 of the TCP
  header. The collector keeps the fixed TCP header and places INT immediately
  after it.

### INT: the switch's measurements

Bytes 120–155:

- **Shim** (4 bytes): type 1, length **9 words** = 36 bytes covering the shim
  (4), the metadata header (8) and the stack (24).
- **Metadata header** (8 bytes): version 1, **Hop ML 6** (each hop's record is
  6 words = 24 bytes), remaining hop count 9, instruction bitmap `0xFC00`:
  bits 0–5 are set, so each hop records switch id, ports, hop latency,
  queue id + occupancy, ingress timestamp and egress timestamp, in that order.
- **Stack** (24 bytes): one hop. The hop latency word is `0xFFFFFFFF`, which
  INT v1.0 reserves for "value not available". Because both timestamps are
  present, the decoder (like the Lua) uses
  `egress − ingress = 3679456041 − 3679454501 = 1540 ns` as the hop latency.

Every one of the 50,000 sampled frames has this same INT layout: shim length
9, Hop ML 6, instructions `0xFC`, exactly one hop.

## What varies across the sample

| Property                       | Observed in `student_sample_50000.pcap`                                             |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| Frame length                   | 190 distinct values, most commonly 157 bytes (29,218 frames) and 357 (15,565)       |
| Report sources                 | 3 (see [How it works](how-it-works.md#why-the-old-version-showed-only-three-flows)) |
| Report switch ids              | 12, 24 and 262146, one per outer source                                             |
| First-hop switch ids           | 23, 24 and 262146, one per outer source                                             |
| Inner protocol                 | TCP 33,180 packets, UDP 16,820                                                      |
| Hop latency (egress − ingress) | 1,328 to 2,276 ns, median 1,391 ns                                                  |
| Queue occupancy                | 2 to 114, median 12                                                                 |
