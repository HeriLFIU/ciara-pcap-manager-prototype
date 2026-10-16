# The Wireshark Lua dissector

`tools/wireshark/int_extension_fullframe_v7.lua` teaches Wireshark (and
tshark) to decode the telemetry report header, the inner packet and the INT
metadata in these captures. It is the reference the Python decoder was built
to match: the two agree on every compared field of every frame of the sample
(see [Checking parity](#checking-parity)).

## Using it

**Wireshark, one session:**

```bash
wireshark -X lua_script:tools/wireshark/int_extension_fullframe_v7.lua samples/student_sample_50000.pcap
```

**Wireshark, permanently:** open *Help → About Wireshark → Folders*, note the
*Personal Lua Plugins* path, copy the `.lua` file there and restart Wireshark
(or use *Analyze → Reload Lua Plugins*).

**tshark** (for scripts):

```bash
tshark -X lua_script:tools/wireshark/int_extension_fullframe_v7.lua \
    -r samples/student_sample_50000.pcap -c 3 -V
```

Once loaded, the packet tree shows *Telemetry Header*, the inner Ethernet/IP
and TCP/UDP layers, *INT Shim*, *INT Metadata* and one *INT Metadata Stack
(Hop N)* item per hop, and the Protocol column reads `INT`. The fields can be
used in display filters, for example:

```text
int_stack.int_hop_latency > 2000
telemetry.f_report_header.f_switch_id == 0x18
int_metadata.int_metadata_header.int_ml == 6
```

## How it works

The script defines six protocols (`telemetry`, `mod`, `switch_local`,
`int_shim`, `int_metadata`, `int_stack`) and their fields, and registers one
function, the telemetry dissector, as a **postdissector**.

### Why a postdissector

A dissector registered on UDP port 5900 would receive only the UDP payload as
Wireshark bounds it, which follows the outer IPv4 and UDP length fields. In
these captures those fields are stale, so captured bytes at the end of the
frame would be hidden (Wireshark shows them as an Ethernet trailer). A
postdissector receives the **complete captured frame**, so every byte stays
available. The script's own comments explain this choice, and the Python
decoder makes the same choice by always working on the full frame.

### The walk, step by step

`p_telemetryproto.dissector` runs on every frame and returns quietly at the
first check that fails, so non-telemetry frames are left alone:

1. Outer Ethernet, then any VLAN tags (`0x8100`, `0x88A8`, `0x9100`); the
   EtherType must be IPv4.
1. Outer IPv4: version 4, IHL at least 5; the protocol must be UDP. IHL is
   used to find the UDP header; Total Length is ignored.
1. Outer UDP: the destination port must be 5900. The UDP Length is ignored.
1. Telemetry report header: 16 bytes at a fixed offset after the UDP header.
1. Inner Ethernet and VLAN tags; inner IPv4 (IHL honoured, Total Length
   ignored); the protocol must be TCP or UDP.
1. INT starts 20 bytes after the TCP header start, or 8 bytes after the UDP
   header start. The TCP data offset is not used.
1. The shim length byte must be at least 3; the inner Ethernet frame is handed
   to Wireshark's own `eth_withoutfcs` dissector for display, and every byte
   from the INT start to the end of the frame is handed to
   `p_intshimproto.dissector`.

`p_intshimproto.dissector` then decodes the shim and the metadata header,
computes the stack length `(shim length − 3) × 4` capped at the bytes
captured, and walks the stack one Hop ML-sized hop at a time. Inside each hop
it reads the fields whose instruction bits are set, in bit order, checking each
against the hop's length. If both timestamps are present it shows
`egress − ingress` (with 32-bit wraparound) as the hop latency; otherwise the
on-wire value. A hop that needs more bytes than Hop ML allows stops the walk.

`heur_int_shim` is defined but never registered; the script keeps it from an
earlier version.

## Lua and Python, side by side

| Step                        | Lua (`int_extension_fullframe_v7.lua`)        | Python (`src/ciara_pcap_manager_prototype/telemetry/decoder.py`) |
| --------------------------- | --------------------------------------------- | ---------------------------------------------------------------- |
| Entry point                 | `p_telemetryproto.dissector`, a postdissector | `decode_frame(data)`                                             |
| VLAN tags                   | `while outer_eth_type == 0x8100 ...`          | `_walk_vlans`                                                    |
| Outer checks                | IPv4, IHL ≥ 5, UDP, port 5900                 | same; failures return a `SkipReason`                             |
| Report header               | fixed 16 bytes                                | `_decode_report`                                                 |
| Inner packet                | IPv4 + TCP (20 B) / UDP (8 B)                 | `_decode_inner`                                                  |
| INT shim + metadata header  | `p_intshimproto.dissector`                    | `_decode_int`                                                    |
| Hop walk and bounds         | `for hop_index = 0, full_hops - 1`            | `_decode_hops`, `_decode_hop`                                    |
| Hop latency                 | egress − ingress when both present            | same, `% 2**32`                                                  |
| What happens to a bad frame | nothing is added to the tree                  | a named `SkipReason`, counted in the decode report               |

The Python decoder adds what the Lua does not need to do: it reports *why* a
frame was skipped, and it hands the inner packet to the flow generator.

## Known differences from the specifications

Compared with the P4.org specifications (see [INT telemetry](int-telemetry.md)),
the Lua has three discrepancies. None of them changes a value used for flows.

1. **Report flags are shifted one bit.** In Telemetry Report v1.0 the first
   word is `Ver(4) Length(4) NProt(3) RepMdBits(6) Reserved(6) D Q F hw_id(6)`,
   so D, Q and F are bits 23, 24 and 25. The Lua reads its "Drop", "Queue" and
   "Flow" flags from bits 24, 25 and 26, and RepMdBits from bits 12–17 instead
   of 11–16. Its "Flow" bit is also the top bit of `hw_id`. Every sampled report
   has flag byte `0x40`: the Lua shows *Queue Bit = True*, the specification
   reads *F = 1* (tracked flow). F = 1 is consistent with the reports carrying
   INT data. **The Python decoder follows the specification here**; these
   fields are not part of the parity check and feed no flow feature.
1. **Instruction bit 6** is labelled "Queue ID + Congestion Status" and
   consumed as 4 bytes; INT v1.0 defines it as level-2 port IDs, 8 bytes. The
   Python decoder matches the Lua. Bit 6 is never set in the sample.
1. **Only the first instruction byte is read**, by both implementations. The
   second byte is zero in every sampled frame.

To bring the Lua in line with item 1, read D from `tvbuf(telemetry_offset + 2, 1):bitfield(7, 1)`, Q and F from bits 0 and 1 of byte 3, and RepMdBits from
`tvbuf(telemetry_offset + 1, 2):bitfield(3, 6)`. The file in this repository
is kept exactly as delivered.

## Checking parity

```bash
bash scripts/non-interactive/check-lua-parity.sh                       # the 50,000-packet sample
bash scripts/non-interactive/check-lua-parity.sh path/to/capture.pcap  # any capture
```

The script runs tshark with the Lua (a local tshark if there is one, otherwise
tshark 4.x from Alpine Linux in podman or docker), extracts 22 fields per
frame, decodes the same file with the Python decoder and compares them. On
`samples/student_sample_50000.pcap`:

```text
compared 50000 frames (1100000 fields): 0 disagree
```

The field list lives in `scripts/check_lua_parity.py` (`TSHARK_FIELDS`); add a
field there to extend the comparison.
