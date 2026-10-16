"""
The headers of one INT telemetry report, as plain immutable records.

A captured frame on the collector link is two packets nested inside each
other::

    outer Ethernet [VLAN]* | outer IPv4 | outer UDP (dst 5900)
      | Telemetry Report header (16 B)
      | inner Ethernet [VLAN]* | inner IPv4 | inner TCP (20 B) or UDP (8 B)
        | INT shim (4 B) | INT metadata header (8 B) | INT metadata stack

The *outer* packet is the envelope the switch used to ship the report to the
collector; every report shares the same few outer addresses. The *inner*
packet is the user traffic the switch observed, and the INT stack carries the
switch's measurements of it. Flows are built from the inner packet only.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OuterHeaders:
    """The envelope that carried the report from the switch to the collector."""

    vlan_ids: tuple[int, ...]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int


@dataclass(frozen=True, slots=True)
class TelemetryReport:
    """The fixed 16-byte telemetry report header that follows the outer UDP."""

    version: int
    length_bytes: int
    next_proto: int
    """0 means the report embeds an Ethernet frame."""
    rep_md_bits: int
    drop: bool
    """D: a packet matching a drop watchlist was dropped."""
    queue: bool
    """Q: congestion on a monitored queue."""
    flow: bool
    """F: the report is for a tracked flow and may embed INT metadata."""
    hw_id: int
    switch_id: int
    sequence_number: int
    ingress_timestamp: int


@dataclass(frozen=True, slots=True)
class IntShim:
    """The 4-byte INT shim header placed after the inner L4 header."""

    type: int
    length_words: int
    dscp: int


@dataclass(frozen=True, slots=True)
class IntMetadataHeader:
    """The 8-byte INT metadata header that describes the stack layout."""

    version: int
    replication: int
    copy: bool
    max_hop_count_exceeded: bool
    mtu_exceeded: bool
    hop_ml_words: int
    remaining_hop_count: int
    instruction_bitmap: int
    """Instruction byte, bit 0 being the most significant bit."""


@dataclass(frozen=True, slots=True)
class IntHop:
    """
    The metadata one switch pushed onto the INT stack.

    A field is None when the instruction bitmap did not ask for it.
    """

    switch_id: int | None
    ingress_port: int | None
    egress_port: int | None
    hop_latency: int | None
    """Egress minus ingress timestamp (wrap-aware) when both are present,
    otherwise the on-wire hop latency word."""
    raw_hop_latency: int | None
    """The hop latency word exactly as carried on the wire."""
    queue_id: int | None
    queue_occupancy: int | None
    ingress_timestamp: int | None
    egress_timestamp: int | None


@dataclass(frozen=True, slots=True)
class IntTelemetry:
    """Everything decoded from the INT shim onward."""

    shim: IntShim
    metadata: IntMetadataHeader
    hops: tuple[IntHop, ...]
    declared_stack_bytes: int
    captured_stack_bytes: int


@dataclass(frozen=True, slots=True)
class InnerPacket:
    """The user packet the switch observed, from its Ethernet header to L4."""

    vlan_ids: tuple[int, ...]
    src_ip: str
    dst_ip: str
    ip_proto: int
    ip_total_length: int
    """IPv4 Total Length as declared in the header, in bytes."""
    ip_captured_bytes: int
    """Bytes actually present from the inner IPv4 header to the frame end."""
    src_port: int
    dst_port: int
    tcp_data_offset: int
    """TCP data-offset nibble; 0 for UDP."""
    tcp_flags: int
    """TCP flags byte; 0 for UDP."""
    udp_length: int
    """UDP Length as declared in the header; 0 for TCP."""
    udp_captured_bytes: int
    """Bytes actually present from the inner UDP header to the frame end; 0
    for TCP."""


@dataclass(frozen=True, slots=True)
class DecodedPacket:
    """A telemetry report whose inner packet was decoded down to L4."""

    outer: OuterHeaders
    report: TelemetryReport
    inner: InnerPacket
    int_telemetry: IntTelemetry | None
    """None when the frame holds no parseable INT shim and metadata header."""
