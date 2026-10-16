"""
Build INT telemetry captures byte by byte, without a capture library.

Committing opaque binary fixtures makes a repository hard to review. These
helpers write every header from :mod:`struct`, in the same layout as the
collector captures (see ``docs/packet-anatomy.md``), so each fixture in the
suite is readable source::

    outer Ethernet + VLAN | outer IPv4 | outer UDP -> 5900
      | telemetry report (16 B)
      | inner Ethernet + VLAN | inner IPv4 | TCP (20 B) or UDP (8 B)
        | INT shim (4 B) | INT metadata header (8 B) | hops

Run it directly to regenerate the synthetic sample shipped for manual testing::

    uv run python tests/support/pcap_factory.py samples/synthetic.pcap
"""

import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

PCAP_MAGIC_NANOSECONDS = 0xA1B23C4D
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_VLAN = 0x8100
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
TELEMETRY_PORT = 5900

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20

#: Instruction byte asking for switch id, ports, hop latency, queue,
#: ingress and egress timestamps: what the real sample carries.
INSTRUCTIONS_SAMPLE = 0xFC

_SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
_DST_MAC = b"\x02\x00\x00\x00\x00\x02"

#: Base capture time: 2023-11-14 22:13:20 UTC, chosen only for stability.
BASE_NS = 1_700_000_000 * 1_000_000_000


@dataclass(frozen=True)
class Hop:
    """One INT hop, in the field order of instruction bits 0 to 5."""

    switch_id: int = 24
    ingress_port: int = 24
    egress_port: int = 18
    hop_latency: int = 0xFFFFFFFF
    queue_id: int = 0
    queue_occupancy: int = 21
    ingress_ts: int = 1_000_000
    egress_ts: int = 1_001_500

    def encode(self, instructions: int = INSTRUCTIONS_SAMPLE) -> bytes:
        """
        Encode the words the instruction byte asks for.

        Args:
            instructions: The instruction byte, bit 0 most significant.

        Returns:
            The hop's bytes.

        """
        words = [
            struct.pack("!I", self.switch_id),
            struct.pack("!HH", self.ingress_port, self.egress_port),
            struct.pack("!I", self.hop_latency),
            bytes([self.queue_id]) + self.queue_occupancy.to_bytes(3, "big"),
            struct.pack("!I", self.ingress_ts),
            struct.pack("!I", self.egress_ts),
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00",
        ]
        return b"".join(
            word for bit, word in enumerate(words) if instructions & (0x80 >> bit)
        )


def int_header(
    hops: list[Hop],
    *,
    instructions: int = INSTRUCTIONS_SAMPLE,
    hop_ml: int | None = None,
    shim_length: int | None = None,
    remaining_hops: int = 9,
) -> bytes:
    """
    Build the INT shim, metadata header and stack.

    Args:
        hops: The hops to encode, first hop first.
        instructions: The instruction byte.
        hop_ml: Words per hop; defaults to the words the instructions need.
        shim_length: Shim length in words; defaults to the correct value.
        remaining_hops: The metadata header's remaining hop count.

    Returns:
        The INT bytes.

    """
    words = bin(instructions).count("1")
    ml = words if hop_ml is None else hop_ml
    stack = b"".join(hop.encode(instructions).ljust(ml * 4, b"\x00") for hop in hops)
    length = 3 + len(stack) // 4 if shim_length is None else shim_length
    shim = bytes([1, 0, length, 0])
    metadata = bytes([0x10, 0x00, ml & 0x1F, remaining_hops, instructions, 0, 0, 0])
    return shim + metadata + stack


def ipv4(
    src: str,
    dst: str,
    protocol: int,
    payload: bytes,
    *,
    total_length: int | None = None,
    options: bytes = b"",
) -> bytes:
    """
    Build an IPv4 header followed by its payload.

    Args:
        src: Source address.
        dst: Destination address.
        protocol: IANA protocol number.
        payload: Everything after the IPv4 header.
        total_length: Declared Total Length; defaults to the real length.
        options: IPv4 options, a multiple of four bytes.

    Returns:
        The packet bytes.

    """
    ihl = 5 + len(options) // 4
    declared = ihl * 4 + len(payload) if total_length is None else total_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl,
        0,
        declared,
        0,
        0x4000,
        64,
        protocol,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + options + payload


def tcp(src_port: int, dst_port: int, flags: int, *, data_offset: int = 5) -> bytes:
    """
    Build the fixed 20-byte TCP header the collector keeps.

    Args:
        src_port: Source port.
        dst_port: Destination port.
        flags: TCP flag bits.
        data_offset: Declared data offset, in words.

    Returns:
        The 20 header bytes.

    """
    return struct.pack(
        "!HHIIBBHHH", src_port, dst_port, 0, 0, data_offset << 4, flags, 1024, 0, 0
    )


def udp(src_port: int, dst_port: int, *, length: int = 8) -> bytes:
    """
    Build an 8-byte UDP header.

    Args:
        src_port: Source port.
        dst_port: Destination port.
        length: Declared UDP Length.

    Returns:
        The header bytes.

    """
    return struct.pack("!HHHH", src_port, dst_port, length, 0)


def ethernet(payload: bytes, *, vlans: tuple[int, ...] = ()) -> bytes:
    """
    Wrap a payload in an Ethernet II frame with optional 802.1Q tags.

    Args:
        payload: The IPv4 bytes.
        vlans: VLAN ids, outermost first.

    Returns:
        The frame bytes.

    """
    tags = b"".join(struct.pack("!HH", ETH_TYPE_VLAN, vlan) for vlan in vlans)
    return _DST_MAC + _SRC_MAC + tags + struct.pack("!H", ETH_TYPE_IPV4) + payload


def report_header(
    *, switch_id: int = 24, sequence: int = 1, ingress_ts: int = 0
) -> bytes:
    """
    Build the 16-byte telemetry report header.

    Args:
        switch_id: The reporting switch.
        sequence: Report sequence number.
        ingress_ts: Report ingress timestamp.

    Returns:
        The header bytes: version 1, length 16, and the F (tracked flow) bit
        set, like every report in the sample.

    """
    return bytes([0x14, 0x00, 0x00, 0x40]) + struct.pack(
        "!III", switch_id, sequence, ingress_ts
    )


def telemetry_frame(
    inner_frame: bytes,
    *,
    outer_src: str = "10.0.0.1",
    outer_dst: str = "10.0.0.254",
    outer_port: int = TELEMETRY_PORT,
    switch_id: int = 24,
    sequence: int = 1,
) -> bytes:
    """
    Wrap an inner Ethernet frame in a report and the outer envelope.

    The outer IPv4 and UDP lengths are left at the size of their own headers,
    like the stale values in the real captures: the decoder must not use them.

    Args:
        inner_frame: The inner Ethernet frame, INT included.
        outer_src: Address of the reporting switch.
        outer_dst: Address of the collector.
        outer_port: Outer UDP destination port.
        switch_id: Report header switch id.
        sequence: Report sequence number.

    Returns:
        The outer Ethernet frame.

    """
    report = report_header(switch_id=switch_id, sequence=sequence)
    outer_udp = udp(6000, outer_port, length=8)
    outer_ip = ipv4(outer_src, outer_dst, IP_PROTO_UDP, b"", total_length=28)
    return ethernet(outer_ip + outer_udp + report + inner_frame, vlans=(21,))


def tcp_report(
    src: str,
    sport: int,
    dst: str,
    dport: int,
    flags: int,
    *,
    size: int = 60,
    hops: list[Hop] | None = None,
    data_offset: int = 5,
) -> bytes:
    """
    Build a complete report whose inner packet is TCP.

    Args:
        src: Inner source address.
        sport: Inner source port.
        dst: Inner destination address.
        dport: Inner destination port.
        flags: TCP flag bits.
        size: Declared inner IPv4 Total Length.
        hops: INT hops; one default hop when omitted.
        data_offset: Declared TCP data offset.

    Returns:
        The captured frame.

    """
    payload = tcp(sport, dport, flags, data_offset=data_offset) + int_header(
        hops if hops is not None else [Hop()]
    )
    inner = ethernet(
        ipv4(src, dst, IP_PROTO_TCP, payload, total_length=size), vlans=(501,)
    )
    return telemetry_frame(inner)


def udp_report(
    src: str,
    sport: int,
    dst: str,
    dport: int,
    *,
    size: int = 60,
    hops: list[Hop] | None = None,
) -> bytes:
    """
    Build a complete report whose inner packet is UDP.

    Args:
        src: Inner source address.
        sport: Inner source port.
        dst: Inner destination address.
        dport: Inner destination port.
        size: Declared inner IPv4 Total Length; UDP Length is 20 less.
        hops: INT hops; one default hop when omitted.

    Returns:
        The captured frame.

    """
    payload = udp(sport, dport, length=size - 20) + int_header(
        hops if hops is not None else [Hop()]
    )
    inner = ethernet(
        ipv4(src, dst, IP_PROTO_UDP, payload, total_length=size), vlans=(501,)
    )
    return telemetry_frame(inner)


def write_pcap(path: Path, frames: list[tuple[int, bytes]]) -> Path:
    """
    Write frames to a classic libpcap file with nanosecond timestamps.

    Args:
        path: Destination file.
        frames: ``(timestamp_ns, frame)`` pairs in file order.

    Returns:
        The path that was written.

    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(
            struct.pack(
                "<IHHiIII",
                PCAP_MAGIC_NANOSECONDS,
                2,
                4,
                0,
                0,
                SNAPLEN,
                LINKTYPE_ETHERNET,
            )
        )
        for timestamp_ns, frame in frames:
            seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
            handle.write(
                struct.pack("<IIII", seconds, nanoseconds, len(frame), len(frame))
            )
            handle.write(frame)
    return path


def _ns(milliseconds: float) -> int:
    """
    Offset the base capture time.

    Args:
        milliseconds: Offset from the base time.

    Returns:
        Epoch nanoseconds.

    """
    return BASE_NS + round(milliseconds * 1_000_000)


def _hop(ingress_us: int, latency_ns: int = 1500, queue: int = 21) -> list[Hop]:
    """
    One hop with a given ingress time and latency.

    Args:
        ingress_us: Ingress timestamp in microseconds.
        latency_ns: Egress minus ingress, in nanoseconds.
        queue: Queue occupancy.

    Returns:
        A one-hop stack.

    """
    ingress = ingress_us * 1000
    return [
        Hop(ingress_ts=ingress, egress_ts=ingress + latency_ns, queue_occupancy=queue)
    ]


CLIENT, SERVER, PEER, RESOLVER = "10.1.0.10", "93.184.216.34", "10.1.0.20", "10.1.0.53"


@dataclass(frozen=True)
class SampleExpectation:
    """What the synthetic sample must produce; the tests assert against it."""

    frames: int = 13
    inner_packets: int = 12
    flows: int = 4
    out_of_order: int = 1
    skipped: tuple[tuple[str, int], ...] = (("not_telemetry_port", 1),)


SAMPLE_EXPECTED = SampleExpectation()


def sample_frames() -> list[tuple[int, bytes]]:
    """
    Describe the synthetic sample: three conversations and one stray frame.

    * A TCP conversation with a handshake, data in both directions and FINs
      from both sides, followed by the final ACK. The FIN pair closes the first
      segment (``tcp_fin_both``); the trailing ACK opens segment 1.
    * A TCP SYN answered by RST (``tcp_rst``).
    * A UDP exchange, one of whose reports is written to the file 5 ms late,
      out of time order, the way interleaved collector streams arrive.
    * A plain UDP frame to port 53 on the collector link, which is not a
      telemetry report and is skipped.

    Returns:
        ``(timestamp_ns, frame)`` pairs in file order.

    """
    c, s = CLIENT, SERVER
    frames = [
        (_ns(0), tcp_report(c, 40000, s, 443, TH_SYN, size=60, hops=_hop(0))),
        (
            _ns(1),
            tcp_report(s, 443, c, 40000, TH_SYN | TH_ACK, size=60, hops=_hop(1000)),
        ),
        (_ns(2), tcp_report(c, 40000, s, 443, TH_ACK, size=52, hops=_hop(2000))),
        (
            _ns(3),
            tcp_report(
                c, 40000, s, 443, TH_PSH | TH_ACK, size=1500, hops=_hop(3000, 2000, 40)
            ),
        ),
        (
            _ns(4),
            tcp_report(s, 443, c, 40000, TH_FIN | TH_ACK, size=52, hops=_hop(4000)),
        ),
        (
            _ns(5),
            tcp_report(c, 40000, s, 443, TH_FIN | TH_ACK, size=52, hops=_hop(5000)),
        ),
        (_ns(6), tcp_report(s, 443, c, 40000, TH_ACK, size=40, hops=_hop(6000))),
        (_ns(10), tcp_report(PEER, 50000, s, 80, TH_SYN, size=60, hops=_hop(10000))),
        (
            _ns(11),
            tcp_report(s, 80, PEER, 50000, TH_RST | TH_ACK, size=40, hops=_hop(11000)),
        ),
        (_ns(20), udp_report(c, 53000, RESOLVER, 53, size=70, hops=_hop(20000))),
        (_ns(30), udp_report(c, 53000, RESOLVER, 53, size=70, hops=_hop(30000))),
        (_ns(25), udp_report(RESOLVER, 53, c, 53000, size=120, hops=_hop(25000))),
    ]
    stray = ethernet(ipv4(c, RESOLVER, IP_PROTO_UDP, udp(53001, 53)))
    frames.insert(7, (_ns(7), stray))
    return frames


def build_sample_capture(path: Path) -> Path:
    """
    Write the synthetic INT telemetry sample.

    Args:
        path: Destination file.

    Returns:
        The path that was written.

    """
    return write_pcap(path, sample_frames())


if __name__ == "__main__":
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/synthetic.pcap")
    print(build_sample_capture(destination))
