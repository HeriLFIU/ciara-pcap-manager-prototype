"""
Decode a captured collector frame into its inner packet and INT metadata.

This is a line-for-line Python counterpart of the Wireshark dissector shipped
in ``tools/wireshark/int_extension_fullframe_v7.lua``. Both walk the headers
*structurally* from the complete captured frame:

* IPv4 IHL and the fixed Ethernet, VLAN, UDP and telemetry header sizes locate
  each next header;
* no length *declaration* (outer or inner IPv4 Total Length, outer or inner
  UDP Length) is trusted to say where the captured bytes end. The collector
  truncates the inner packet and appends the INT stack, so those fields
  describe the original packet, not the bytes on disk. The only bound is the
  number of bytes actually captured;
* INT starts right after a fixed 20-byte TCP header or 8-byte UDP header. The
  TCP data offset is recorded but not used to find INT, because in this
  collector layout the INT shim always follows the first 20 TCP bytes.

The INT stack itself is bounded by INT's own fields: the shim length (4-byte
words covering shim + metadata header + stack) and Hop ML (4-byte words per
hop), capped at the bytes captured.
"""

import socket
import struct
from enum import StrEnum
from typing import Final

from ciara_pcap_manager_prototype.telemetry.layers import (
    DecodedPacket,
    InnerPacket,
    IntHop,
    IntMetadataHeader,
    IntShim,
    IntTelemetry,
    OuterHeaders,
    TelemetryReport,
)

#: UDP destination port the switches send telemetry reports to.
DEFAULT_TELEMETRY_PORT: Final = 5900

ETH_LEN: Final = 14
VLAN_LEN: Final = 4
IPV4_MIN_LEN: Final = 20
UDP_LEN: Final = 8
TCP_FIXED_LEN: Final = 20
TELEMETRY_REPORT_LEN: Final = 16
INT_SHIM_LEN: Final = 4
INT_MD_LEN: Final = 8

ETHERTYPE_IPV4: Final = 0x0800
#: 802.1Q, 802.1ad and the legacy pre-standard QinQ tag protocol identifiers.
VLAN_ETHERTYPES: Final = frozenset({0x8100, 0x88A8, 0x9100})

IP_PROTO_TCP: Final = 6
IP_PROTO_UDP: Final = 17

#: The shim length covers itself and the metadata header: three words minimum.
_MIN_SHIM_WORDS: Final = 3
_WORD: Final = 4
_U32_WRAP: Final = 1 << 32
_VLAN_ID_MASK: Final = 0x0FFF

_U16 = struct.Struct("!H")
_U32 = struct.Struct("!I")
_PORTS = struct.Struct("!HH")


class SkipReason(StrEnum):
    """Why a captured frame did not yield an inner TCP/UDP packet."""

    UNSUPPORTED_LINK_TYPE = "unsupported_link_type"
    OUTER_TRUNCATED = "outer_truncated"
    OUTER_NOT_IPV4 = "outer_not_ipv4"
    OUTER_NOT_UDP = "outer_not_udp"
    NOT_TELEMETRY_PORT = "not_telemetry_port"
    REPORT_TRUNCATED = "report_truncated"
    INNER_TRUNCATED = "inner_truncated"
    INNER_NOT_IPV4 = "inner_not_ipv4"
    INNER_NOT_TCP_UDP = "inner_not_tcp_udp"
    INNER_L4_TRUNCATED = "inner_l4_truncated"


def _walk_vlans(
    data: bytes, ethertype_offset: int, end: int
) -> tuple[int, int, tuple[int, ...]] | None:
    """
    Step over any VLAN tags following an Ethernet header.

    Args:
        data: The whole captured frame.
        ethertype_offset: Absolute offset of the Ethernet EtherType field.
        end: Absolute offset one past the last captured byte.

    Returns:
        ``(ethertype, payload_offset, vlan_ids)``, or None if a tag is cut off.

    """
    ethertype = _U16.unpack_from(data, ethertype_offset)[0]
    offset = ethertype_offset + 2
    vlan_ids: list[int] = []
    while ethertype in VLAN_ETHERTYPES:
        if end < offset + VLAN_LEN:
            return None
        vlan_ids.append(_U16.unpack_from(data, offset)[0] & _VLAN_ID_MASK)
        ethertype = _U16.unpack_from(data, offset + 2)[0]
        offset += VLAN_LEN
    return ethertype, offset, tuple(vlan_ids)


def decode_frame(  # noqa: PLR0911 - one early return per header check, as in the Lua
    data: bytes, *, telemetry_port: int = DEFAULT_TELEMETRY_PORT
) -> DecodedPacket | SkipReason:
    """
    Decode one captured Ethernet frame from the collector link.

    Args:
        data: The captured bytes of the frame, starting at the outer Ethernet
            header.
        telemetry_port: Outer UDP destination port that marks a report.

    Returns:
        The decoded packet, or the reason the frame was skipped.

    """
    frame_len = len(data)

    # Outer Ethernet and VLAN tags.
    if frame_len < ETH_LEN:
        return SkipReason.OUTER_TRUNCATED
    walked = _walk_vlans(data, 12, frame_len)
    if walked is None:
        return SkipReason.OUTER_TRUNCATED
    outer_ethertype, outer_ip, outer_vlans = walked
    if outer_ethertype != ETHERTYPE_IPV4:
        return SkipReason.OUTER_NOT_IPV4

    # Outer IPv4: IHL locates the UDP header; Total Length is ignored.
    if frame_len < outer_ip + IPV4_MIN_LEN:
        return SkipReason.OUTER_TRUNCATED
    version, outer_ihl = data[outer_ip] >> 4, (data[outer_ip] & 0x0F) * 4
    if version != 4 or outer_ihl < IPV4_MIN_LEN:  # noqa: PLR2004 - IP version
        return SkipReason.OUTER_NOT_IPV4
    if frame_len < outer_ip + outer_ihl:
        return SkipReason.OUTER_TRUNCATED
    if data[outer_ip + 9] != IP_PROTO_UDP:
        return SkipReason.OUTER_NOT_UDP

    # Outer UDP: only the fixed header and the destination port matter.
    outer_udp = outer_ip + outer_ihl
    if frame_len < outer_udp + UDP_LEN:
        return SkipReason.OUTER_TRUNCATED
    outer_sport, outer_dport = _PORTS.unpack_from(data, outer_udp)
    if outer_dport != telemetry_port:
        return SkipReason.NOT_TELEMETRY_PORT

    report_offset = outer_udp + UDP_LEN
    if frame_len < report_offset + TELEMETRY_REPORT_LEN + ETH_LEN:
        return SkipReason.REPORT_TRUNCATED

    outer = OuterHeaders(
        vlan_ids=outer_vlans,
        src_ip=socket.inet_ntoa(data[outer_ip + 12 : outer_ip + 16]),
        dst_ip=socket.inet_ntoa(data[outer_ip + 16 : outer_ip + 20]),
        src_port=outer_sport,
        dst_port=outer_dport,
    )
    report = _decode_report(data, report_offset)

    inner_start = report_offset + TELEMETRY_REPORT_LEN
    inner = _decode_inner(data, inner_start)
    if isinstance(inner, SkipReason):
        return inner
    inner_packet, int_offset = inner

    return DecodedPacket(
        outer=outer,
        report=report,
        inner=inner_packet,
        int_telemetry=_decode_int(data, int_offset),
    )


def _decode_report(data: bytes, offset: int) -> TelemetryReport:
    """
    Decode the 16-byte telemetry report header.

    Bit positions follow the P4.org Telemetry Report Format v1.0, section 3.2:
    ``Ver(4) Length(4) NProt(3) RepMdBits(6) Reserved(6) D Q F hw_id(6)``,
    then 32-bit switch id, sequence number and ingress timestamp. The Lua
    dissector reads D, Q, F and RepMdBits one bit too far to the right (see
    docs/lua-dissector.md); none of these flags feeds a flow feature.

    Args:
        data: The whole captured frame.
        offset: Absolute offset of the report header.

    Returns:
        The decoded header.

    """
    b0, b1, b2, b3 = data[offset : offset + 4]
    return TelemetryReport(
        version=b0 >> 4,
        length_bytes=(b0 & 0x0F) * _WORD,
        next_proto=b1 >> 5,
        rep_md_bits=(((b1 << 8) | b2) >> 7) & 0x3F,
        drop=bool(b2 & 0x01),
        queue=bool(b3 & 0x80),
        flow=bool(b3 & 0x40),
        hw_id=b3 & 0x3F,
        switch_id=_U32.unpack_from(data, offset + 4)[0],
        sequence_number=_U32.unpack_from(data, offset + 8)[0],
        ingress_timestamp=_U32.unpack_from(data, offset + 12)[0],
    )


def _decode_inner(  # noqa: PLR0911 - one early return per header check
    data: bytes, inner_start: int
) -> tuple[InnerPacket, int] | SkipReason:
    """
    Decode the inner Ethernet, IPv4 and TCP/UDP headers.

    Args:
        data: The whole captured frame.
        inner_start: Absolute offset of the inner Ethernet header.

    Returns:
        The inner packet and the absolute offset where INT begins, or the
        reason the inner packet could not be decoded.

    """
    frame_len = len(data)
    walked = _walk_vlans(data, inner_start + 12, frame_len)
    if walked is None:
        return SkipReason.INNER_TRUNCATED
    ethertype, ip, vlans = walked
    if ethertype != ETHERTYPE_IPV4:
        return SkipReason.INNER_NOT_IPV4

    if frame_len < ip + IPV4_MIN_LEN:
        return SkipReason.INNER_TRUNCATED
    version, ihl = data[ip] >> 4, (data[ip] & 0x0F) * 4
    if version != 4 or ihl < IPV4_MIN_LEN:  # noqa: PLR2004 - IP version
        return SkipReason.INNER_NOT_IPV4
    if frame_len < ip + ihl:
        return SkipReason.INNER_TRUNCATED

    proto = data[ip + 9]
    l4 = ip + ihl
    if proto == IP_PROTO_TCP:
        if frame_len < l4 + TCP_FIXED_LEN:
            return SkipReason.INNER_L4_TRUNCATED
        data_offset, flags = data[l4 + 12] >> 4, data[l4 + 13]
        udp_length = udp_captured = 0
        int_offset = l4 + TCP_FIXED_LEN
    elif proto == IP_PROTO_UDP:
        if frame_len < l4 + UDP_LEN:
            return SkipReason.INNER_L4_TRUNCATED
        data_offset = flags = 0
        udp_length = _U16.unpack_from(data, l4 + 4)[0]
        udp_captured = frame_len - l4
        int_offset = l4 + UDP_LEN
    else:
        return SkipReason.INNER_NOT_TCP_UDP

    src_port, dst_port = _PORTS.unpack_from(data, l4)
    inner = InnerPacket(
        vlan_ids=vlans,
        src_ip=socket.inet_ntoa(data[ip + 12 : ip + 16]),
        dst_ip=socket.inet_ntoa(data[ip + 16 : ip + 20]),
        ip_proto=proto,
        ip_total_length=_U16.unpack_from(data, ip + 2)[0],
        ip_captured_bytes=frame_len - ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_data_offset=data_offset,
        tcp_flags=flags,
        udp_length=udp_length,
        udp_captured_bytes=udp_captured,
    )
    return inner, int_offset


def _decode_int(data: bytes, offset: int) -> IntTelemetry | None:
    """
    Decode the INT shim, metadata header and metadata stack.

    Args:
        data: The whole captured frame.
        offset: Absolute offset of the INT shim header.

    Returns:
        The INT telemetry, or None when the shim and metadata header are not
        both captured or the shim length is smaller than three words.

    """
    frame_len = len(data)
    if frame_len < offset + INT_SHIM_LEN + INT_MD_LEN:
        return None
    shim_words = data[offset + 2]
    if shim_words < _MIN_SHIM_WORDS:
        return None

    shim = IntShim(
        type=data[offset], length_words=shim_words, dscp=data[offset + 3] >> 2
    )

    md = offset + INT_SHIM_LEN
    m0, m1, m2, m3, m4 = data[md : md + 5]
    metadata = IntMetadataHeader(
        version=m0 >> 4,
        replication=(m0 >> 2) & 0x03,
        copy=bool(m0 & 0x02),
        max_hop_count_exceeded=bool(m0 & 0x01),
        mtu_exceeded=bool(m1 & 0x80),
        hop_ml_words=m2 & 0x1F,
        remaining_hop_count=m3,
        instruction_bitmap=m4,
    )

    declared = (shim_words - _MIN_SHIM_WORDS) * _WORD
    stack_start = md + INT_MD_LEN
    captured = min(declared, max(frame_len - stack_start, 0))
    hops = _decode_hops(data, stack_start, captured, metadata)
    return IntTelemetry(
        shim=shim,
        metadata=metadata,
        hops=hops,
        declared_stack_bytes=declared,
        captured_stack_bytes=captured,
    )


def _decode_hops(
    data: bytes, stack_start: int, stack_len: int, metadata: IntMetadataHeader
) -> tuple[IntHop, ...]:
    """
    Split the INT stack into hops and decode each one.

    Every hop is exactly Hop ML words long. A hop whose instruction bitmap asks
    for more words than Hop ML allows is invalid: it is dropped and decoding
    stops, exactly where the Lua dissector stops.

    Args:
        data: The whole captured frame.
        stack_start: Absolute offset of the first hop.
        stack_len: Stack bytes to decode: the declared length capped at the
            bytes captured.
        metadata: The metadata header, for Hop ML and the instruction bitmap.

    Returns:
        The decoded hops, in stack order.

    """
    hop_len = metadata.hop_ml_words * _WORD
    if hop_len <= 0 or stack_len < hop_len:
        return ()

    bits = [bool(metadata.instruction_bitmap & (0x80 >> bit)) for bit in range(8)]
    hops: list[IntHop] = []
    for index in range(stack_len // hop_len):
        hop = _decode_hop(data, stack_start + index * hop_len, hop_len, bits)
        if hop is None:
            break
        hops.append(hop)
    return tuple(hops)


def _decode_hop(
    data: bytes, start: int, hop_len: int, bits: list[bool]
) -> IntHop | None:
    """
    Decode one hop of the INT stack.

    Instruction bits, most significant first (INT v1.0, section 4.7): 0 switch
    ID, 1 ingress and egress port IDs, 2 hop latency, 3 queue ID and occupancy,
    4 ingress timestamp, 5 egress timestamp, 6 level-2 port IDs, 7 egress port
    TX utilisation. Fields are laid out in bit order. Bits 6 and 7 come after
    every decoded field and are counted but not decoded, as in the Lua
    dissector, which counts bit 6 as one word (INT v1.0 makes it two). Only
    bits 0 to 7 (the first instruction byte) are read, like the Lua.

    Args:
        data: The whole captured frame.
        start: Absolute offset of the hop.
        hop_len: Hop length in bytes (Hop ML x 4).
        bits: The eight instruction bits, bit 0 first.

    Returns:
        The decoded hop, or None if the requested fields overflow the hop.

    """
    words_needed = sum(bits)
    if words_needed * _WORD > hop_len:
        return None

    switch_id = ingress_port = egress_port = raw_latency = None
    queue_id = queue_occupancy = ingress_ts = egress_ts = None
    offset = start
    if bits[0]:
        switch_id = _U32.unpack_from(data, offset)[0]
        offset += _WORD
    if bits[1]:
        ingress_port, egress_port = _PORTS.unpack_from(data, offset)
        offset += _WORD
    if bits[2]:
        raw_latency = _U32.unpack_from(data, offset)[0]
        offset += _WORD
    if bits[3]:
        queue_id = data[offset]
        queue_occupancy = int.from_bytes(data[offset + 1 : offset + 4], "big")
        offset += _WORD
    if bits[4]:
        ingress_ts = _U32.unpack_from(data, offset)[0]
        offset += _WORD
    if bits[5]:
        egress_ts = _U32.unpack_from(data, offset)[0]

    if ingress_ts is not None and egress_ts is not None:
        latency: int | None = (egress_ts - ingress_ts) % _U32_WRAP
    else:
        latency = raw_latency

    return IntHop(
        switch_id=switch_id,
        ingress_port=ingress_port,
        egress_port=egress_port,
        hop_latency=latency,
        raw_hop_latency=raw_latency,
        queue_id=queue_id,
        queue_occupancy=queue_occupancy,
        ingress_timestamp=ingress_ts,
        egress_timestamp=egress_ts,
    )
