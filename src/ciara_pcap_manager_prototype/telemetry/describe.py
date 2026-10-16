"""
Render a decoded packet as indented, human-readable text, layer by layer.

Used by ``ciara-pcap-inspect --inspect`` to show what the decoder sees in a
frame, the same way Wireshark's packet tree does with the Lua dissector.
"""

from ciara_pcap_manager_prototype.domain.flows import protocol_name
from ciara_pcap_manager_prototype.telemetry.layers import DecodedPacket, IntHop

_INSTRUCTIONS = (
    "switch id",
    "ingress+egress port",
    "hop latency",
    "queue id+occupancy",
    "ingress timestamp",
    "egress timestamp",
    "level-2 port ids",
    "egress port tx util",
)


def _vlans(vlan_ids: tuple[int, ...]) -> str:
    """
    Describe a VLAN tag stack.

    Args:
        vlan_ids: VLAN identifiers, outermost first.

    Returns:
        ``" vlan 21"``-style text, or an empty string when untagged.

    """
    return "".join(f" vlan {vlan}" for vlan in vlan_ids)


def _hop(index: int, hop: IntHop) -> list[str]:
    """
    Describe one INT hop.

    Args:
        index: One-based hop position in the stack.
        hop: The decoded hop.

    Returns:
        Indented lines describing the hop's fields.

    """
    fields = [
        ("switch id", hop.switch_id),
        ("ingress port", hop.ingress_port),
        ("egress port", hop.egress_port),
        ("queue id", hop.queue_id),
        ("queue occupancy", hop.queue_occupancy),
        ("ingress timestamp", hop.ingress_timestamp),
        ("egress timestamp", hop.egress_timestamp),
        ("hop latency (wire)", hop.raw_hop_latency),
        ("hop latency (ns)", hop.hop_latency),
    ]
    lines = [f"      hop {index}"]
    lines += [
        f"        {name:<20}{value}" for name, value in fields if value is not None
    ]
    return lines


def describe_packet(packet: DecodedPacket) -> list[str]:
    """
    Describe every layer of a decoded telemetry report.

    Args:
        packet: The decoded packet.

    Returns:
        Lines of text, outermost layer first.

    """
    outer, report, inner = packet.outer, packet.report, packet.inner
    proto = protocol_name(inner.ip_proto)
    lines = [
        (
            f"  OUTER  {outer.src_ip}:{outer.src_port} -> "
            f"{outer.dst_ip}:{outer.dst_port} UDP{_vlans(outer.vlan_ids)}"
        ),
        (
            f"  REPORT v{report.version} switch {report.switch_id} "
            f"seq {report.sequence_number} ingress_ts {report.ingress_timestamp} "
            f"drop={int(report.drop)} queue={int(report.queue)} flow={int(report.flow)}"
        ),
        (
            f"  INNER  {inner.src_ip}:{inner.src_port} -> "
            f"{inner.dst_ip}:{inner.dst_port} {proto}{_vlans(inner.vlan_ids)} "
            f"ip_len {inner.ip_total_length} (captured {inner.ip_captured_bytes})"
        ),
    ]
    if inner.ip_proto == 6:  # noqa: PLR2004 - TCP
        lines.append(
            f"         tcp data offset {inner.tcp_data_offset} "
            f"flags {inner.tcp_flags:#04x}"
        )
    else:
        lines.append(
            f"         udp length {inner.udp_length} "
            f"(captured {inner.udp_captured_bytes})"
        )

    telemetry = packet.int_telemetry
    if telemetry is None:
        lines.append("  INT    none")
        return lines

    metadata = telemetry.metadata
    requested = [
        name
        for bit, name in enumerate(_INSTRUCTIONS)
        if metadata.instruction_bitmap & (0x80 >> bit)
    ]
    lines += [
        (
            f"  INT    shim type {telemetry.shim.type} length "
            f"{telemetry.shim.length_words} words dscp {telemetry.shim.dscp}"
        ),
        (
            f"         md v{metadata.version} hop_ml {metadata.hop_ml_words} words "
            f"remaining {metadata.remaining_hop_count} instructions "
            f"{metadata.instruction_bitmap:#04x} ({', '.join(requested)})"
        ),
        (
            f"         stack {telemetry.captured_stack_bytes} of "
            f"{telemetry.declared_stack_bytes} declared bytes, "
            f"{len(telemetry.hops)} hop(s)"
        ),
    ]
    for index, hop in enumerate(telemetry.hops, start=1):
        lines += _hop(index, hop)
    return lines
