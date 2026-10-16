"""
Object factories shared by the test suite.

`make_flow` does not hand-write the 99 codebook columns: it runs a few packet
rows through the real `FlowSegment`, so every factory flow is internally
consistent, then applies the overrides a test asks for.
"""

from dataclasses import replace
from typing import Any

from ciara_pcap_manager_prototype.domain.flows import (
    DecodeReport,
    Flow,
    FlowSummary,
    TerminationReason,
)
from ciara_pcap_manager_prototype.flows.packet import PacketRecord
from ciara_pcap_manager_prototype.flows.segment import FlowSegment

BASE_NS = 1_700_000_000 * 1_000_000_000

_PACKET = PacketRecord(
    packet_uid="sample|sample.pcap|0",
    source_file="sample.pcap",
    packet_index=0,
    packet_time=BASE_NS / 1e9,
    packet_time_ns=BASE_NS,
    timeframe_id="sample",
    direction="unknown",
    inner_ip_src="10.0.0.1",
    inner_ip_dst="93.184.216.34",
    inner_ip_proto=6,
    l4_proto="TCP",
    src_port=5001,
    dst_port=443,
    tcp_dataofs=5,
    tcp_header_len_bytes=20,
    tcp_options_len=0,
    inner_ip_len=60,
    inner_ip_total_length_declared=60,
    int_ingress_timestamp=1_000,
    int_egress_timestamp=2_500,
    int_queue_occupancy=21,
    inner_ip_truncated_vs_declared=False,
    inner_udp_truncated_vs_declared=False,
    tcp_flag_syn=False,
    tcp_flag_ack=True,
    tcp_flag_fin=False,
    tcp_flag_rst=False,
    tcp_flag_psh=False,
    tcp_flag_urg=False,
    capture_start_utc=None,
    capture_end_utc=None,
    capture_start_epoch=None,
    capture_end_epoch=None,
    int_hop_count=1,
    int_path_latency=1_500,
    int_queue_observations=(21,),
)


def make_packet(**overrides: Any) -> PacketRecord:  # noqa: ANN401 - fields of every type
    """
    Build a packet row: a TCP ACK from 10.0.0.1:5001 with one INT hop.

    Args:
        **overrides: Fields replacing the defaults. ``packet_time_ns`` also
            updates ``packet_time``.

    Returns:
        The packet row.

    """
    if "packet_time_ns" in overrides and "packet_time" not in overrides:
        overrides["packet_time"] = overrides["packet_time_ns"] / 1e9
    return replace(_PACKET, **overrides)


def reply_to(packet: PacketRecord, **overrides: Any) -> PacketRecord:  # noqa: ANN401 - fields of every type
    """
    Build the reverse-direction counterpart of a packet.

    Args:
        packet: The packet to answer.
        **overrides: Further fields to change.

    Returns:
        A packet from the original destination back to the source.

    """
    swapped: dict[str, Any] = {
        "inner_ip_src": packet.inner_ip_dst,
        "inner_ip_dst": packet.inner_ip_src,
        "src_port": packet.dst_port,
        "dst_port": packet.src_port,
    }
    return replace(packet, **(swapped | overrides))


def make_flow(**overrides: object) -> Flow:
    """
    Build a flow from three packets (two forward, one back), then override.

    Args:
        **overrides: Codebook columns replacing the computed values.

    Returns:
        The flow.

    """
    first = make_packet()
    segment = FlowSegment(
        base_flow_key="6|10.0.0.1|93.184.216.34|5001|443", segment_id=0, first=first
    )
    segment.add(first)
    segment.add(make_packet(packet_index=1, packet_time_ns=BASE_NS + 10_000_000))
    segment.add(
        reply_to(
            first,
            packet_index=2,
            packet_time_ns=BASE_NS + 20_000_000,
            inner_ip_len=1500,
        )
    )
    flow = segment.to_flow(TerminationReason.END_OF_INPUT)
    return Flow.model_validate(flow.model_dump() | overrides)


def make_report(**overrides: Any) -> DecodeReport:  # noqa: ANN401 - fields of every type
    """
    Build a decode report for 12 frames, 10 of them decoded.

    Args:
        **overrides: Fields replacing the defaults.

    Returns:
        The report.

    """
    base: dict[str, Any] = {
        "frames_read": 12,
        "inner_packets": 10,
        "packets_with_int": 10,
        "packets_with_int_hops": 10,
        "packets_out_of_order": 2,
        "packets_late": 0,
        "packets_over_flow_cap": 0,
        "skipped": {"not_telemetry_port": 2},
    }
    return DecodeReport.model_validate(base | overrides)


def summary_payload(*flows: Flow) -> dict[str, Any]:
    """
    Build the JSON a backend returns for a job summary.

    Args:
        *flows: The job's flows; one default flow when omitted.

    Returns:
        The summary as JSON-compatible data.

    """
    summary = FlowSummary.from_flows(list(flows) or [make_flow()], make_report())
    return summary.model_dump(mode="json")
