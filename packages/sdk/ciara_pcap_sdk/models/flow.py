from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.initiator_confidence import InitiatorConfidence, check_initiator_confidence
from ..models.termination_reason import TerminationReason, check_termination_reason

T = TypeVar("T", bound="Flow")


@_attrs_define
class Flow:
    """One flow segment built from the inner packets of INT telemetry reports."""

    ack_count_bwd: int
    """ ACK packets, B to A. """
    ack_count_fwd: int
    """ ACK packets, A to B. """
    ack_fraction: float
    """ ACK packets / `pkts_total`. """
    ack_ratio_bwd: float
    """ `ack_count_bwd / pkts_bwd`. """
    ack_ratio_fwd: float
    """ `ack_count_fwd / pkts_fwd`. """
    base_flow_key: str
    """ Direction-independent identity: `proto|ip_low|ip_high|port_low|port_high`. """
    bwd_bps: float | None
    """ `bytes_bwd / duration`. """
    bwd_pps: float | None
    """ `pkts_bwd / duration`. """
    bytes_bwd: int
    """ Inner IPv4 Total Length summed, B to A. """
    bytes_fwd: int
    """ Inner IPv4 Total Length summed, A to B. """
    bytes_per_pkt_bwd: float
    """ `bytes_bwd / pkts_bwd`, else 0.0. """
    bytes_per_pkt_fwd: float
    """ `bytes_fwd / pkts_fwd`, else 0.0. """
    bytes_per_pkt_gap: float
    """ `bytes_per_pkt_fwd - bytes_per_pkt_bwd`. """
    bytes_total: int
    """ `bytes_fwd + bytes_bwd`. """
    crosses_file_boundary: int
    """ 1 if the segment took packets from several files. """
    duration: float
    """ Seconds from the first to the last packet. """
    fin_count_bwd: int
    """ FIN packets, B to A. """
    fin_count_fwd: int
    """ FIN packets, A to B. """
    fin_fraction: float
    """ FIN packets / `pkts_total`. """
    fin_ratio_bwd: float
    """ `fin_count_bwd / pkts_bwd`. """
    fin_ratio_fwd: float
    """ `fin_count_fwd / pkts_fwd`. """
    first_observed_dst_ip: str
    """ Equals `ip_b`. """
    first_observed_dst_port: int
    """ Equals `port_b`. """
    first_observed_src_ip: str
    """ Equals `ip_a`. """
    first_observed_src_port: int
    """ Equals `port_a`. """
    first_packet_ack: int
    """ 1 if the first packet had ACK. """
    first_packet_direction: str
    """ Always `fwd`: A/B are taken from the first packet. """
    first_packet_syn: int
    """ 1 if the first packet had SYN. """
    first_packet_was_syn: int
    """ 1 for TCP with SYN=1 and ACK=0 on the first packet. """
    first_packet_was_syn_ack: int
    """ 1 for TCP with SYN=1 and ACK=1 on the first packet. """
    first_source_file: str
    """ First capture file of the segment. """
    first_timeframe_id: None | str
    """ First timeframe observed. """
    flow_end_time: float
    """ Epoch seconds of the last packet. """
    flow_id: str
    """ Segment identifier: `base_flow_key|segment`. """
    flow_initiator: str
    """ Always `observed_first_packet_src`. """
    flow_segment_id: int
    """ Segment counter per `base_flow_key`, starting at 0. """
    flow_start_time: float
    """ Epoch seconds of the first packet. """
    fwd_bps: float | None
    """ `bytes_fwd / duration`. """
    fwd_pps: float | None
    """ `pkts_fwd / duration`. """
    fwd_share_bytes: float | None
    """ `bytes_fwd / bytes_total`. """
    fwd_share_pkts: float | None
    """ `pkts_fwd / pkts_total`. """
    iat_int_count: int
    """ INT-timestamp inter-arrival observations in the segment. """
    iat_max_int_ns: float
    """ Largest INT inter-arrival (ns); 0.0 if none. """
    iat_min_int_ns: float
    """ Smallest INT inter-arrival (ns); 0.0 if none. """
    iat_std_int_ns: float
    """ Population std dev of INT inter-arrival (ns); 0.0 if <= 1. """
    initiator_confidence: InitiatorConfidence
    """ How much the first packet says about who opened the flow. """
    ip_a: str
    """ Source address of the segment's first packet. """
    ip_b: str
    """ Destination address of the segment's first packet. """
    last_source_file: str
    """ Last capture file of the segment. """
    last_timeframe_id: None | str
    """ Last timeframe observed. """
    latency_max: int | None
    """ Largest per-packet INT latency (ns). """
    latency_min: int | None
    """ Smallest per-packet INT latency (ns). """
    latency_std: float | None
    """ Population std dev of per-packet INT latency (ns). """
    mean_hop_count: float | None
    """ Mean INT hops per packet, over packets carrying INT hops. """
    mean_hop_latency: float | None
    """ Mean per-packet INT latency (ns, summed over hops). """
    mean_iat_int_ns: float
    """ Mean INT inter-arrival (ns); 0.0 if none. """
    mean_pkt_size: float | None
    """ Mean packet size in bytes. """
    pkt_size_max: int | None
    """ Largest packet size in bytes. """
    pkt_size_min: int | None
    """ Smallest packet size in bytes. """
    pkt_size_std: float | None
    """ Population std dev of sizes. """
    pkts_bwd: int
    """ Packets from B to A. """
    pkts_fwd: int
    """ Packets from A to B. """
    pkts_total: int
    """ `pkts_fwd + pkts_bwd`. """
    port_a: int
    """ Port paired with `ip_a`. """
    port_b: int
    """ Port paired with `ip_b`. """
    proto: int
    """ IP protocol number: 6 for TCP, 17 for UDP. """
    psh_count_bwd: int
    """ PSH packets, B to A. """
    psh_count_fwd: int
    """ PSH packets, A to B. """
    psh_fraction: float
    """ PSH packets / `pkts_total`. """
    psh_ratio_bwd: float
    """ `psh_count_bwd / pkts_bwd`. """
    psh_ratio_fwd: float
    """ `psh_count_fwd / pkts_fwd`. """
    queue_occupancy_max: int | None
    """ Largest INT queue occupancy. """
    queue_occupancy_mean: float | None
    """ Mean INT queue occupancy over every hop observation. """
    queue_occupancy_std: float | None
    """ Population std dev of INT queue occupancy. """
    rst_count_bwd: int
    """ RST packets, B to A. """
    rst_count_fwd: int
    """ RST packets, A to B. """
    rst_fraction: float
    """ RST packets / `pkts_total`. """
    rst_ratio_bwd: float
    """ `rst_count_bwd / pkts_bwd`. """
    rst_ratio_fwd: float
    """ `rst_count_fwd / pkts_fwd`. """
    small_pkt_fraction_total: float
    """ Share of packets of at most 100 bytes. """
    source_file_count: int
    """ 1 plus the number of source-file changes in the segment. """
    syn_ack_gap: int
    """ `syn_count_fwd - ack_count_bwd`. """
    syn_count_bwd: int
    """ SYN packets, B to A. """
    syn_count_fwd: int
    """ SYN packets, A to B. """
    syn_fraction: float
    """ SYN packets / `pkts_total`. """
    syn_ratio_bwd: float
    """ `syn_count_bwd / pkts_bwd`. """
    syn_ratio_fwd: float
    """ `syn_count_fwd / pkts_fwd`. """
    termination_reason: TerminationReason
    """ Why a flow segment was closed. """
    timeframe_id: None | str
    """ Timeframe of the segment's first packet (the capture's file name without its extension). """
    tiny_pkt_fraction_total: float
    """ Share of packets of at most 40 bytes. """
    total_bps: float | None
    """ `bytes_total / duration`. """
    total_pps: float | None
    """ `pkts_total / duration`. """
    truncated_ip_fraction: float | None
    """ Share of packets whose captured inner IPv4 bytes differ from its declared Total Length. """
    truncated_udp_fraction: float | None
    """ Share of packets whose captured inner UDP bytes differ from its declared Length. """
    urg_count_bwd: int
    """ URG packets, B to A. """
    urg_count_fwd: int
    """ URG packets, A to B. """
    urg_fraction: float
    """ URG packets / `pkts_total`. """
    urg_ratio_bwd: float
    """ `urg_count_bwd / pkts_bwd`. """
    urg_ratio_fwd: float
    """ `urg_count_fwd / pkts_fwd`. """
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ack_count_bwd = self.ack_count_bwd

        ack_count_fwd = self.ack_count_fwd

        ack_fraction = self.ack_fraction

        ack_ratio_bwd = self.ack_ratio_bwd

        ack_ratio_fwd = self.ack_ratio_fwd

        base_flow_key = self.base_flow_key

        bwd_bps: float | None
        bwd_bps = self.bwd_bps

        bwd_pps: float | None
        bwd_pps = self.bwd_pps

        bytes_bwd = self.bytes_bwd

        bytes_fwd = self.bytes_fwd

        bytes_per_pkt_bwd = self.bytes_per_pkt_bwd

        bytes_per_pkt_fwd = self.bytes_per_pkt_fwd

        bytes_per_pkt_gap = self.bytes_per_pkt_gap

        bytes_total = self.bytes_total

        crosses_file_boundary = self.crosses_file_boundary

        duration = self.duration

        fin_count_bwd = self.fin_count_bwd

        fin_count_fwd = self.fin_count_fwd

        fin_fraction = self.fin_fraction

        fin_ratio_bwd = self.fin_ratio_bwd

        fin_ratio_fwd = self.fin_ratio_fwd

        first_observed_dst_ip = self.first_observed_dst_ip

        first_observed_dst_port = self.first_observed_dst_port

        first_observed_src_ip = self.first_observed_src_ip

        first_observed_src_port = self.first_observed_src_port

        first_packet_ack = self.first_packet_ack

        first_packet_direction = self.first_packet_direction

        first_packet_syn = self.first_packet_syn

        first_packet_was_syn = self.first_packet_was_syn

        first_packet_was_syn_ack = self.first_packet_was_syn_ack

        first_source_file = self.first_source_file

        first_timeframe_id: None | str
        first_timeframe_id = self.first_timeframe_id

        flow_end_time = self.flow_end_time

        flow_id = self.flow_id

        flow_initiator = self.flow_initiator

        flow_segment_id = self.flow_segment_id

        flow_start_time = self.flow_start_time

        fwd_bps: float | None
        fwd_bps = self.fwd_bps

        fwd_pps: float | None
        fwd_pps = self.fwd_pps

        fwd_share_bytes: float | None
        fwd_share_bytes = self.fwd_share_bytes

        fwd_share_pkts: float | None
        fwd_share_pkts = self.fwd_share_pkts

        iat_int_count = self.iat_int_count

        iat_max_int_ns = self.iat_max_int_ns

        iat_min_int_ns = self.iat_min_int_ns

        iat_std_int_ns = self.iat_std_int_ns

        initiator_confidence: str = self.initiator_confidence

        ip_a = self.ip_a

        ip_b = self.ip_b

        last_source_file = self.last_source_file

        last_timeframe_id: None | str
        last_timeframe_id = self.last_timeframe_id

        latency_max: int | None
        latency_max = self.latency_max

        latency_min: int | None
        latency_min = self.latency_min

        latency_std: float | None
        latency_std = self.latency_std

        mean_hop_count: float | None
        mean_hop_count = self.mean_hop_count

        mean_hop_latency: float | None
        mean_hop_latency = self.mean_hop_latency

        mean_iat_int_ns = self.mean_iat_int_ns

        mean_pkt_size: float | None
        mean_pkt_size = self.mean_pkt_size

        pkt_size_max: int | None
        pkt_size_max = self.pkt_size_max

        pkt_size_min: int | None
        pkt_size_min = self.pkt_size_min

        pkt_size_std: float | None
        pkt_size_std = self.pkt_size_std

        pkts_bwd = self.pkts_bwd

        pkts_fwd = self.pkts_fwd

        pkts_total = self.pkts_total

        port_a = self.port_a

        port_b = self.port_b

        proto = self.proto

        psh_count_bwd = self.psh_count_bwd

        psh_count_fwd = self.psh_count_fwd

        psh_fraction = self.psh_fraction

        psh_ratio_bwd = self.psh_ratio_bwd

        psh_ratio_fwd = self.psh_ratio_fwd

        queue_occupancy_max: int | None
        queue_occupancy_max = self.queue_occupancy_max

        queue_occupancy_mean: float | None
        queue_occupancy_mean = self.queue_occupancy_mean

        queue_occupancy_std: float | None
        queue_occupancy_std = self.queue_occupancy_std

        rst_count_bwd = self.rst_count_bwd

        rst_count_fwd = self.rst_count_fwd

        rst_fraction = self.rst_fraction

        rst_ratio_bwd = self.rst_ratio_bwd

        rst_ratio_fwd = self.rst_ratio_fwd

        small_pkt_fraction_total = self.small_pkt_fraction_total

        source_file_count = self.source_file_count

        syn_ack_gap = self.syn_ack_gap

        syn_count_bwd = self.syn_count_bwd

        syn_count_fwd = self.syn_count_fwd

        syn_fraction = self.syn_fraction

        syn_ratio_bwd = self.syn_ratio_bwd

        syn_ratio_fwd = self.syn_ratio_fwd

        termination_reason: str = self.termination_reason

        timeframe_id: None | str
        timeframe_id = self.timeframe_id

        tiny_pkt_fraction_total = self.tiny_pkt_fraction_total

        total_bps: float | None
        total_bps = self.total_bps

        total_pps: float | None
        total_pps = self.total_pps

        truncated_ip_fraction: float | None
        truncated_ip_fraction = self.truncated_ip_fraction

        truncated_udp_fraction: float | None
        truncated_udp_fraction = self.truncated_udp_fraction

        urg_count_bwd = self.urg_count_bwd

        urg_count_fwd = self.urg_count_fwd

        urg_fraction = self.urg_fraction

        urg_ratio_bwd = self.urg_ratio_bwd

        urg_ratio_fwd = self.urg_ratio_fwd

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ack_count_bwd": ack_count_bwd,
                "ack_count_fwd": ack_count_fwd,
                "ack_fraction": ack_fraction,
                "ack_ratio_bwd": ack_ratio_bwd,
                "ack_ratio_fwd": ack_ratio_fwd,
                "base_flow_key": base_flow_key,
                "bwd_Bps": bwd_bps,
                "bwd_pps": bwd_pps,
                "bytes_bwd": bytes_bwd,
                "bytes_fwd": bytes_fwd,
                "bytes_per_pkt_bwd": bytes_per_pkt_bwd,
                "bytes_per_pkt_fwd": bytes_per_pkt_fwd,
                "bytes_per_pkt_gap": bytes_per_pkt_gap,
                "bytes_total": bytes_total,
                "crosses_file_boundary": crosses_file_boundary,
                "duration": duration,
                "fin_count_bwd": fin_count_bwd,
                "fin_count_fwd": fin_count_fwd,
                "fin_fraction": fin_fraction,
                "fin_ratio_bwd": fin_ratio_bwd,
                "fin_ratio_fwd": fin_ratio_fwd,
                "first_observed_dst_ip": first_observed_dst_ip,
                "first_observed_dst_port": first_observed_dst_port,
                "first_observed_src_ip": first_observed_src_ip,
                "first_observed_src_port": first_observed_src_port,
                "first_packet_ack": first_packet_ack,
                "first_packet_direction": first_packet_direction,
                "first_packet_syn": first_packet_syn,
                "first_packet_was_syn": first_packet_was_syn,
                "first_packet_was_syn_ack": first_packet_was_syn_ack,
                "first_source_file": first_source_file,
                "first_timeframe_id": first_timeframe_id,
                "flow_end_time": flow_end_time,
                "flow_id": flow_id,
                "flow_initiator": flow_initiator,
                "flow_segment_id": flow_segment_id,
                "flow_start_time": flow_start_time,
                "fwd_Bps": fwd_bps,
                "fwd_pps": fwd_pps,
                "fwd_share_bytes": fwd_share_bytes,
                "fwd_share_pkts": fwd_share_pkts,
                "iat_int_count": iat_int_count,
                "iat_max_int_ns": iat_max_int_ns,
                "iat_min_int_ns": iat_min_int_ns,
                "iat_std_int_ns": iat_std_int_ns,
                "initiator_confidence": initiator_confidence,
                "ip_a": ip_a,
                "ip_b": ip_b,
                "last_source_file": last_source_file,
                "last_timeframe_id": last_timeframe_id,
                "latency_max": latency_max,
                "latency_min": latency_min,
                "latency_std": latency_std,
                "mean_hop_count": mean_hop_count,
                "mean_hop_latency": mean_hop_latency,
                "mean_iat_int_ns": mean_iat_int_ns,
                "mean_pkt_size": mean_pkt_size,
                "pkt_size_max": pkt_size_max,
                "pkt_size_min": pkt_size_min,
                "pkt_size_std": pkt_size_std,
                "pkts_bwd": pkts_bwd,
                "pkts_fwd": pkts_fwd,
                "pkts_total": pkts_total,
                "port_a": port_a,
                "port_b": port_b,
                "proto": proto,
                "psh_count_bwd": psh_count_bwd,
                "psh_count_fwd": psh_count_fwd,
                "psh_fraction": psh_fraction,
                "psh_ratio_bwd": psh_ratio_bwd,
                "psh_ratio_fwd": psh_ratio_fwd,
                "queue_occupancy_max": queue_occupancy_max,
                "queue_occupancy_mean": queue_occupancy_mean,
                "queue_occupancy_std": queue_occupancy_std,
                "rst_count_bwd": rst_count_bwd,
                "rst_count_fwd": rst_count_fwd,
                "rst_fraction": rst_fraction,
                "rst_ratio_bwd": rst_ratio_bwd,
                "rst_ratio_fwd": rst_ratio_fwd,
                "small_pkt_fraction_total": small_pkt_fraction_total,
                "source_file_count": source_file_count,
                "syn_ack_gap": syn_ack_gap,
                "syn_count_bwd": syn_count_bwd,
                "syn_count_fwd": syn_count_fwd,
                "syn_fraction": syn_fraction,
                "syn_ratio_bwd": syn_ratio_bwd,
                "syn_ratio_fwd": syn_ratio_fwd,
                "termination_reason": termination_reason,
                "timeframe_id": timeframe_id,
                "tiny_pkt_fraction_total": tiny_pkt_fraction_total,
                "total_Bps": total_bps,
                "total_pps": total_pps,
                "truncated_ip_fraction": truncated_ip_fraction,
                "truncated_udp_fraction": truncated_udp_fraction,
                "urg_count_bwd": urg_count_bwd,
                "urg_count_fwd": urg_count_fwd,
                "urg_fraction": urg_fraction,
                "urg_ratio_bwd": urg_ratio_bwd,
                "urg_ratio_fwd": urg_ratio_fwd,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ack_count_bwd = d.pop("ack_count_bwd")

        ack_count_fwd = d.pop("ack_count_fwd")

        ack_fraction = d.pop("ack_fraction")

        ack_ratio_bwd = d.pop("ack_ratio_bwd")

        ack_ratio_fwd = d.pop("ack_ratio_fwd")

        base_flow_key = d.pop("base_flow_key")

        def _parse_bwd_bps(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        bwd_bps = _parse_bwd_bps(d.pop("bwd_Bps"))

        def _parse_bwd_pps(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        bwd_pps = _parse_bwd_pps(d.pop("bwd_pps"))

        bytes_bwd = d.pop("bytes_bwd")

        bytes_fwd = d.pop("bytes_fwd")

        bytes_per_pkt_bwd = d.pop("bytes_per_pkt_bwd")

        bytes_per_pkt_fwd = d.pop("bytes_per_pkt_fwd")

        bytes_per_pkt_gap = d.pop("bytes_per_pkt_gap")

        bytes_total = d.pop("bytes_total")

        crosses_file_boundary = d.pop("crosses_file_boundary")

        duration = d.pop("duration")

        fin_count_bwd = d.pop("fin_count_bwd")

        fin_count_fwd = d.pop("fin_count_fwd")

        fin_fraction = d.pop("fin_fraction")

        fin_ratio_bwd = d.pop("fin_ratio_bwd")

        fin_ratio_fwd = d.pop("fin_ratio_fwd")

        first_observed_dst_ip = d.pop("first_observed_dst_ip")

        first_observed_dst_port = d.pop("first_observed_dst_port")

        first_observed_src_ip = d.pop("first_observed_src_ip")

        first_observed_src_port = d.pop("first_observed_src_port")

        first_packet_ack = d.pop("first_packet_ack")

        first_packet_direction = d.pop("first_packet_direction")

        first_packet_syn = d.pop("first_packet_syn")

        first_packet_was_syn = d.pop("first_packet_was_syn")

        first_packet_was_syn_ack = d.pop("first_packet_was_syn_ack")

        first_source_file = d.pop("first_source_file")

        def _parse_first_timeframe_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        first_timeframe_id = _parse_first_timeframe_id(d.pop("first_timeframe_id"))

        flow_end_time = d.pop("flow_end_time")

        flow_id = d.pop("flow_id")

        flow_initiator = d.pop("flow_initiator")

        flow_segment_id = d.pop("flow_segment_id")

        flow_start_time = d.pop("flow_start_time")

        def _parse_fwd_bps(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        fwd_bps = _parse_fwd_bps(d.pop("fwd_Bps"))

        def _parse_fwd_pps(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        fwd_pps = _parse_fwd_pps(d.pop("fwd_pps"))

        def _parse_fwd_share_bytes(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        fwd_share_bytes = _parse_fwd_share_bytes(d.pop("fwd_share_bytes"))

        def _parse_fwd_share_pkts(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        fwd_share_pkts = _parse_fwd_share_pkts(d.pop("fwd_share_pkts"))

        iat_int_count = d.pop("iat_int_count")

        iat_max_int_ns = d.pop("iat_max_int_ns")

        iat_min_int_ns = d.pop("iat_min_int_ns")

        iat_std_int_ns = d.pop("iat_std_int_ns")

        initiator_confidence = check_initiator_confidence(d.pop("initiator_confidence"))

        ip_a = d.pop("ip_a")

        ip_b = d.pop("ip_b")

        last_source_file = d.pop("last_source_file")

        def _parse_last_timeframe_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        last_timeframe_id = _parse_last_timeframe_id(d.pop("last_timeframe_id"))

        def _parse_latency_max(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        latency_max = _parse_latency_max(d.pop("latency_max"))

        def _parse_latency_min(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        latency_min = _parse_latency_min(d.pop("latency_min"))

        def _parse_latency_std(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        latency_std = _parse_latency_std(d.pop("latency_std"))

        def _parse_mean_hop_count(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        mean_hop_count = _parse_mean_hop_count(d.pop("mean_hop_count"))

        def _parse_mean_hop_latency(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        mean_hop_latency = _parse_mean_hop_latency(d.pop("mean_hop_latency"))

        mean_iat_int_ns = d.pop("mean_iat_int_ns")

        def _parse_mean_pkt_size(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        mean_pkt_size = _parse_mean_pkt_size(d.pop("mean_pkt_size"))

        def _parse_pkt_size_max(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        pkt_size_max = _parse_pkt_size_max(d.pop("pkt_size_max"))

        def _parse_pkt_size_min(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        pkt_size_min = _parse_pkt_size_min(d.pop("pkt_size_min"))

        def _parse_pkt_size_std(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        pkt_size_std = _parse_pkt_size_std(d.pop("pkt_size_std"))

        pkts_bwd = d.pop("pkts_bwd")

        pkts_fwd = d.pop("pkts_fwd")

        pkts_total = d.pop("pkts_total")

        port_a = d.pop("port_a")

        port_b = d.pop("port_b")

        proto = d.pop("proto")

        psh_count_bwd = d.pop("psh_count_bwd")

        psh_count_fwd = d.pop("psh_count_fwd")

        psh_fraction = d.pop("psh_fraction")

        psh_ratio_bwd = d.pop("psh_ratio_bwd")

        psh_ratio_fwd = d.pop("psh_ratio_fwd")

        def _parse_queue_occupancy_max(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        queue_occupancy_max = _parse_queue_occupancy_max(d.pop("queue_occupancy_max"))

        def _parse_queue_occupancy_mean(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        queue_occupancy_mean = _parse_queue_occupancy_mean(d.pop("queue_occupancy_mean"))

        def _parse_queue_occupancy_std(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        queue_occupancy_std = _parse_queue_occupancy_std(d.pop("queue_occupancy_std"))

        rst_count_bwd = d.pop("rst_count_bwd")

        rst_count_fwd = d.pop("rst_count_fwd")

        rst_fraction = d.pop("rst_fraction")

        rst_ratio_bwd = d.pop("rst_ratio_bwd")

        rst_ratio_fwd = d.pop("rst_ratio_fwd")

        small_pkt_fraction_total = d.pop("small_pkt_fraction_total")

        source_file_count = d.pop("source_file_count")

        syn_ack_gap = d.pop("syn_ack_gap")

        syn_count_bwd = d.pop("syn_count_bwd")

        syn_count_fwd = d.pop("syn_count_fwd")

        syn_fraction = d.pop("syn_fraction")

        syn_ratio_bwd = d.pop("syn_ratio_bwd")

        syn_ratio_fwd = d.pop("syn_ratio_fwd")

        termination_reason = check_termination_reason(d.pop("termination_reason"))

        def _parse_timeframe_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        timeframe_id = _parse_timeframe_id(d.pop("timeframe_id"))

        tiny_pkt_fraction_total = d.pop("tiny_pkt_fraction_total")

        def _parse_total_bps(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        total_bps = _parse_total_bps(d.pop("total_Bps"))

        def _parse_total_pps(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        total_pps = _parse_total_pps(d.pop("total_pps"))

        def _parse_truncated_ip_fraction(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        truncated_ip_fraction = _parse_truncated_ip_fraction(d.pop("truncated_ip_fraction"))

        def _parse_truncated_udp_fraction(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        truncated_udp_fraction = _parse_truncated_udp_fraction(d.pop("truncated_udp_fraction"))

        urg_count_bwd = d.pop("urg_count_bwd")

        urg_count_fwd = d.pop("urg_count_fwd")

        urg_fraction = d.pop("urg_fraction")

        urg_ratio_bwd = d.pop("urg_ratio_bwd")

        urg_ratio_fwd = d.pop("urg_ratio_fwd")

        flow = cls(
            ack_count_bwd=ack_count_bwd,
            ack_count_fwd=ack_count_fwd,
            ack_fraction=ack_fraction,
            ack_ratio_bwd=ack_ratio_bwd,
            ack_ratio_fwd=ack_ratio_fwd,
            base_flow_key=base_flow_key,
            bwd_bps=bwd_bps,
            bwd_pps=bwd_pps,
            bytes_bwd=bytes_bwd,
            bytes_fwd=bytes_fwd,
            bytes_per_pkt_bwd=bytes_per_pkt_bwd,
            bytes_per_pkt_fwd=bytes_per_pkt_fwd,
            bytes_per_pkt_gap=bytes_per_pkt_gap,
            bytes_total=bytes_total,
            crosses_file_boundary=crosses_file_boundary,
            duration=duration,
            fin_count_bwd=fin_count_bwd,
            fin_count_fwd=fin_count_fwd,
            fin_fraction=fin_fraction,
            fin_ratio_bwd=fin_ratio_bwd,
            fin_ratio_fwd=fin_ratio_fwd,
            first_observed_dst_ip=first_observed_dst_ip,
            first_observed_dst_port=first_observed_dst_port,
            first_observed_src_ip=first_observed_src_ip,
            first_observed_src_port=first_observed_src_port,
            first_packet_ack=first_packet_ack,
            first_packet_direction=first_packet_direction,
            first_packet_syn=first_packet_syn,
            first_packet_was_syn=first_packet_was_syn,
            first_packet_was_syn_ack=first_packet_was_syn_ack,
            first_source_file=first_source_file,
            first_timeframe_id=first_timeframe_id,
            flow_end_time=flow_end_time,
            flow_id=flow_id,
            flow_initiator=flow_initiator,
            flow_segment_id=flow_segment_id,
            flow_start_time=flow_start_time,
            fwd_bps=fwd_bps,
            fwd_pps=fwd_pps,
            fwd_share_bytes=fwd_share_bytes,
            fwd_share_pkts=fwd_share_pkts,
            iat_int_count=iat_int_count,
            iat_max_int_ns=iat_max_int_ns,
            iat_min_int_ns=iat_min_int_ns,
            iat_std_int_ns=iat_std_int_ns,
            initiator_confidence=initiator_confidence,
            ip_a=ip_a,
            ip_b=ip_b,
            last_source_file=last_source_file,
            last_timeframe_id=last_timeframe_id,
            latency_max=latency_max,
            latency_min=latency_min,
            latency_std=latency_std,
            mean_hop_count=mean_hop_count,
            mean_hop_latency=mean_hop_latency,
            mean_iat_int_ns=mean_iat_int_ns,
            mean_pkt_size=mean_pkt_size,
            pkt_size_max=pkt_size_max,
            pkt_size_min=pkt_size_min,
            pkt_size_std=pkt_size_std,
            pkts_bwd=pkts_bwd,
            pkts_fwd=pkts_fwd,
            pkts_total=pkts_total,
            port_a=port_a,
            port_b=port_b,
            proto=proto,
            psh_count_bwd=psh_count_bwd,
            psh_count_fwd=psh_count_fwd,
            psh_fraction=psh_fraction,
            psh_ratio_bwd=psh_ratio_bwd,
            psh_ratio_fwd=psh_ratio_fwd,
            queue_occupancy_max=queue_occupancy_max,
            queue_occupancy_mean=queue_occupancy_mean,
            queue_occupancy_std=queue_occupancy_std,
            rst_count_bwd=rst_count_bwd,
            rst_count_fwd=rst_count_fwd,
            rst_fraction=rst_fraction,
            rst_ratio_bwd=rst_ratio_bwd,
            rst_ratio_fwd=rst_ratio_fwd,
            small_pkt_fraction_total=small_pkt_fraction_total,
            source_file_count=source_file_count,
            syn_ack_gap=syn_ack_gap,
            syn_count_bwd=syn_count_bwd,
            syn_count_fwd=syn_count_fwd,
            syn_fraction=syn_fraction,
            syn_ratio_bwd=syn_ratio_bwd,
            syn_ratio_fwd=syn_ratio_fwd,
            termination_reason=termination_reason,
            timeframe_id=timeframe_id,
            tiny_pkt_fraction_total=tiny_pkt_fraction_total,
            total_bps=total_bps,
            total_pps=total_pps,
            truncated_ip_fraction=truncated_ip_fraction,
            truncated_udp_fraction=truncated_udp_fraction,
            urg_count_bwd=urg_count_bwd,
            urg_count_fwd=urg_count_fwd,
            urg_fraction=urg_fraction,
            urg_ratio_bwd=urg_ratio_bwd,
            urg_ratio_fwd=urg_ratio_fwd,
        )

        flow.additional_properties = d
        return flow

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
