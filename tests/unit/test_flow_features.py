"""
Tests for the codebook features computed when a flow segment closes.

Each test names the codebook section whose rule it checks.
"""

import math
import statistics

import pytest

from ciara_pcap_manager_prototype.domain.flows import (
    Flow,
    InitiatorConfidence,
    TerminationReason,
)
from ciara_pcap_manager_prototype.flows.packet import PacketRecord, build_packet_record
from ciara_pcap_manager_prototype.flows.segment import FlowSegment, RunningStats
from ciara_pcap_manager_prototype.pcap.reader import Frame
from ciara_pcap_manager_prototype.telemetry.decoder import decode_frame
from ciara_pcap_manager_prototype.telemetry.layers import DecodedPacket
from tests.support.factories import BASE_NS, make_packet, reply_to
from tests.support.pcap_factory import TH_ACK, TH_SYN, Hop, tcp_report, udp_report

MS = 1_000_000


def close(*packets: PacketRecord) -> Flow:
    """Feed packets into one segment, oriented by the first, and close it."""
    segment = FlowSegment(base_flow_key="key", segment_id=0, first=packets[0])
    for packet in packets:
        segment.add(packet)
    return segment.to_flow(TerminationReason.END_OF_INPUT)


def record(frame: bytes, *, index: int = 0, time_ns: int = BASE_NS) -> PacketRecord:
    """Decode a frame into a packet row."""
    decoded = decode_frame(frame)
    assert isinstance(decoded, DecodedPacket)
    raw = Frame(
        index=index,
        timestamp_ns=time_ns,
        data=frame,
        original_length=len(frame),
        link_type=1,
    )
    return build_packet_record(raw, decoded, source_file="x.pcap", timeframe_id="x")


# -- Section 1: packet rows ---------------------------------------------------------


def test_tcp_rows_zero_the_udp_fields_and_flatten_the_first_hop() -> None:
    row = record(
        tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_SYN, size=60, data_offset=8)
    )

    assert row.l4_proto == "TCP"
    assert row.tcp_flag_syn
    assert not row.tcp_flag_ack
    assert (row.tcp_dataofs, row.tcp_header_len_bytes, row.tcp_options_len) == (
        8,
        32,
        12,
    )
    assert row.inner_udp_truncated_vs_declared is False
    assert row.inner_ip_len == row.inner_ip_total_length_declared == 60
    assert (row.int_ingress_timestamp, row.int_egress_timestamp) == (
        1_000_000,
        1_001_500,
    )
    assert row.int_queue_occupancy == 21
    assert row.int_path_latency == 1_500
    assert row.packet_uid == "x|x.pcap|0"
    assert row.direction == "unknown"


def test_udp_rows_zero_the_tcp_fields() -> None:
    row = record(udp_report("10.0.0.1", 1, "10.0.0.2", 2, size=500))

    assert row.l4_proto == "UDP"
    assert (row.tcp_dataofs, row.tcp_header_len_bytes, row.tcp_options_len) == (0, 0, 0)
    assert not any((row.tcp_flag_syn, row.tcp_flag_ack, row.tcp_flag_fin))
    assert row.inner_udp_truncated_vs_declared is True
    assert row.inner_ip_truncated_vs_declared is True


def test_path_latency_sums_hops_and_queue_keeps_every_hop() -> None:
    hops = [
        Hop(ingress_ts=0, egress_ts=100, queue_occupancy=5),
        Hop(ingress_ts=0, egress_ts=300, queue_occupancy=9),
    ]
    row = record(tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK, hops=hops))

    assert row.int_hop_count == 2
    assert row.int_path_latency == 400
    assert row.int_queue_observations == (5, 9)
    assert row.int_queue_occupancy == 5


def test_a_packet_without_hops_has_no_int_fields() -> None:
    row = record(tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK, hops=[]))

    assert row.int_hop_count == 0
    assert row.int_ingress_timestamp is None
    assert row.int_path_latency is None
    assert row.int_timestamp is None


def test_int_timestamp_prefers_egress_then_ingress() -> None:
    assert (
        make_packet(int_egress_timestamp=9, int_ingress_timestamp=5).int_timestamp == 9
    )
    assert (
        make_packet(int_egress_timestamp=None, int_ingress_timestamp=5).int_timestamp
        == 5
    )


# -- Sections 2, 3.1 and 3.2: identity, counts and rates -----------------------------


def test_orientation_comes_from_the_first_packet() -> None:
    first = make_packet(tcp_flag_syn=True, tcp_flag_ack=False)
    flow = close(first, reply_to(first, packet_index=1, packet_time_ns=BASE_NS + MS))

    assert (flow.ip_a, flow.port_a, flow.ip_b, flow.port_b) == (
        "10.0.0.1",
        5001,
        "93.184.216.34",
        443,
    )
    assert flow.first_observed_src_ip == flow.ip_a
    assert flow.first_observed_dst_port == flow.port_b
    assert (flow.pkts_fwd, flow.pkts_bwd) == (1, 1)
    assert flow.first_packet_direction == "fwd"
    assert flow.flow_initiator == "observed_first_packet_src"


def test_a_bare_syn_raises_initiator_confidence() -> None:
    syn = close(make_packet(tcp_flag_syn=True, tcp_flag_ack=False))
    syn_ack = close(make_packet(tcp_flag_syn=True, tcp_flag_ack=True))

    assert syn.initiator_confidence is InitiatorConfidence.TCP_SYN_NOACK_OBSERVED
    assert (syn.first_packet_was_syn, syn.first_packet_was_syn_ack) == (1, 0)
    assert syn_ack.initiator_confidence is InitiatorConfidence.OBSERVED_FIRST_PACKET
    assert (syn_ack.first_packet_was_syn, syn_ack.first_packet_was_syn_ack) == (0, 1)


def test_udp_is_never_a_syn() -> None:
    flow = close(make_packet(inner_ip_proto=17, tcp_flag_syn=True, tcp_flag_ack=False))

    assert flow.first_packet_was_syn == 0
    assert flow.initiator_confidence is InitiatorConfidence.OBSERVED_FIRST_PACKET


def test_counts_bytes_duration_and_rates() -> None:
    first = make_packet(inner_ip_len=100)
    flow = close(
        first,
        make_packet(
            packet_index=1, packet_time_ns=BASE_NS + 250 * MS, inner_ip_len=300
        ),
        reply_to(
            first, packet_index=2, packet_time_ns=BASE_NS + 500 * MS, inner_ip_len=600
        ),
    )

    assert (flow.pkts_fwd, flow.pkts_bwd, flow.pkts_total) == (2, 1, 3)
    assert (flow.bytes_fwd, flow.bytes_bwd, flow.bytes_total) == (400, 600, 1000)
    assert flow.duration == pytest.approx(0.5)
    assert flow.flow_end_time - flow.flow_start_time == pytest.approx(0.5)
    assert flow.fwd_pps == pytest.approx(4.0)
    assert flow.bwd_pps == pytest.approx(2.0)
    assert flow.total_pps == pytest.approx(6.0)
    assert flow.total_Bps == pytest.approx(2000.0)
    assert flow.fwd_Bps == pytest.approx(800.0)
    assert flow.bwd_Bps == pytest.approx(1200.0)


def test_zero_duration_rates_are_zero_not_blank() -> None:
    flow = close(make_packet())

    assert flow.duration == 0.0
    assert (flow.fwd_pps, flow.total_Bps, flow.bwd_pps) == (0.0, 0.0, 0.0)


def test_provenance_of_a_single_file() -> None:
    flow = close(make_packet())

    assert (flow.first_source_file, flow.last_source_file) == (
        "sample.pcap",
        "sample.pcap",
    )
    assert (flow.source_file_count, flow.crosses_file_boundary) == (1, 0)
    assert (
        flow.timeframe_id
        == flow.first_timeframe_id
        == flow.last_timeframe_id
        == "sample"
    )


def test_provenance_across_files() -> None:
    flow = close(
        make_packet(),
        make_packet(packet_index=1, source_file="next.pcap", timeframe_id="next"),
    )

    assert (flow.last_source_file, flow.source_file_count) == ("next.pcap", 2)
    assert flow.crosses_file_boundary == 1
    assert flow.last_timeframe_id == "next"


# -- Section 3.3: packet sizes ------------------------------------------------------


def test_packet_size_statistics_are_population_statistics() -> None:
    sizes = [40, 100, 1500, 60]
    flow = close(
        *(
            make_packet(packet_index=i, inner_ip_len=size)
            for i, size in enumerate(sizes)
        )
    )

    assert flow.mean_pkt_size == pytest.approx(statistics.fmean(sizes))
    assert flow.pkt_size_std == pytest.approx(statistics.pstdev(sizes))
    assert (flow.pkt_size_min, flow.pkt_size_max) == (40, 1500)


# -- Section 3.4: hops, INT inter-arrival, latency and queue -------------------


def test_int_iat_with_no_observation_is_numeric_zero() -> None:
    flow = close(make_packet())

    assert flow.iat_int_count == 0
    assert (flow.mean_iat_int_ns, flow.iat_std_int_ns) == (0.0, 0.0)
    assert (flow.iat_min_int_ns, flow.iat_max_int_ns) == (0.0, 0.0)


def test_int_iat_with_one_observation() -> None:
    flow = close(
        make_packet(int_egress_timestamp=1_000),
        make_packet(packet_index=1, int_egress_timestamp=4_000),
    )

    assert flow.iat_int_count == 1
    assert flow.mean_iat_int_ns == flow.iat_min_int_ns == flow.iat_max_int_ns == 3_000
    assert flow.iat_std_int_ns == 0.0


def test_int_iat_statistics_and_counter_wrap() -> None:
    stamps = [0xFFFFFF00, 0x00000100, 0x00000600]
    flow = close(
        *(
            make_packet(packet_index=i, int_egress_timestamp=t)
            for i, t in enumerate(stamps)
        )
    )

    assert flow.iat_int_count == 2
    assert (flow.iat_min_int_ns, flow.iat_max_int_ns) == (0x200, 0x500)
    assert flow.mean_iat_int_ns == pytest.approx(statistics.fmean([0x200, 0x500]))
    assert flow.iat_std_int_ns == pytest.approx(statistics.pstdev([0x200, 0x500]))


def test_int_iat_skips_packets_without_a_timestamp() -> None:
    flow = close(
        make_packet(int_egress_timestamp=1_000),
        make_packet(
            packet_index=1, int_egress_timestamp=None, int_ingress_timestamp=None
        ),
        make_packet(packet_index=2, int_egress_timestamp=1_500),
    )

    assert flow.iat_int_count == 1
    assert flow.mean_iat_int_ns == 500


def test_latency_hop_count_and_queue_statistics() -> None:
    flow = close(
        make_packet(
            int_path_latency=1_000, int_hop_count=1, int_queue_observations=(10,)
        ),
        make_packet(
            packet_index=1,
            int_path_latency=3_000,
            int_hop_count=2,
            int_queue_observations=(20, 30),
        ),
    )

    assert flow.mean_hop_count == pytest.approx(1.5)
    assert flow.mean_hop_latency == pytest.approx(2_000)
    assert (flow.latency_min, flow.latency_max) == (1_000, 3_000)
    assert flow.latency_std == pytest.approx(1_000)
    assert flow.queue_occupancy_mean == pytest.approx(20)
    assert flow.queue_occupancy_std == pytest.approx(statistics.pstdev([10, 20, 30]))
    assert flow.queue_occupancy_max == 30


def test_int_columns_are_blank_without_int() -> None:
    flow = close(
        make_packet(
            int_hop_count=0,
            int_path_latency=None,
            int_queue_observations=(),
            int_egress_timestamp=None,
            int_ingress_timestamp=None,
        )
    )

    assert flow.mean_hop_count is None
    assert flow.mean_hop_latency is None
    assert (flow.latency_min, flow.latency_max, flow.latency_std) == (None, None, None)
    assert flow.queue_occupancy_mean is None
    assert flow.queue_occupancy_max is None
    assert flow.iat_int_count == 0


# -- Sections 3.5 to 3.7: flags, directionality, quality ----------------------


def test_flag_counts_ratios_and_fractions() -> None:
    first = make_packet(tcp_flag_syn=True, tcp_flag_ack=False)
    flow = close(
        first,
        reply_to(first, packet_index=1, tcp_flag_syn=True, tcp_flag_ack=True),
        make_packet(packet_index=2, tcp_flag_ack=True, tcp_flag_psh=True),
    )

    assert (flow.syn_count_fwd, flow.syn_count_bwd) == (1, 1)
    assert (flow.ack_count_fwd, flow.ack_count_bwd) == (1, 1)
    assert flow.syn_ratio_fwd == pytest.approx(0.5)
    assert flow.syn_ratio_bwd == pytest.approx(1.0)
    assert flow.syn_fraction == pytest.approx(2 / 3)
    assert flow.psh_fraction == pytest.approx(1 / 3)
    assert flow.urg_fraction == 0.0
    assert flow.syn_ack_gap == 0


def test_backward_ratios_are_zero_without_backward_packets() -> None:
    flow = close(make_packet())

    assert flow.pkts_bwd == 0
    assert (flow.ack_ratio_bwd, flow.bytes_per_pkt_bwd) == (0.0, 0.0)
    assert flow.fwd_share_pkts == 1.0
    assert flow.fwd_share_bytes == 1.0


def test_directionality_and_size_fractions() -> None:
    first = make_packet(inner_ip_len=40)
    flow = close(
        first,
        make_packet(packet_index=1, inner_ip_len=100),
        reply_to(first, packet_index=2, inner_ip_len=1000),
        reply_to(first, packet_index=3, inner_ip_len=101),
    )

    assert flow.bytes_per_pkt_fwd == pytest.approx(70)
    assert flow.bytes_per_pkt_bwd == pytest.approx(550.5)
    assert flow.bytes_per_pkt_gap == pytest.approx(70 - 550.5)
    assert flow.small_pkt_fraction_total == pytest.approx(0.5)  # 40 and 100
    assert flow.tiny_pkt_fraction_total == pytest.approx(0.25)  # 40 only
    assert flow.fwd_share_pkts == pytest.approx(0.5)
    assert flow.fwd_share_bytes == pytest.approx(140 / 1241)


def test_truncation_fractions() -> None:
    flow = close(
        make_packet(inner_ip_truncated_vs_declared=True),
        make_packet(packet_index=1, inner_ip_truncated_vs_declared=False),
    )

    assert flow.truncated_ip_fraction == pytest.approx(0.5)
    assert flow.truncated_udp_fraction == 0.0


def test_running_stats_match_the_sum_of_squares_formula() -> None:
    values = [1.0e9 + delta for delta in (0.0, 3.0, 7.0, 11.0)]
    stats = RunningStats()
    for value in values:
        stats.add(value)

    assert stats.mean == pytest.approx(statistics.fmean(values))
    assert stats.std == pytest.approx(statistics.pstdev(values))
    assert math.isinf(RunningStats().minimum)
    assert RunningStats().std == 0.0
