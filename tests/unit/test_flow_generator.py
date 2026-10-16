"""Tests for flow keys, segmentation, termination reasons and reordering."""

import pytest

from ciara_pcap_manager_prototype.domain.flows import TerminationReason
from ciara_pcap_manager_prototype.flows.generator import FlowGenerator, base_flow_key
from ciara_pcap_manager_prototype.flows.packet import PacketRecord
from ciara_pcap_manager_prototype.flows.reorder import ReorderBuffer
from tests.support.factories import BASE_NS, make_packet, reply_to

SECOND = 1_000_000_000


def at(seconds: float, **overrides: object) -> PacketRecord:
    """A default packet at an offset from the base time."""
    return make_packet(packet_time_ns=BASE_NS + round(seconds * SECOND), **overrides)


def test_both_directions_share_one_key() -> None:
    packet = make_packet()

    assert base_flow_key(packet) == base_flow_key(reply_to(packet))
    assert base_flow_key(packet) == "6|10.0.0.1|93.184.216.34|5001|443"


def test_addresses_are_ordered_numerically_and_ports_stay_paired() -> None:
    packet = make_packet(
        inner_ip_src="10.0.0.20", src_port=1, inner_ip_dst="10.0.0.3", dst_port=2
    )

    # Numerically 10.0.0.3 < 10.0.0.20, although "10.0.0.20" < "10.0.0.3" as text.
    assert base_flow_key(packet) == "6|10.0.0.3|10.0.0.20|2|1"


def test_same_address_orders_by_port() -> None:
    packet = make_packet(
        inner_ip_src="10.0.0.1", src_port=9, inner_ip_dst="10.0.0.1", dst_port=3
    )

    assert base_flow_key(packet) == "6|10.0.0.1|10.0.0.1|3|9"


def test_tcp_and_udp_with_the_same_ports_are_different_flows() -> None:
    generator = FlowGenerator()
    generator.add(at(0))
    generator.add(at(0.1, inner_ip_proto=17))

    assert len(generator.finish()) == 2


def test_rst_closes_the_segment_on_the_rst_packet() -> None:
    generator = FlowGenerator()
    first = at(0)
    generator.add_all([first, reply_to(first, tcp_flag_rst=True), at(0.2)])

    flows = generator.finish()

    assert [flow.termination_reason for flow in flows] == [
        TerminationReason.TCP_RST,
        TerminationReason.END_OF_INPUT,
    ]
    assert [flow.flow_segment_id for flow in flows] == [0, 1]
    assert flows[0].pkts_total == 2
    assert flows[1].flow_id.endswith("|1")


def test_fin_from_both_sides_closes_the_segment() -> None:
    generator = FlowGenerator()
    first = at(0, tcp_flag_fin=True)
    generator.add_all([first, at(0.1), reply_to(first, tcp_flag_fin=True)])

    (flow,) = generator.finish()

    assert flow.termination_reason is TerminationReason.TCP_FIN_BOTH
    assert (flow.fin_count_fwd, flow.fin_count_bwd) == (1, 1)


def test_fin_from_one_side_only_keeps_the_segment_open() -> None:
    generator = FlowGenerator()
    generator.add_all([at(0, tcp_flag_fin=True), at(0.1, tcp_flag_fin=True)])

    (flow,) = generator.finish()

    assert flow.termination_reason is TerminationReason.END_OF_INPUT


def test_udp_ignores_tcp_flags_for_termination() -> None:
    generator = FlowGenerator()
    generator.add_all(
        [at(0, inner_ip_proto=17, tcp_flag_rst=True), at(0.1, inner_ip_proto=17)]
    )

    (flow,) = generator.finish()

    assert flow.pkts_total == 2


def test_an_idle_gap_starts_a_new_segment() -> None:
    generator = FlowGenerator(idle_timeout_seconds=1.0)
    generator.add_all([at(0), at(0.5), at(2.0)])

    flows = generator.finish()

    assert [flow.termination_reason for flow in flows] == [
        TerminationReason.INACTIVE_TIMEOUT,
        TerminationReason.END_OF_INPUT,
    ]
    assert [flow.pkts_total for flow in flows] == [2, 1]


def test_a_gap_equal_to_the_idle_timeout_does_not_split() -> None:
    generator = FlowGenerator(idle_timeout_seconds=1.0)
    generator.add_all([at(0), at(1.0)])

    assert len(generator.finish()) == 1


def test_quiet_segments_are_swept_as_inactive_while_time_advances() -> None:
    generator = FlowGenerator(idle_timeout_seconds=1.0)
    generator.add(at(0))
    generator.add(at(5.0, inner_ip_src="10.9.9.9"))

    reasons = {flow.ip_a: flow.termination_reason for flow in generator.finish()}

    assert reasons["10.0.0.1"] is TerminationReason.INACTIVE_TIMEOUT
    assert reasons["10.9.9.9"] is TerminationReason.END_OF_INPUT


def test_a_long_segment_is_cut_by_the_active_timeout() -> None:
    generator = FlowGenerator(idle_timeout_seconds=10.0, active_timeout_seconds=2.0)
    generator.add_all([at(t) for t in (0, 1, 2, 2.5, 3)])

    flows = generator.finish()

    assert [flow.termination_reason for flow in flows] == [
        TerminationReason.ACTIVE_TIMEOUT,
        TerminationReason.END_OF_INPUT,
    ]
    assert [flow.pkts_total for flow in flows] == [3, 2]


def test_the_flow_cap_drops_packets_of_new_flows_only() -> None:
    generator = FlowGenerator(max_flows=1)
    generator.add_all([at(0), at(0.1, src_port=7), at(0.2)])

    (flow,) = generator.finish()

    assert flow.pkts_total == 2
    assert generator.packets_over_cap == 1


def test_flows_are_returned_in_start_order() -> None:
    generator = FlowGenerator()
    generator.add_all([at(0.3, src_port=3), at(0.1, src_port=1), at(0.2, src_port=2)])

    assert [flow.port_a for flow in generator.finish()] == [1, 2, 3]


def test_reorder_buffer_restores_time_order_within_the_window() -> None:
    buffer = ReorderBuffer(window_seconds=1.0)
    times = [0.0, 0.5, 0.2, 1.6, 0.9, 3.0]
    released: list[float] = []
    for index, offset in enumerate(times):
        released += [
            (p.packet_time_ns - BASE_NS) / SECOND
            for p in buffer.push(at(offset, packet_index=index))
        ]
    released += [(p.packet_time_ns - BASE_NS) / SECOND for p in buffer.drain()]

    assert released == sorted(times)
    assert buffer.out_of_order == 2
    assert buffer.late == 0


def test_reorder_buffer_counts_packets_beyond_the_window_as_late() -> None:
    buffer = ReorderBuffer(window_seconds=0.1)
    times = [0.0, 1.0, 2.0, 0.5]
    released = [
        p.packet_index
        for i, t in enumerate(times)
        for p in buffer.push(at(t, packet_index=i))
    ]
    released += [p.packet_index for p in buffer.drain()]

    # 0.0 and 1.0 have left by the time 0.5 arrives, so 0.5 cannot be put back.
    assert released == [0, 1, 3, 2]
    assert buffer.late == 1


def test_a_lagging_packet_is_not_late_while_nothing_newer_has_left() -> None:
    buffer = ReorderBuffer(window_seconds=0.1)
    released = [
        p.packet_index
        for i, t in enumerate([0.0, 1.0, 0.5])
        for p in buffer.push(at(t, packet_index=i))
    ]
    released += [p.packet_index for p in buffer.drain()]

    assert released == [0, 2, 1]
    assert buffer.late == 0


def test_a_zero_window_keeps_file_order() -> None:
    buffer = ReorderBuffer(window_seconds=0)
    released = [
        p.packet_index
        for i, t in enumerate([0.5, 0.1, 0.9])
        for p in buffer.push(at(t, packet_index=i))
    ]

    assert released == [0, 1, 2]
    assert (buffer.out_of_order, buffer.late) == (1, 1)


def test_reordering_fixes_orientation_and_int_gaps() -> None:
    first = at(0.0, tcp_flag_syn=True, tcp_flag_ack=False, int_egress_timestamp=1_000)
    answer = reply_to(
        first,
        packet_time_ns=BASE_NS + SECOND // 100,
        packet_index=1,
        tcp_flag_syn=True,
        tcp_flag_ack=True,
        int_egress_timestamp=2_000,
    )
    buffer = ReorderBuffer(window_seconds=1.0)
    generator = FlowGenerator()
    for packet in (answer, first):  # the answer is read first, out of order
        generator.add_all(buffer.push(packet))
    generator.add_all(buffer.drain())

    (flow,) = generator.finish()

    assert flow.ip_a == "10.0.0.1"
    assert flow.first_packet_was_syn == 1
    assert flow.mean_iat_int_ns == pytest.approx(1_000)
