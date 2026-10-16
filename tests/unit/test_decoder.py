"""
Tests for the INT telemetry decoder.

The golden frame is frame 0 of ``samples/student_sample_50000.pcap``. Its
expected values were confirmed independently by running the Wireshark Lua
dissector (``tools/wireshark/int_extension_fullframe_v7.lua``) in tshark 4.2.5
over the same file; ``scripts/non-interactive/check-lua-parity.sh`` repeats that
comparison for every frame.
"""

import random

import pytest

from ciara_pcap_manager_prototype.telemetry.decoder import (
    SkipReason,
    decode_frame,
)
from ciara_pcap_manager_prototype.telemetry.layers import DecodedPacket
from tests.support.pcap_factory import (
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    TH_ACK,
    TH_PSH,
    Hop,
    ethernet,
    int_header,
    ipv4,
    tcp,
    tcp_report,
    telemetry_frame,
    udp,
    udp_report,
)

GOLDEN_FRAME = bytes.fromhex(
    "5a72d5def69e765d7e174cf18100001508004500014f000040004011febd5e08"
    "38330aec99b91772170c013b00001400004000000018ad5de3cedb500d3a5a94"
    "d5852798ca285288e9e0810001f50800455c052e15af40003e06b3f1cb3176e1"
    "bb54706601bb3906ade42d94de5489a650180119000000000100090010000609"
    "fc0000000000001800180012ffffffff00000015db500525db500b2900000000"
).ljust(357, b"\x00")


def decoded(frame: bytes) -> DecodedPacket:
    """Decode a frame that must decode."""
    result = decode_frame(frame)
    assert isinstance(result, DecodedPacket), result
    return result


def test_golden_frame_outer_envelope() -> None:
    packet = decoded(GOLDEN_FRAME)

    assert packet.outer.vlan_ids == (21,)
    assert (packet.outer.src_ip, packet.outer.src_port) == ("94.8.56.51", 6002)
    assert (packet.outer.dst_ip, packet.outer.dst_port) == ("10.236.153.185", 5900)


def test_golden_frame_report_header() -> None:
    report = decoded(GOLDEN_FRAME).report

    assert report.version == 1
    assert report.length_bytes == 16
    assert report.next_proto == 0  # Ethernet follows
    # Flag byte 0x40 is F (tracked flow) in the v1.0 layout; the Lua calls it Q.
    assert (report.drop, report.queue, report.flow) == (False, False, True)
    assert report.rep_md_bits == 0
    assert report.hw_id == 0
    assert report.switch_id == 0x18
    assert report.sequence_number == 0xAD5DE3CE
    assert report.ingress_timestamp == 0xDB500D3A


def test_golden_frame_inner_packet() -> None:
    inner = decoded(GOLDEN_FRAME).inner

    assert inner.vlan_ids == (501,)
    assert (inner.src_ip, inner.src_port) == ("203.49.118.225", 443)
    assert (inner.dst_ip, inner.dst_port) == ("187.84.112.102", 14598)
    assert inner.ip_proto == IP_PROTO_TCP
    assert inner.ip_total_length == 1326
    assert inner.ip_captured_bytes == 277
    assert inner.tcp_flags == TH_PSH | TH_ACK
    assert inner.tcp_data_offset == 5


def test_golden_frame_int_stack() -> None:
    telemetry = decoded(GOLDEN_FRAME).int_telemetry
    assert telemetry is not None

    assert telemetry.shim.type == 1
    assert telemetry.shim.length_words == 9
    assert telemetry.metadata.version == 1
    assert telemetry.metadata.hop_ml_words == 6
    assert telemetry.metadata.remaining_hop_count == 9
    assert telemetry.metadata.instruction_bitmap == 0xFC
    assert telemetry.declared_stack_bytes == 24
    assert len(telemetry.hops) == 1

    hop = telemetry.hops[0]
    assert hop.switch_id == 0x18
    assert (hop.ingress_port, hop.egress_port) == (24, 18)
    assert hop.raw_hop_latency == 0xFFFFFFFF
    assert (hop.queue_id, hop.queue_occupancy) == (0, 21)
    assert hop.ingress_timestamp == 0xDB500525
    assert hop.egress_timestamp == 0xDB500B29
    # Egress minus ingress replaces the on-wire 0xFFFFFFFF, as in the Lua.
    assert hop.hop_latency == 1540


def test_udp_inner_packet_reports_its_declared_and_captured_length() -> None:
    packet = decoded(udp_report("10.0.0.1", 5353, "10.0.0.2", 53, size=120))

    assert packet.inner.ip_proto == IP_PROTO_UDP
    assert packet.inner.udp_length == 100
    assert packet.inner.udp_captured_bytes == 8 + 36
    assert packet.inner.tcp_flags == 0
    assert packet.int_telemetry is not None


def test_int_is_found_after_20_tcp_bytes_whatever_the_data_offset() -> None:
    packet = decoded(tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK, data_offset=8))

    assert packet.inner.tcp_data_offset == 8
    assert packet.int_telemetry is not None
    assert len(packet.int_telemetry.hops) == 1


def test_outer_length_fields_do_not_bound_the_frame() -> None:
    # The factory leaves outer IPv4/UDP lengths covering only their headers.
    packet = decoded(tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK))

    assert packet.int_telemetry is not None


def test_several_hops_are_decoded_in_stack_order() -> None:
    hops = [Hop(switch_id=1), Hop(switch_id=2), Hop(switch_id=3)]
    packet = decoded(tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK, hops=hops))

    assert packet.int_telemetry is not None
    assert [hop.switch_id for hop in packet.int_telemetry.hops] == [1, 2, 3]


def test_latency_wraps_around_the_32_bit_counter() -> None:
    hop = Hop(ingress_ts=0xFFFFFF00, egress_ts=0x00000010)
    packet = decoded(tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK, hops=[hop]))

    assert packet.int_telemetry is not None
    assert packet.int_telemetry.hops[0].hop_latency == 0x110


def test_wire_latency_is_kept_without_both_timestamps() -> None:
    instructions = 0xA0  # switch id and hop latency only
    payload = tcp(1, 2, TH_ACK) + int_header(
        [Hop(switch_id=7, hop_latency=900)], instructions=instructions
    )
    frame = telemetry_frame(
        ethernet(ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, payload))
    )
    telemetry = decoded(frame).int_telemetry

    assert telemetry is not None
    hop = telemetry.hops[0]
    assert (hop.switch_id, hop.hop_latency, hop.raw_hop_latency) == (7, 900, 900)
    assert hop.ingress_timestamp is None
    assert hop.queue_occupancy is None


def test_hops_stop_when_instructions_need_more_words_than_hop_ml() -> None:
    payload = tcp(1, 2, TH_ACK) + int_header([Hop()], hop_ml=4)
    frame = telemetry_frame(
        ethernet(ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, payload))
    )
    telemetry = decoded(frame).int_telemetry

    assert telemetry is not None
    assert telemetry.hops == ()


def test_a_zero_hop_ml_yields_no_hops() -> None:
    payload = tcp(1, 2, TH_ACK) + int_header([], hop_ml=0, shim_length=9)
    frame = telemetry_frame(
        ethernet(ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, payload))
    )
    telemetry = decoded(frame).int_telemetry

    assert telemetry is not None
    assert telemetry.hops == ()


def test_the_stack_is_capped_at_the_captured_bytes() -> None:
    full = tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK, hops=[Hop(), Hop()])
    telemetry = decoded(full[:-10]).int_telemetry

    assert telemetry is not None
    assert telemetry.declared_stack_bytes == 48
    assert telemetry.captured_stack_bytes == 38
    assert len(telemetry.hops) == 1


def test_a_shim_shorter_than_three_words_means_no_int() -> None:
    payload = tcp(1, 2, TH_ACK) + int_header([Hop()], shim_length=2)
    frame = telemetry_frame(
        ethernet(ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, payload))
    )

    assert decoded(frame).int_telemetry is None


def test_a_packet_without_int_bytes_still_decodes() -> None:
    inner = ethernet(ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_UDP, udp(1, 2)))
    packet = decoded(telemetry_frame(inner))

    assert packet.int_telemetry is None
    assert packet.inner.src_port == 1


def test_ip_options_move_the_l4_header() -> None:
    payload = tcp(1234, 80, TH_ACK) + int_header([Hop()])
    ip = ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, payload, options=b"\x01" * 8)
    packet = decoded(telemetry_frame(ethernet(ip)))

    assert (packet.inner.src_port, packet.inner.dst_port) == (1234, 80)
    assert packet.int_telemetry is not None


def test_stacked_vlan_tags_are_walked() -> None:
    payload = udp(1, 2) + int_header([Hop()])
    inner = ethernet(
        ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_UDP, payload), vlans=(10, 20)
    )

    assert decoded(telemetry_frame(inner)).inner.vlan_ids == (10, 20)


def test_the_telemetry_port_is_configurable() -> None:
    frame = telemetry_frame(
        ethernet(ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_UDP, udp(1, 2))), outer_port=9555
    )

    assert decode_frame(frame) is SkipReason.NOT_TELEMETRY_PORT
    assert isinstance(decode_frame(frame, telemetry_port=9555), DecodedPacket)


@pytest.mark.parametrize(
    ("frame", "reason"),
    [
        (b"\x00" * 10, SkipReason.OUTER_TRUNCATED),
        (ethernet(b"")[:-2] + b"\x86\xdd" + b"\x00" * 40, SkipReason.OUTER_NOT_IPV4),
        (
            ethernet(ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_TCP, b"\x00" * 40)),
            SkipReason.OUTER_NOT_UDP,
        ),
        (
            ethernet(ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_UDP, udp(1, 53))),
            SkipReason.NOT_TELEMETRY_PORT,
        ),
        (
            ethernet(
                ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_UDP, udp(1, 5900) + b"\x00" * 20)
            ),
            SkipReason.REPORT_TRUNCATED,
        ),
        (
            telemetry_frame(ethernet(b"")[:-2] + b"\x86\xdd" + b"\x00" * 40),
            SkipReason.INNER_NOT_IPV4,
        ),
        (
            telemetry_frame(ethernet(ipv4("1.1.1.1", "2.2.2.2", 1, b"\x08\x00"))),
            SkipReason.INNER_NOT_TCP_UDP,
        ),
        (
            telemetry_frame(
                ethernet(ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_TCP, b"\x00" * 10))
            ),
            SkipReason.INNER_L4_TRUNCATED,
        ),
        (telemetry_frame(ethernet(b"")), SkipReason.INNER_TRUNCATED),
    ],
)
def test_each_skip_reason(frame: bytes, reason: SkipReason) -> None:
    assert decode_frame(frame) is reason


def test_every_truncation_of_a_valid_frame_is_handled() -> None:
    frame = tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK, hops=[Hop(), Hop()])

    for length in range(len(frame) + 1):
        result = decode_frame(frame[:length])
        assert isinstance(result, DecodedPacket | SkipReason)


def test_random_bytes_never_raise() -> None:
    rng = random.Random(20261015)  # noqa: S311 - reproducible fuzzing, not cryptography
    template = bytearray(tcp_report("10.0.0.1", 1, "10.0.0.2", 2, TH_ACK))
    for _ in range(3000):
        mutated = bytearray(template)
        for _ in range(rng.randint(1, 12)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        cut = rng.randint(0, len(mutated))
        assert isinstance(
            decode_frame(bytes(mutated[:cut])), DecodedPacket | SkipReason
        )


def test_report_flags_follow_the_v1_0_bit_layout() -> None:
    frame = bytearray(GOLDEN_FRAME)
    # Word 0 of the report: Ver=1 Len=4 | NProt=0, RepMdBits=0b100001 | D | Q, hw_id=5
    frame[46:50] = bytes([0x14, 0b0001_0000, 0b1000_0001, 0b1000_0101])
    report = decoded(bytes(frame)).report

    assert report.rep_md_bits == 0b100001
    assert (report.drop, report.queue, report.flow) == (True, True, False)
    assert report.hw_id == 5
