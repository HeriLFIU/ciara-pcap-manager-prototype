"""Tests for the extraction pipeline on the synthetic INT capture."""

from pathlib import Path

import pytest

from ciara_pcap_manager_prototype.domain.flows import TerminationReason
from ciara_pcap_manager_prototype.pcap.extractor import (
    ExtractionOptions,
    PcapExtractionError,
    extract_flows,
)
from tests.support.pcap_factory import (
    CLIENT,
    PEER,
    RESOLVER,
    SAMPLE_EXPECTED,
    SERVER,
    build_sample_capture,
)


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    """The synthetic sample, written fresh for each test."""
    return build_sample_capture(tmp_path / "synthetic.pcap")


def test_the_decode_report_accounts_for_every_frame(sample: Path) -> None:
    report = extract_flows(sample).report

    assert report.frames_read == SAMPLE_EXPECTED.frames
    assert report.inner_packets == SAMPLE_EXPECTED.inner_packets
    assert (
        report.packets_with_int == report.packets_with_int_hops == report.inner_packets
    )
    assert report.skipped == dict(SAMPLE_EXPECTED.skipped)
    assert report.packets_out_of_order == SAMPLE_EXPECTED.out_of_order
    assert report.packets_late == 0
    assert report.packets_over_flow_cap == 0


def test_only_inner_packets_become_flows(sample: Path) -> None:
    flows = extract_flows(sample).flows
    endpoints = {flow.ip_a for flow in flows} | {flow.ip_b for flow in flows}

    assert len(flows) == SAMPLE_EXPECTED.flows
    assert endpoints == {CLIENT, SERVER, PEER, RESOLVER}
    assert sum(flow.pkts_total for flow in flows) == SAMPLE_EXPECTED.inner_packets


def test_each_conversation_ends_for_the_expected_reason(sample: Path) -> None:
    flows = extract_flows(sample).flows
    by_key = {(flow.proto, flow.ip_a, flow.flow_segment_id): flow for flow in flows}

    handshake = by_key[6, CLIENT, 0]
    assert handshake.termination_reason is TerminationReason.TCP_FIN_BOTH
    assert (handshake.pkts_fwd, handshake.pkts_bwd) == (4, 2)
    assert handshake.first_packet_was_syn == 1

    trailing_ack = by_key[6, SERVER, 1]
    assert trailing_ack.termination_reason is TerminationReason.END_OF_INPUT
    assert trailing_ack.pkts_total == 1

    reset = by_key[6, PEER, 0]
    assert reset.termination_reason is TerminationReason.TCP_RST


def test_the_late_udp_report_is_put_back_in_time_order(sample: Path) -> None:
    (udp,) = [flow for flow in extract_flows(sample).flows if flow.proto == 17]

    assert (udp.pkts_fwd, udp.pkts_bwd) == (2, 1)
    assert udp.iat_int_count == 2
    assert udp.mean_iat_int_ns == pytest.approx(5_000_000)
    assert udp.iat_std_int_ns == 0.0


def test_without_reordering_the_late_report_wraps_into_a_huge_int_gap(
    sample: Path,
) -> None:
    options = ExtractionOptions(reorder_window_seconds=0)
    (udp,) = [
        flow
        for flow in extract_flows(sample, options=options).flows
        if flow.proto == 17
    ]

    # File order is 20 ms, 30 ms, 25 ms: the -5 ms step wraps modulo 2**32.
    assert udp.iat_min_int_ns == pytest.approx(10_000_000)
    assert udp.iat_max_int_ns == pytest.approx(2**32 - 5_000_000)


def test_the_source_name_sets_provenance(sample: Path) -> None:
    flows = extract_flows(sample, source_name="2026-10-15_capture.pcap").flows

    assert {flow.first_source_file for flow in flows} == {"2026-10-15_capture.pcap"}
    assert {flow.timeframe_id for flow in flows} == {"2026-10-15_capture"}


def test_the_flow_cap_is_reported(sample: Path) -> None:
    result = extract_flows(sample, options=ExtractionOptions(max_flows=1))

    assert len(result.flows) == 1
    assert result.report.packets_over_flow_cap > 0


def test_a_missing_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(PcapExtractionError, match="does not exist"):
        extract_flows(tmp_path / "absent.pcap")


def test_a_file_that_is_not_a_capture_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "notes.pcap"
    path.write_text("hello", encoding="utf-8")

    with pytest.raises(PcapExtractionError, match="not a libpcap or pcapng"):
        extract_flows(path)


def test_a_capture_of_another_link_type_skips_every_frame(
    sample: Path, tmp_path: Path
) -> None:
    raw = bytearray(sample.read_bytes())
    raw[20:24] = (101).to_bytes(4, "little")  # LINKTYPE_RAW
    other = tmp_path / "raw.pcap"
    other.write_bytes(bytes(raw))

    result = extract_flows(other)

    assert result.flows == []
    assert result.report.skipped == {"unsupported_link_type": SAMPLE_EXPECTED.frames}
