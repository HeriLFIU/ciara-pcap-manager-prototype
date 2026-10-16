"""
End-to-end checks against the bundled 50,000-packet collector capture.

The expected numbers below are regression values. The decoder that produces
them was cross-checked field by field against the Wireshark Lua dissector
(``scripts/non-interactive/check-lua-parity.sh``: 0 mismatches over 50,000
frames). If a deliberate change to the flow logic moves one of them, update it
in the same commit and say why in the commit message.
"""

import hashlib
import io
from pathlib import Path

import pytest

from ciara_pcap_manager_prototype.flows.export import write_flows_csv
from ciara_pcap_manager_prototype.pcap.extractor import (
    ExtractionResult,
    PcapExtractionError,
    extract_flows,
)
from ciara_pcap_manager_prototype.pcap.runner import FlowExtractionRunner
from tests.support.pcap_factory import SAMPLE_EXPECTED, build_sample_capture

SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "student_sample_50000.pcap"

#: SHA-256 of the full codebook CSV export of the sample.
CSV_SHA256 = "1b04f7229708f284f3f154394fdc1e9049a76995d4ed74359b7bf232a4adcc1a"


@pytest.fixture(scope="module")
def result() -> ExtractionResult:
    """The sample, extracted once for the whole module."""
    return extract_flows(SAMPLE)


def test_every_frame_is_an_int_report_with_a_decodable_inner_packet(
    result: ExtractionResult,
) -> None:
    report = result.report

    assert report.frames_read == 50_000
    assert report.inner_packets == 50_000
    assert report.packets_with_int == report.packets_with_int_hops == 50_000
    assert report.skipped == {}


def test_interleaved_report_streams_are_reordered(result: ExtractionResult) -> None:
    assert result.report.packets_out_of_order == 22_220
    assert result.report.packets_late == 0


def test_flow_totals(result: ExtractionResult) -> None:
    flows = result.flows

    assert len(flows) == 15_458
    assert sum(flow.pkts_total for flow in flows) == 50_000
    assert sum(1 for flow in flows if flow.proto == 6) == 10_383
    assert sum(1 for flow in flows if flow.proto == 17) == 5_075
    reasons = {flow.termination_reason.value for flow in flows}
    assert reasons == {"end_of_input", "tcp_rst", "tcp_fin_both"}


def test_no_flow_is_built_from_the_outer_envelope(result: ExtractionResult) -> None:
    collector_ports = {5900, 6000, 6001, 6002}
    outer_addresses = {
        "10.236.153.185",
        "10.236.153.180",
        "94.8.56.51",
        "204.207.103.137",
    }

    for flow in result.flows:
        assert {flow.port_a, flow.port_b} != {6002, 5900}
        assert not ({flow.port_a, flow.port_b} <= collector_ports)
        assert flow.ip_b not in outer_addresses or flow.port_b not in collector_ports


def test_the_largest_flow(result: ExtractionResult) -> None:
    flow = max(result.flows, key=lambda candidate: candidate.bytes_total)

    assert flow.flow_id == "6|30.61.41.32|176.47.15.163|443|59976|0"
    assert (flow.pkts_fwd, flow.pkts_bwd) == (254, 66)
    assert (flow.bytes_fwd, flow.bytes_bwd) == (385_259, 6_000)
    assert flow.iat_int_count == 319
    assert (flow.latency_min, flow.latency_max) == (1_332, 1_494)
    assert flow.queue_occupancy_max == 35
    assert flow.truncated_ip_fraction == 1.0


def test_the_csv_export_is_stable(result: ExtractionResult) -> None:
    stream = io.StringIO()
    write_flows_csv(result.flows, stream)

    digest = hashlib.sha256(stream.getvalue().encode("utf-8")).hexdigest()
    assert digest == CSV_SHA256


async def test_the_runner_extracts_in_a_worker_process(tmp_path: Path) -> None:
    capture = build_sample_capture(tmp_path / "synthetic.pcap")
    runner = FlowExtractionRunner(max_workers=1, timeout_seconds=120)

    result = await runner.extract(capture, source_name="upload.pcap")

    assert len(result.flows) == SAMPLE_EXPECTED.flows
    assert {flow.first_source_file for flow in result.flows} == {"upload.pcap"}
    runner.shutdown()


async def test_the_runner_turns_a_worker_failure_into_an_error(tmp_path: Path) -> None:
    runner = FlowExtractionRunner(max_workers=1, timeout_seconds=120)

    with pytest.raises(PcapExtractionError, match="does not exist"):
        await runner.extract(tmp_path / "absent.pcap")


async def test_the_runner_enforces_its_timeout(tmp_path: Path) -> None:
    capture = build_sample_capture(tmp_path / "synthetic.pcap")
    runner = FlowExtractionRunner(max_workers=1, timeout_seconds=0.01)

    with pytest.raises(PcapExtractionError, match="exceeded"):
        await runner.extract(capture)
