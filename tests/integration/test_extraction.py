"""
End-to-end extraction against the real NFStream engine.

These are the only tests that load the native library and start worker
processes. They are marked ``capture_backend`` and skip themselves when the
platform packet-capture runtime is unavailable, so a machine without Npcap or
libpcap still gets a green suite.
"""

from pathlib import Path

import pytest

from ciara_pcap_manager_prototype.domain.flows import ExpirationReason
from ciara_pcap_manager_prototype.pcap.compat import ensure_capture_backend
from ciara_pcap_manager_prototype.pcap.extractor import (
    PcapExtractionError,
    extract_flows,
)
from ciara_pcap_manager_prototype.pcap.runner import FlowExtractionRunner
from tests.support.pcap_factory import build_sample_capture

pytestmark = pytest.mark.capture_backend

EXPECTED_FLOWS = 2
HTTP_PACKETS = 8
DNS_PACKETS = 2


def capture_backend_available() -> bool:
    """
    Report whether NFStream's native engine can be loaded here.

    Returns:
        True when ``import nfstream`` succeeds.

    """
    ensure_capture_backend()
    try:
        import nfstream  # noqa: F401, PLC0415  # pyright: ignore[reportMissingTypeStubs, reportUnusedImport]
    except ImportError:
        return False
    return True


requires_backend = pytest.mark.skipif(
    not capture_backend_available(),
    reason="No usable libpcap/Npcap runtime on this host",
)


@pytest.fixture
def sample_capture(tmp_path: Path) -> Path:
    """A capture holding one HTTP conversation and one DNS exchange."""
    return build_sample_capture(tmp_path / "sample.pcap")


@requires_backend
def test_extraction_produces_one_flow_per_conversation(sample_capture: Path) -> None:
    flows = extract_flows(sample_capture)

    assert len(flows) == EXPECTED_FLOWS
    assert {flow.protocol_name for flow in flows} == {"TCP", "UDP"}


@requires_backend
def test_bidirectional_counters_account_for_every_packet(
    sample_capture: Path,
) -> None:
    by_protocol = {flow.protocol_name: flow for flow in extract_flows(sample_capture)}

    http = by_protocol["TCP"]
    assert http.bidirectional_packets == HTTP_PACKETS
    assert http.src2dst_packets + http.dst2src_packets == HTTP_PACKETS
    assert http.bidirectional_bytes == http.src2dst_bytes + http.dst2src_bytes
    assert by_protocol["UDP"].bidirectional_packets == DNS_PACKETS


@requires_backend
def test_ndpi_identifies_the_applications(sample_capture: Path) -> None:
    labels = {flow.application_name for flow in extract_flows(sample_capture)}

    assert labels == {"HTTP", "DNS"}


@requires_backend
def test_the_server_name_is_lifted_out_of_the_payload(sample_capture: Path) -> None:
    names = {flow.requested_server_name for flow in extract_flows(sample_capture)}

    assert names == {"example.com"}


@requires_backend
def test_disabling_dissection_still_yields_flows(sample_capture: Path) -> None:
    flows = extract_flows(sample_capture, n_dissections=0)

    assert len(flows) == EXPECTED_FLOWS


@requires_backend
def test_the_flow_cap_is_honoured(sample_capture: Path) -> None:
    flows = extract_flows(sample_capture, max_flows=1)

    assert len(flows) == 1


@requires_backend
def test_every_flow_carries_a_named_expiration_reason(sample_capture: Path) -> None:
    reasons = {flow.expiration_reason for flow in extract_flows(sample_capture)}

    assert reasons <= set(ExpirationReason)
    assert ExpirationReason.UNKNOWN not in reasons


def test_a_missing_capture_is_reported_before_nfstream_is_loaded(
    tmp_path: Path,
) -> None:
    with pytest.raises(PcapExtractionError, match="does not exist"):
        extract_flows(tmp_path / "absent.pcap")


@requires_backend
async def test_the_runner_extracts_in_a_worker_process(sample_capture: Path) -> None:
    runner = FlowExtractionRunner(max_workers=1, timeout_seconds=120)

    flows = await runner.extract(sample_capture)

    assert len(flows) == EXPECTED_FLOWS


@requires_backend
async def test_the_runner_turns_a_worker_failure_into_an_error(
    tmp_path: Path,
) -> None:
    runner = FlowExtractionRunner(max_workers=1, timeout_seconds=120)

    with pytest.raises(PcapExtractionError):
        await runner.extract(tmp_path / "absent.pcap")


@requires_backend
async def test_the_runner_enforces_its_timeout(sample_capture: Path) -> None:
    runner = FlowExtractionRunner(max_workers=1, timeout_seconds=0.01)

    with pytest.raises(PcapExtractionError, match="exceeded"):
        await runner.extract(sample_capture)
