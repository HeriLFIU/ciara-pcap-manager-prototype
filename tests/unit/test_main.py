"""Unit tests for the application entry point and profiling target."""

from __future__ import annotations

from pathlib import Path

import pytest

import ciara_pcap_manager_prototype.main as app_main
from ciara_pcap_manager_prototype.domain.flows import ExpirationReason, Flow
from ciara_pcap_manager_prototype.main import build_parser, main
from ciara_pcap_manager_prototype.pcap.extractor import PcapExtractionError


def _make_dummy_flow() -> Flow:
    """Create a minimal Flow domain instance for mocking."""
    return Flow(
        flow_id=1,
        expiration_reason=ExpirationReason.IDLE_TIMEOUT,
        src_ip="192.168.1.10",
        src_port=12345,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol=6,
        protocol_name="TCP",
        ip_version=4,
        vlan_id=0,
        first_seen_ms=1000,
        last_seen_ms=2000,
        duration_ms=1000,
        bidirectional_packets=5,
        bidirectional_bytes=500,
        src2dst_packets=3,
        src2dst_bytes=300,
        dst2src_packets=2,
        dst2src_bytes=200,
        application_name="HTTP",
        application_category_name="Web",
        application_is_guessed=False,
        application_confidence=6,
        requested_server_name=None,
        client_fingerprint=None,
        server_fingerprint=None,
        user_agent=None,
        content_type=None,
    )


def test_build_parser() -> None:
    """Verify that the argument parser is constructed with expected options."""
    parser = build_parser()
    args = parser.parse_args(["--n-dissections", "10"])
    assert args.n_dissections == 10


def test_build_parser_fallback_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify parser falls back to resolving relative to module file."""
    original_is_file = Path.is_file

    def fake_is_file(self: Path) -> bool:
        if self == Path("samples/synthetic.pcap"):
            return False
        return original_is_file(self)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    parser = build_parser()
    assert parser is not None


def test_main_help() -> None:
    """Verify that --help exits cleanly."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0


def test_main_missing_capture(tmp_path: Path) -> None:
    """Verify that a missing capture file logs and exits with 0."""
    missing_file = tmp_path / "nonexistent.pcap"
    exit_code = main([str(missing_file)])
    assert exit_code == 0


def test_main_successful_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that successful flow extraction returns 0."""
    dummy_pcap = tmp_path / "test.pcap"
    dummy_pcap.write_bytes(b"dummy-pcap-content")

    called = False

    def fake_extract_success(
        _path: Path,
        *,
        _n_dissections: int = 20,
        _max_flows: int = 0,
        **_kwargs: object,
    ) -> list[Flow]:
        nonlocal called
        called = True
        return [_make_dummy_flow()]

    monkeypatch.setattr(app_main, "extract_flows", fake_extract_success)

    exit_code = main([str(dummy_pcap)])
    assert exit_code == 0
    assert called


def test_main_handles_extraction_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that extraction errors are handled gracefully and return 0."""
    dummy_pcap = tmp_path / "corrupt.pcap"
    dummy_pcap.write_bytes(b"corrupt-data")

    def fake_extract_error(
        _path: Path,
        *,
        _n_dissections: int = 20,
        _max_flows: int = 0,
        **_kwargs: object,
    ) -> list[Flow]:
        msg = "Corrupt capture"
        raise PcapExtractionError(msg)

    monkeypatch.setattr(app_main, "extract_flows", fake_extract_error)

    exit_code = main([str(dummy_pcap)])
    assert exit_code == 0


def test_main_defaults_to_bundled_sample(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that running with default arguments executes without error."""

    def fake_extract_default(
        _path: Path,
        *,
        _n_dissections: int = 20,
        _max_flows: int = 0,
        **_kwargs: object,
    ) -> list[Flow]:
        return [_make_dummy_flow()]

    monkeypatch.setattr(app_main, "extract_flows", fake_extract_default)

    exit_code = main([])
    assert exit_code == 0
