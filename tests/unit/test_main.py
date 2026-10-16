"""Tests for the offline ``ciara-pcap-inspect`` command line."""

from pathlib import Path

import pytest

from ciara_pcap_manager_prototype.main import build_parser, main
from tests.support.pcap_factory import SAMPLE_EXPECTED, build_sample_capture


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    """The synthetic INT capture."""
    return build_sample_capture(tmp_path / "synthetic.pcap")


def test_the_summary_counts_frames_packets_and_flows(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample)]) == 0

    out = capsys.readouterr().out
    assert f"frames read            {SAMPLE_EXPECTED.frames}" in out
    assert f"inner packets decoded  {SAMPLE_EXPECTED.inner_packets}" in out
    assert f"flows                  {SAMPLE_EXPECTED.flows}" in out
    assert "skipped frames         1 (not_telemetry_port)" in out


def test_inspect_prints_every_layer(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample), "--inspect", "1"]) == 0

    out = capsys.readouterr().out
    for layer in (
        "OUTER",
        "REPORT",
        "INNER",
        "INT",
        "hop 1",
        "hop latency (ns)    1500",
    ):
        assert layer in out
    assert "10.1.0.10:40000 -> 93.184.216.34:443 TCP" in out


def test_inspect_names_the_reason_a_frame_is_skipped(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample), "--inspect", "9"]) == 0

    assert "skipped: not_telemetry_port" in capsys.readouterr().out


def test_csv_export(sample: Path, tmp_path: Path) -> None:
    destination = tmp_path / "flows.csv"

    assert main([str(sample), "--csv", str(destination)]) == 0

    lines = destination.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 + SAMPLE_EXPECTED.flows


def test_a_missing_capture_fails(tmp_path: Path) -> None:
    assert main([str(tmp_path / "absent.pcap")]) == 1


def test_a_file_that_is_not_a_capture_fails(tmp_path: Path) -> None:
    path = tmp_path / "notes.pcap"
    path.write_text("hello", encoding="utf-8")

    assert main([str(path)]) == 1
    assert main([str(path), "--inspect", "1"]) == 1


def test_the_default_capture_is_the_bundled_sample() -> None:
    default = build_parser().parse_args([]).pcap

    assert default is not None
    assert default.name == "synthetic.pcap"
    assert main([]) == 0
