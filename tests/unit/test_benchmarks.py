"""
Micro-benchmarks of the decode and flow-building hot paths.

Benchmarks are disabled by default (each runs once as a plain test). Measure
them with ``make bench``; see docs/common_workflows/ci_feedback.md.
"""

from collections.abc import Callable
from pathlib import Path
from typing import cast

from pytest_benchmark.fixture import BenchmarkFixture

from ciara_pcap_manager_prototype.pcap.extractor import extract_flows
from ciara_pcap_manager_prototype.telemetry.decoder import decode_frame
from ciara_pcap_manager_prototype.telemetry.layers import DecodedPacket
from tests.support.pcap_factory import SAMPLE_EXPECTED, build_sample_capture
from tests.unit.test_decoder import GOLDEN_FRAME


def measure[T](
    benchmark: BenchmarkFixture, function: Callable[..., T], *args: object
) -> T:
    """Run a benchmark, keeping the result's type: pytest-benchmark is untyped."""
    return cast("T", benchmark(function, *args))


def test_decode_one_frame(benchmark: BenchmarkFixture) -> None:
    benchmark.group = "decode"

    result = measure(benchmark, decode_frame, GOLDEN_FRAME)

    assert isinstance(result, DecodedPacket)


def test_extract_the_synthetic_sample(
    benchmark: BenchmarkFixture, tmp_path: Path
) -> None:
    benchmark.group = "extract"
    capture = build_sample_capture(tmp_path / "synthetic.pcap")

    result = measure(benchmark, extract_flows, capture)

    assert len(result.flows) == SAMPLE_EXPECTED.flows
