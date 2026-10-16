"""Tests for the value formatting shared by the CLI and the GUI."""

import json

import pytest
from ciara_pcap_client import (
    endpoint,
    format_bytes,
    format_clock,
    format_count,
    format_duration,
    format_nanoseconds,
    format_percent,
    format_timestamp,
    int_coverage,
    protocol_label,
    ranked_counts,
)
from ciara_pcap_sdk.models import FlowSummary
from ciara_pcap_sdk.types import UNSET

from tests.support.factories import summary_payload


@pytest.mark.parametrize(
    ("count", "expected"),
    [(0, "0 B"), (512, "512 B"), (2048, "2.0 KB"), (5 * 1024 * 1024, "5.0 MB")],
)
def test_byte_formatting(count: int, expected: str) -> None:
    assert format_bytes(count) == expected


def test_timestamps_are_utc() -> None:
    assert format_timestamp(1_700_000_000.09) == "2023-11-14 22:13:20.090"
    assert format_clock(1_700_000_000.000123) == "22:13:20.000123"


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(0, "0 s"), (0.00085, "850 µs"), (0.0125, "12.5 ms"), (3.2, "3.200 s")],
)
def test_duration_formatting(seconds: float, expected: str) -> None:
    assert format_duration(seconds) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "—"), (640, "640 ns"), (1540, "1.54 µs"), (2_500_000, "2.50 ms")],
)
def test_nanosecond_formatting(value: float | None, expected: str) -> None:
    assert format_nanoseconds(value) == expected


def test_small_helpers() -> None:
    assert format_count(15458) == "15,458"
    assert format_percent(0.4205) == "42.0%"
    assert format_percent(None) == "—"
    assert protocol_label(6) == "TCP"
    assert protocol_label(17) == "UDP"
    assert protocol_label(253) == "IP-253"
    assert endpoint("10.0.0.1", 443) == "10.0.0.1:443"


def test_ranked_counts_and_int_coverage() -> None:
    summary = FlowSummary.from_dict(json.loads(json.dumps(summary_payload())))

    assert ranked_counts(summary.flows_by_protocol) == [("TCP", 1)]
    assert ranked_counts(UNSET) == []
    assert int_coverage(summary) == pytest.approx(1.0)


def test_int_coverage_is_undefined_without_inner_packets() -> None:
    payload = summary_payload()
    payload["decode"]["inner_packets"] = 0
    payload["decode"]["packets_with_int_hops"] = 0

    assert int_coverage(FlowSummary.from_dict(payload)) is None
