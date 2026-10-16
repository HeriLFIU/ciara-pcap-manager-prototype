"""Tests for the shared domain models and the published contract."""

import json
from pathlib import Path

import pytest
from ciara_pcap_api.openapi import build_document

from ciara_pcap_manager_prototype.domain.flows import (
    FlowSummary,
    TerminationReason,
    protocol_name,
)
from ciara_pcap_manager_prototype.domain.jobs import AnalysisJob, JobStatus
from tests.support.factories import make_flow, make_report

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("number", "expected"),
    [(6, "TCP"), (17, "UDP"), (1, "ICMP"), (58, "ICMPv6"), (253, "IP-253")],
)
def test_protocol_name_maps_known_numbers(number: int, expected: str) -> None:
    assert protocol_name(number) == expected


def test_an_empty_summary_has_no_time_range() -> None:
    summary = FlowSummary.from_flows([], make_report(inner_packets=0))

    assert (summary.flow_count, summary.packet_count, summary.byte_count) == (0, 0, 0)
    assert summary.first_seen is None
    assert summary.last_seen is None
    assert summary.flows_by_protocol == {}


def test_summary_totals_and_breakdowns() -> None:
    flows = [
        make_flow(),
        make_flow(proto=17, flow_start_time=1.0, flow_end_time=2.0),
        make_flow(proto=17, termination_reason=TerminationReason.TCP_RST),
    ]

    summary = FlowSummary.from_flows(flows, make_report())

    assert summary.flow_count == 3
    assert summary.packet_count == sum(flow.pkts_total for flow in flows)
    assert summary.byte_count == sum(flow.bytes_total for flow in flows)
    assert summary.first_seen == 1.0
    assert summary.last_seen == max(flow.flow_end_time for flow in flows)
    assert list(summary.flows_by_protocol.items()) == [("UDP", 2), ("TCP", 1)]
    assert summary.flows_by_termination == {"end_of_input": 2, "tcp_rst": 1}
    assert summary.decode.inner_packets == 10


def test_job_status_terminality() -> None:
    assert JobStatus.SUCCEEDED.is_terminal
    assert JobStatus.FAILED.is_terminal
    assert not JobStatus.PENDING.is_terminal
    assert not JobStatus.RUNNING.is_terminal


def test_a_new_job_is_pending() -> None:
    job = AnalysisJob(filename="sample.pcap", size_bytes=10)

    assert job.status is JobStatus.PENDING
    assert job.summary is None


def test_the_committed_openapi_contract_is_current() -> None:
    committed = json.loads((REPO / "openapi.json").read_text(encoding="utf-8"))

    assert committed == build_document(), (
        "openapi.json is stale. Regenerate it and the SDK with "
        "`bash scripts/non-interactive/generate-sdk.sh`."
    )
