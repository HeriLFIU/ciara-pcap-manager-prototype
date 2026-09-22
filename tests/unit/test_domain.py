"""Tests for the shared domain models."""

import pytest

from ciara_pcap_manager_prototype.domain.flows import (
    ExpirationReason,
    FlowSummary,
    protocol_name,
)
from ciara_pcap_manager_prototype.domain.jobs import AnalysisJob, JobStatus
from tests.support.factories import make_flow


@pytest.mark.parametrize(
    ("number", "expected"),
    [(6, "TCP"), (17, "UDP"), (1, "ICMP"), (58, "ICMPv6"), (253, "IP-253")],
)
def test_protocol_name_maps_known_numbers(number: int, expected: str) -> None:
    assert protocol_name(number) == expected


@pytest.mark.parametrize(
    ("expiration_id", "expected"),
    [
        (0, ExpirationReason.IDLE_TIMEOUT),
        (1, ExpirationReason.ACTIVE_TIMEOUT),
        (-1, ExpirationReason.CUSTOM),
        (99, ExpirationReason.UNKNOWN),
    ],
)
def test_expiration_reason_maps_nfstream_ids(
    expiration_id: int, expected: ExpirationReason
) -> None:
    assert ExpirationReason.from_expiration_id(expiration_id) is expected


def test_summary_of_no_flows_is_empty() -> None:
    summary = FlowSummary.from_flows([])

    assert summary.flow_count == 0
    assert summary.packet_count == 0
    assert summary.byte_count == 0
    assert summary.first_seen_ms is None
    assert summary.top_applications == {}


def test_summary_aggregates_counts_and_time_span() -> None:
    flows = [
        make_flow(flow_id=0, bidirectional_packets=8, bidirectional_bytes=500),
        make_flow(
            flow_id=1,
            bidirectional_packets=2,
            bidirectional_bytes=100,
            first_seen_ms=1_700_000_000_500,
            last_seen_ms=1_700_000_000_900,
            application_name="DNS",
        ),
    ]

    summary = FlowSummary.from_flows(flows)

    assert summary.flow_count == 2
    assert summary.packet_count == 10
    assert summary.byte_count == 600
    assert summary.first_seen_ms == 1_700_000_000_000
    assert summary.last_seen_ms == 1_700_000_000_900


def test_summary_ranks_applications_by_frequency_then_name() -> None:
    flows = [
        make_flow(flow_id=0, application_name="DNS"),
        make_flow(flow_id=1, application_name="HTTP"),
        make_flow(flow_id=2, application_name="HTTP"),
        make_flow(flow_id=3, application_name="TLS"),
    ]

    summary = FlowSummary.from_flows(flows)

    assert list(summary.top_applications.items()) == [
        ("HTTP", 2),
        ("DNS", 1),
        ("TLS", 1),
    ]


def test_summary_top_n_truncates_the_ranking() -> None:
    flows = [make_flow(flow_id=i, application_name=f"App{i}") for i in range(5)]

    summary = FlowSummary.from_flows(flows, top_n=2)

    assert len(summary.top_applications) == 2


@pytest.mark.parametrize(
    ("status", "terminal"),
    [
        (JobStatus.PENDING, False),
        (JobStatus.RUNNING, False),
        (JobStatus.SUCCEEDED, True),
        (JobStatus.FAILED, True),
    ],
)
def test_job_status_knows_which_states_are_terminal(
    status: JobStatus, terminal: bool
) -> None:
    assert status.is_terminal is terminal


def test_new_job_starts_pending_with_a_timezone_aware_timestamp() -> None:
    job = AnalysisJob(filename="capture.pcap", size_bytes=851)

    assert job.status is JobStatus.PENDING
    assert job.created_at.tzinfo is not None
    assert job.summary is None
    assert job.error is None
