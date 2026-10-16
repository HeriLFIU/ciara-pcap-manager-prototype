"""
Tests for the desktop client's item models and feature grouping.

These use only QtCore, so they run on hosts without the Qt widget libraries.
Qt runs on the offscreen platform plugin (see ``[tool.pytest_env]``).
"""

import json
from datetime import UTC, datetime

import pytest
from ciara_pcap_client import FLOW_CSV_COLUMNS
from ciara_pcap_gui.features import FEATURE_GROUPS, feature_rows, format_feature
from ciara_pcap_gui.models import (
    FLOW_COLUMNS,
    JOB_COLUMNS,
    OBJECT_ROLE,
    SORT_ROLE,
    FlowFilterProxy,
    FlowTableModel,
    ObjectTableModel,
)
from ciara_pcap_sdk.models import AnalysisJob, Flow
from PySide6.QtCore import QCoreApplication, Qt

from tests.support.factories import make_flow, summary_payload


def sdk_flow(**overrides: object) -> Flow:
    """Build an SDK flow from the domain factory."""
    return Flow.from_dict(json.loads(make_flow(**overrides).model_dump_json()))


@pytest.fixture
def model(qt_app: QCoreApplication) -> FlowTableModel:  # noqa: ARG001 - Qt needs the app alive
    """A flow model holding a TCP flow, a UDP flow and a flow without INT."""
    table = FlowTableModel()
    table.set_rows(
        [
            sdk_flow(bytes_total=509),
            sdk_flow(proto=17, ip_b="8.8.8.8", port_b=53, bytes_total=158),
            sdk_flow(flow_segment_id=2, bytes_total=4096, mean_hop_latency=None),
        ]
    )
    return table


def test_dimensions_match_the_data(model: FlowTableModel) -> None:
    assert model.rowCount() == 3
    assert model.columnCount() == len(FLOW_COLUMNS)


def test_cells_render_endpoints_and_units(model: FlowTableModel) -> None:
    def cell(row: int, header: str) -> object:
        column = [c.header for c in FLOW_COLUMNS].index(header)
        return model.data(model.index(row, column))

    assert cell(0, "Endpoint A") == "10.0.0.1:5001"
    assert cell(1, "Endpoint B") == "8.8.8.8:53"
    assert cell(1, "Proto") == "UDP"
    assert cell(0, "Bytes") == "509 B"
    assert cell(2, "INT latency") == "—"


def test_the_sort_role_publishes_raw_values(model: FlowTableModel) -> None:
    column = [c.header for c in FLOW_COLUMNS].index("Bytes")

    assert model.data(model.index(2, column), SORT_ROLE) == 4096


def test_the_object_role_returns_the_sdk_flow(model: FlowTableModel) -> None:
    flow = model.data(model.index(1, 0), OBJECT_ROLE)

    assert isinstance(flow, Flow)
    assert flow.proto == 17


def test_numeric_columns_are_right_aligned(model: FlowTableModel) -> None:
    numeric = [c.header for c in FLOW_COLUMNS].index("Packets")
    textual = [c.header for c in FLOW_COLUMNS].index("Endpoint A")
    alignment = Qt.ItemDataRole.TextAlignmentRole

    assert model.data(model.index(0, numeric), alignment) is not None
    assert model.data(model.index(0, textual), alignment) is None


def test_headers_have_labels_and_tooltips(model: FlowTableModel) -> None:
    horizontal = Qt.Orientation.Horizontal

    assert model.headerData(0, horizontal) == "Endpoint A"
    assert "ip_a" in model.headerData(0, horizontal, Qt.ItemDataRole.ToolTipRole)
    assert model.headerData(0, Qt.Orientation.Vertical) is None


def test_the_filter_needs_every_term(model: FlowTableModel) -> None:
    proxy = FlowFilterProxy(model)

    proxy.set_text("8.8.8.8 udp")
    assert proxy.rowCount() == 1
    proxy.set_text("8.8.8.8 tcp")
    assert proxy.rowCount() == 0
    proxy.set_text("")
    assert proxy.rowCount() == 3


def test_the_protocol_filter(model: FlowTableModel) -> None:
    proxy = FlowFilterProxy(model)

    proxy.set_protocol(6)
    assert proxy.rowCount() == 2
    proxy.set_protocol(17)
    assert proxy.rowCount() == 1
    proxy.set_protocol(None)
    assert proxy.rowCount() == 3


def test_sorting_uses_raw_values(model: FlowTableModel) -> None:
    proxy = FlowFilterProxy(model)
    column = [c.header for c in FLOW_COLUMNS].index("Bytes")

    proxy.sort(column, Qt.SortOrder.DescendingOrder)

    assert proxy.data(proxy.index(0, column)) == "4.0 KB"


def test_the_job_model(qt_app: QCoreApplication) -> None:  # noqa: ARG001 - Qt needs the app alive
    job = AnalysisJob.from_dict(
        {
            "job_id": "11111111-2222-3333-4444-555555555555",
            "status": "succeeded",
            "filename": "sample.pcap",
            "size_bytes": 2048,
            "created_at": datetime(2026, 10, 15, 12, tzinfo=UTC).isoformat(),
            "summary": summary_payload(),
        }
    )
    jobs = ObjectTableModel(JOB_COLUMNS)
    jobs.set_rows([job])

    rendered = [
        jobs.data(jobs.index(0, column)) for column in range(jobs.columnCount())
    ]

    assert rendered == [
        "sample.pcap",
        "succeeded",
        "2.0 KB",
        "1",
        "2026-10-15 12:00:00",
    ]


def test_every_codebook_column_is_shown_exactly_once() -> None:
    shown = [column for _, columns in FEATURE_GROUPS for column in columns]

    assert sorted(shown) == sorted(FLOW_CSV_COLUMNS)
    assert len(shown) == len(set(shown))


def test_feature_rows_follow_the_groups() -> None:
    rows = feature_rows(make_flow().model_dump(mode="json"))

    assert [title for title, _ in rows] == [title for title, _ in FEATURE_GROUPS]
    identity = dict(rows[0][1])
    assert identity["proto"] == 6


@pytest.mark.parametrize(
    ("column", "value", "expected"),
    [
        ("latency_min", None, "—"),
        ("pkts_total", 15458, "15,458"),
        ("port_a", 14598, "14598"),
        ("proto", 6, "6"),
        ("first_packet_syn", True, "1"),
        ("mean_hop_latency", 1500.123456789, "1500.12"),
        ("total_Bps", 46_300_000.25, "46,300,000.2"),
        ("flow_start_time", 1_700_000_000.5, "2023-11-14 22:13:20.500000 UTC"),
        ("termination_reason", "tcp_rst", "tcp_rst"),
    ],
)
def test_feature_formatting(column: str, value: object, expected: str) -> None:
    assert format_feature(column, value) == expected
