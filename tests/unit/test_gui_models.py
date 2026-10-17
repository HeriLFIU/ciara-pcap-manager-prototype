"""
Tests for the desktop client's item models and feature grouping.

These use only QtCore, so they run on hosts without the Qt widget libraries.
Qt runs on the offscreen platform plugin (see ``[tool.pytest_env]``).
"""

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from ciara_pcap_client import FLOW_CSV_COLUMNS
from ciara_pcap_gui.features import FEATURE_GROUPS, feature_rows, format_feature
from ciara_pcap_gui.models import (
    FLOW_COLUMNS,
    JOB_COLUMNS,
    OBJECT_ROLE,
    SORT_ROLE,
    TONE_ROLE,
    FlowFilterProxy,
    FlowTableModel,
    ObjectTableModel,
)
from ciara_pcap_sdk.models import AnalysisJob, Flow
from PySide6.QtCore import QCoreApplication, QPersistentModelIndex, Qt

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


def test_sorting_ascending_and_back_to_backend_order(model: FlowTableModel) -> None:
    proxy = FlowFilterProxy(model)
    column = [c.header for c in FLOW_COLUMNS].index("Bytes")

    proxy.sort(column, Qt.SortOrder.AscendingOrder)
    assert [proxy.data(proxy.index(row, column)) for row in range(3)] == [
        "158 B",
        "509 B",
        "4.0 KB",
    ]
    proxy.sort(-1)
    assert [proxy.data(proxy.index(row, column)) for row in range(3)] == [
        "509 B",
        "158 B",
        "4.0 KB",
    ]


def test_endpoints_sort_by_address_value_not_text(
    qt_app: QCoreApplication,  # noqa: ARG001 - Qt needs the app alive
) -> None:
    table = FlowTableModel()
    table.set_rows(
        [
            sdk_flow(ip_a="10.0.0.10"),
            sdk_flow(ip_a="10.0.0.9"),
            sdk_flow(ip_a="9.1.1.1"),
        ]
    )
    proxy = FlowFilterProxy(table)

    proxy.sort(0, Qt.SortOrder.AscendingOrder)

    assert [proxy.data(proxy.index(row, 0)) for row in range(3)] == [
        "9.1.1.1:5001",
        "10.0.0.9:5001",
        "10.0.0.10:5001",
    ]


def test_the_filter_keeps_the_sort_order(model: FlowTableModel) -> None:
    proxy = FlowFilterProxy(model)
    column = [c.header for c in FLOW_COLUMNS].index("Bytes")
    proxy.sort(column, Qt.SortOrder.DescendingOrder)

    proxy.set_protocol(6)

    assert [proxy.data(proxy.index(row, column)) for row in range(2)] == [
        "4.0 KB",
        "509 B",
    ]


def test_a_persistent_index_follows_its_flow_through_a_sort(
    model: FlowTableModel,
) -> None:
    proxy = FlowFilterProxy(model)
    column = [c.header for c in FLOW_COLUMNS].index("Bytes")
    held = QPersistentModelIndex(proxy.index(0, column))  # the 509 B flow

    proxy.sort(column, Qt.SortOrder.DescendingOrder)

    assert held.row() == 1
    assert held.data() == "509 B"


def test_a_persistent_index_is_dropped_when_its_flow_is_filtered_out(
    model: FlowTableModel,
) -> None:
    proxy = FlowFilterProxy(model)
    udp = QPersistentModelIndex(proxy.index(1, 0))

    proxy.set_protocol(6)

    assert not udp.isValid()


def test_mapping_between_proxy_and_source(model: FlowTableModel) -> None:
    proxy = FlowFilterProxy(model)
    proxy.set_protocol(17)

    assert proxy.mapToSource(proxy.index(0, 2)).row() == 1
    assert proxy.mapFromSource(model.index(1, 2)).row() == 0
    assert not proxy.mapFromSource(model.index(0, 2)).isValid()
    assert proxy.data(proxy.index(0, 0), OBJECT_ROLE) is model.row_object(1)


def test_sorting_does_not_render_a_cell_per_comparison(
    qt_app: QCoreApplication,  # noqa: ARG001 - Qt needs the app alive
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flows = [sdk_flow(bytes_total=(n * 7919) % 5000) for n in range(2000)]
    table = FlowTableModel()
    table.set_rows(flows)
    proxy = FlowFilterProxy(table)
    calls = 0
    original = FlowTableModel.data

    def counting(self: FlowTableModel, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 - Qt variant
        nonlocal calls
        calls += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FlowTableModel, "data", counting)
    column = [c.header for c in FLOW_COLUMNS].index("Bytes")

    proxy.sort(column, Qt.SortOrder.AscendingOrder)
    proxy.set_text("10.0.0.1")

    assert calls == 0
    sizes = [proxy.data(proxy.index(row, column), SORT_ROLE) for row in range(2000)]
    assert sizes == sorted(flow.bytes_total for flow in flows)


def test_the_proxy_passes_qts_model_consistency_checks(model: FlowTableModel) -> None:
    qt_test = pytest.importorskip("PySide6.QtTest")
    proxy = FlowFilterProxy(model)
    tester = qt_test.QAbstractItemModelTester(
        proxy, qt_test.QAbstractItemModelTester.FailureReportingMode.Fatal
    )
    column = [c.header for c in FLOW_COLUMNS].index("Bytes")

    proxy.sort(column, Qt.SortOrder.DescendingOrder)
    proxy.set_text("10.0.0.1")
    proxy.set_protocol(17)
    proxy.set_filter("", None)
    model.set_rows([sdk_flow()])
    proxy.sort(-1)

    assert proxy.rowCount() == 1
    del tester


@pytest.mark.parametrize(
    ("overrides", "header", "tone"),
    [
        ({}, "Proto", "accent"),
        ({"proto": 17}, "Proto", "secondary"),
        ({"proto": 1}, "Proto", "neutral"),
        ({"termination_reason": "tcp_fin_both"}, "Ended by", "success"),
        ({"termination_reason": "tcp_rst"}, "Ended by", "danger"),
        ({"termination_reason": "active_timeout"}, "Ended by", "warning"),
        ({"termination_reason": "end_of_input"}, "Ended by", "neutral"),
        ({}, "Packets", None),
    ],
)
def test_categorical_cells_publish_a_tone(
    qt_app: QCoreApplication,  # noqa: ARG001 - Qt needs the app alive
    overrides: dict[str, object],
    header: str,
    tone: str | None,
) -> None:
    table = FlowTableModel()
    table.set_rows([sdk_flow(**overrides)])
    column = [c.header for c in FLOW_COLUMNS].index(header)

    assert table.data(table.index(0, column), TONE_ROLE) == tone


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
    assert jobs.data(jobs.index(0, 1), TONE_ROLE) == "success"


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
