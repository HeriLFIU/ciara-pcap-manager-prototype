"""
Tests for the desktop client's table model.

Qt runs on the offscreen platform plugin here, so these exercise the real
``QAbstractTableModel`` contract -- row and column counts, roles, sorting and
filtering -- without opening a window.
"""

import json

import pytest
from ciara_pcap_gui.models import COLUMNS, SORT_ROLE, FlowTableModel
from ciara_pcap_sdk.models import Flow
from PySide6.QtCore import QCoreApplication, QSortFilterProxyModel, Qt

from tests.support.factories import make_flow

EXPECTED_ROWS = 3


@pytest.fixture(scope="session")
def qt_app() -> QCoreApplication:
    """A process-wide Qt application, required before any model exists."""
    app = QCoreApplication.instance() or QCoreApplication([])
    assert isinstance(app, QCoreApplication)
    return app


def sdk_flow(**overrides: object) -> Flow:
    """Build an SDK flow model from the domain factory."""
    return Flow.from_dict(json.loads(make_flow(**overrides).model_dump_json()))


@pytest.fixture
def model(qt_app: QCoreApplication) -> FlowTableModel:  # noqa: ARG001 - Qt needs the app alive
    """A table model holding three flows."""
    table = FlowTableModel()
    table.set_flows(
        [
            sdk_flow(flow_id=0, application_name="HTTP", bidirectional_bytes=509),
            sdk_flow(
                flow_id=1,
                application_name="DNS",
                src_port=40000,
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol_name="UDP",
                bidirectional_bytes=158,
            ),
            sdk_flow(flow_id=2, application_name="TLS", bidirectional_bytes=4096),
        ]
    )
    return table


def test_dimensions_match_the_data(model: FlowTableModel) -> None:
    assert model.rowCount() == EXPECTED_ROWS
    assert model.columnCount() == len(COLUMNS)


def test_headers_are_published_for_the_horizontal_orientation(
    model: FlowTableModel,
) -> None:
    headers = [
        model.headerData(column, Qt.Orientation.Horizontal)
        for column in range(model.columnCount())
    ]

    assert headers[:4] == ["#", "Source", "Destination", "Proto"]
    assert model.headerData(0, Qt.Orientation.Vertical) is None


def test_cells_render_endpoints_and_units(model: FlowTableModel) -> None:
    row = 1

    assert model.data(model.index(row, 1)) == "10.0.0.1:40000"
    assert model.data(model.index(row, 2)) == "8.8.8.8:53"
    assert model.data(model.index(row, 3)) == "UDP"
    assert model.data(model.index(row, 7)) == "158 B"


def test_a_guessed_application_is_flagged(qt_app: QCoreApplication) -> None:  # noqa: ARG001
    table = FlowTableModel()
    table.set_flows([sdk_flow(application_name="HTTP", application_is_guessed=True)])

    assert table.data(table.index(0, 4)) == "HTTP?"


def test_the_sort_role_exposes_raw_comparable_values(model: FlowTableModel) -> None:
    assert model.data(model.index(0, 7), SORT_ROLE) == 509
    assert model.data(model.index(0, 7)) == "509 B"


def test_numeric_columns_are_right_aligned(model: FlowTableModel) -> None:
    alignment = model.data(model.index(0, 6), Qt.ItemDataRole.TextAlignmentRole)

    assert alignment is not None
    assert alignment & int(Qt.AlignmentFlag.AlignRight)
    assert model.data(model.index(0, 1), Qt.ItemDataRole.TextAlignmentRole) is None


def test_an_invalid_index_yields_nothing(model: FlowTableModel) -> None:
    from PySide6.QtCore import QModelIndex  # noqa: PLC0415 - only needed here

    assert model.data(QModelIndex()) is None


def test_sorting_by_bytes_uses_the_numeric_value_not_the_label(
    model: FlowTableModel,
) -> None:
    proxy = QSortFilterProxyModel()
    proxy.setSourceModel(model)
    proxy.setSortRole(SORT_ROLE)

    proxy.sort(7, Qt.SortOrder.AscendingOrder)

    ordered = [proxy.data(proxy.index(row, 0)) for row in range(proxy.rowCount())]
    assert ordered == ["1", "0", "2"]


def test_filtering_searches_every_column(model: FlowTableModel) -> None:
    proxy = QSortFilterProxyModel()
    proxy.setSourceModel(model)
    proxy.setFilterKeyColumn(-1)
    proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    proxy.setFilterFixedString("8.8.8.8")
    assert proxy.rowCount() == 1

    proxy.setFilterFixedString("")
    assert proxy.rowCount() == EXPECTED_ROWS


def test_resetting_the_model_replaces_every_row(model: FlowTableModel) -> None:
    model.set_flows([])

    assert model.rowCount() == 0
