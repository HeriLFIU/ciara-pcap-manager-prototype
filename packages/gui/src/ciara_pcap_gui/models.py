"""
Qt item model exposing extracted flows to a table view.

A dedicated ``QAbstractTableModel`` keeps the flows in their SDK form and
renders cells on demand, so a capture with hundreds of thousands of flows costs
one Python object per flow rather than one widget per cell.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ciara_pcap_client import (
    application_label,
    format_bytes,
    format_clock,
    value_or,
)
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt
from PySide6.QtCore import QPersistentModelIndex as QPmi

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import Flow

#: Role under which raw, comparable values are published for sorting.
SORT_ROLE = Qt.ItemDataRole.UserRole + 1


@dataclass(frozen=True)
class Column:
    """One column of the flow table."""

    header: str
    display: Callable[["Flow"], str]
    sort_key: Callable[["Flow"], object]
    numeric: bool = False


COLUMNS: tuple[Column, ...] = (
    Column("#", lambda f: str(f.flow_id), lambda f: f.flow_id, numeric=True),
    Column("Source", lambda f: f"{f.src_ip}:{f.src_port}", lambda f: f.src_ip),
    Column("Destination", lambda f: f"{f.dst_ip}:{f.dst_port}", lambda f: f.dst_ip),
    Column("Proto", lambda f: f.protocol_name, lambda f: f.protocol_name),
    Column("Application", application_label, lambda f: f.application_name),
    Column(
        "Category",
        lambda f: f.application_category_name,
        lambda f: f.application_category_name,
    ),
    Column(
        "Packets",
        lambda f: str(f.bidirectional_packets),
        lambda f: f.bidirectional_packets,
        numeric=True,
    ),
    Column(
        "Bytes",
        lambda f: format_bytes(f.bidirectional_bytes),
        lambda f: f.bidirectional_bytes,
        numeric=True,
    ),
    Column(
        "Out / In",
        lambda f: f"{f.src2dst_packets} / {f.dst2src_packets}",
        lambda f: f.src2dst_packets,
        numeric=True,
    ),
    Column(
        "Duration",
        lambda f: f"{f.duration_ms} ms",
        lambda f: f.duration_ms,
        numeric=True,
    ),
    Column(
        "First seen",
        lambda f: format_clock(f.first_seen_ms),
        lambda f: f.first_seen_ms,
        numeric=True,
    ),
    Column(
        "Server name",
        lambda f: value_or(f.requested_server_name, ""),
        lambda f: value_or(f.requested_server_name, ""),
    ),
)


class FlowTableModel(QAbstractTableModel):
    """Presents a list of flows as a sortable, filterable table."""

    def __init__(self, parent: QObject | None = None) -> None:
        """
        Create an empty model.

        Args:
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self._flows: list[Flow] = []

    def set_flows(self, flows: "Sequence[Flow]") -> None:
        """
        Replace the model's contents.

        Args:
            flows: The flows to display.

        """
        self.beginResetModel()
        self._flows = list(flows)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | QPmi | None = None) -> int:  # noqa: N802 - Qt API
        """
        Report the number of flows.

        Args:
            parent: Unused; this model is not hierarchical.

        Returns:
            The row count.

        """
        if parent is not None and parent.isValid():
            return 0
        return len(self._flows)

    def columnCount(self, parent: QModelIndex | QPmi | None = None) -> int:  # noqa: N802 - Qt API
        """
        Report the number of columns.

        Args:
            parent: Unused; this model is not hierarchical.

        Returns:
            The column count.

        """
        if parent is not None and parent.isValid():
            return 0
        return len(COLUMNS)

    def data(
        self,
        index: QModelIndex | QPmi,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:  # noqa: ANN401 - Qt returns a variant
        """
        Return the value of one cell for the requested role.

        Args:
            index: The cell being rendered.
            role: The Qt item data role.

        Returns:
            The cell value, or None when the role is not handled.

        """
        if not index.isValid():
            return None
        flow = self._flows[index.row()]
        column = COLUMNS[index.column()]

        if role == Qt.ItemDataRole.DisplayRole:
            return column.display(flow)
        if role == SORT_ROLE:
            return column.sort_key(flow)
        if role == Qt.ItemDataRole.TextAlignmentRole and column.numeric:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def headerData(  # noqa: N802 - Qt API
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:  # noqa: ANN401 - Qt returns a variant
        """
        Return a header label.

        Args:
            section: Column or row index.
            orientation: Which header is being drawn.
            role: The Qt item data role.

        Returns:
            The header text, or None when the role is not handled.

        """
        if (
            role != Qt.ItemDataRole.DisplayRole
            or orientation != Qt.Orientation.Horizontal
        ):
            return None
        return COLUMNS[section].header
