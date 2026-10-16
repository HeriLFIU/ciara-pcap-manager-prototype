"""
Qt item models for flows and jobs.

The models keep SDK objects as they are and render cells on demand, so a
capture with hundreds of thousands of flows costs one Python object per flow
rather than one widget per cell. Columns are declared as data (`Column`), so
adding a column to a table is one line here.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ciara_pcap_client import (
    endpoint,
    format_bytes,
    format_clock,
    format_count,
    format_duration,
    format_nanoseconds,
    protocol_label,
    value_or,
)
from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtCore import QPersistentModelIndex as QPmi

from ciara_pcap_gui.tones import Tone, job_tone, protocol_tone, termination_tone

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import AnalysisJob, Flow

#: Role under which raw, comparable values are published for sorting.
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
#: Role under which a row's SDK object is published.
OBJECT_ROLE = Qt.ItemDataRole.UserRole + 2
#: Role under which a categorical cell publishes its `Tone`, for pill rendering.
TONE_ROLE = Qt.ItemDataRole.UserRole + 3

_RIGHT = int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)


@dataclass(frozen=True)
class Column[T]:
    """One column of a table: a header and how to render and sort a row."""

    header: str
    display: Callable[[T], str]
    sort_key: Callable[[T], object]
    numeric: bool = False
    tooltip: str = ""
    tone: Callable[[T], Tone] | None = None


def _latency_key(flow: "Flow") -> float:
    """
    Sort key for INT latency that puts flows without INT last.

    Args:
        flow: The flow.

    Returns:
        The mean hop latency, or infinity when it was not measured.

    """
    return flow.mean_hop_latency if flow.mean_hop_latency is not None else float("inf")


FLOW_COLUMNS: tuple[Column["Flow"], ...] = (
    Column(
        "Endpoint A",
        lambda f: endpoint(f.ip_a, f.port_a),
        lambda f: (f.ip_a, f.port_a),
        tooltip="Source of the segment's first packet (ip_a:port_a)",
    ),
    Column(
        "Endpoint B",
        lambda f: endpoint(f.ip_b, f.port_b),
        lambda f: (f.ip_b, f.port_b),
        tooltip="Destination of the segment's first packet (ip_b:port_b)",
    ),
    Column(
        "Proto",
        lambda f: protocol_label(f.proto),
        lambda f: f.proto,
        tone=lambda f: protocol_tone(protocol_label(f.proto)),
    ),
    Column(
        "Packets",
        lambda f: format_count(f.pkts_total),
        lambda f: f.pkts_total,
        numeric=True,
    ),
    Column(
        "A→B",
        lambda f: format_count(f.pkts_fwd),
        lambda f: f.pkts_fwd,
        numeric=True,
        tooltip="Packets from A to B (pkts_fwd)",
    ),
    Column(
        "B→A",
        lambda f: format_count(f.pkts_bwd),
        lambda f: f.pkts_bwd,
        numeric=True,
        tooltip="Packets from B to A (pkts_bwd)",
    ),
    Column(
        "Bytes",
        lambda f: format_bytes(f.bytes_total),
        lambda f: f.bytes_total,
        numeric=True,
        tooltip="Inner IPv4 Total Length, summed (bytes_total)",
    ),
    Column(
        "Duration",
        lambda f: format_duration(f.duration),
        lambda f: f.duration,
        numeric=True,
    ),
    Column(
        "Start (UTC)",
        lambda f: format_clock(f.flow_start_time),
        lambda f: f.flow_start_time,
        numeric=True,
    ),
    Column(
        "INT latency",
        lambda f: format_nanoseconds(f.mean_hop_latency),
        _latency_key,
        numeric=True,
        tooltip="Mean per-packet INT hop latency (mean_hop_latency)",
    ),
    Column(
        "Queue",
        lambda f: "—" if f.queue_occupancy_max is None else str(f.queue_occupancy_max),
        lambda f: -1 if f.queue_occupancy_max is None else f.queue_occupancy_max,
        numeric=True,
        tooltip="Largest INT queue occupancy (queue_occupancy_max)",
    ),
    Column(
        "Ended by",
        lambda f: str(f.termination_reason),
        lambda f: f.termination_reason,
        tone=lambda f: termination_tone(str(f.termination_reason)),
    ),
)


JOB_COLUMNS: tuple[Column["AnalysisJob"], ...] = (
    Column("Capture", lambda j: j.filename, lambda j: j.filename.lower()),
    Column(
        "Status",
        lambda j: str(j.status),
        lambda j: str(j.status),
        tone=lambda j: job_tone(str(j.status)),
    ),
    Column(
        "Size",
        lambda j: format_bytes(j.size_bytes),
        lambda j: j.size_bytes,
        numeric=True,
    ),
    Column(
        "Flows",
        lambda j: (
            ""
            if (s := value_or(j.summary, None)) is None
            else format_count(s.flow_count)
        ),
        lambda j: -1 if (s := value_or(j.summary, None)) is None else s.flow_count,
        numeric=True,
    ),
    Column(
        "Created (UTC)",
        lambda j: (
            ""
            if (c := value_or(j.created_at, None)) is None
            else c.strftime("%Y-%m-%d %H:%M:%S")
        ),
        lambda j: "" if (c := value_or(j.created_at, None)) is None else c.isoformat(),
    ),
)


class ObjectTableModel[T](QAbstractTableModel):
    """A read-only table of objects, one row each, rendered by `Column` specs."""

    def __init__(
        self, columns: Sequence[Column[T]], parent: QObject | None = None
    ) -> None:
        """
        Create an empty model.

        Args:
            columns: How to render each column.
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self._columns = tuple(columns)
        self._rows: list[T] = []

    @property
    def columns(self) -> tuple[Column[T], ...]:
        """
        The column specifications, in display order.

        Returns:
            The columns.

        """
        return self._columns

    def set_rows(self, rows: Sequence[T]) -> None:
        """
        Replace the model's contents.

        Args:
            rows: The objects to display.

        """
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def row_object(self, row: int) -> T:
        """
        Return the object behind a source row.

        Args:
            row: The source model row.

        Returns:
            The object.

        """
        return self._rows[row]

    def row_of(self, item: T) -> int | None:
        """
        Find the source row holding an object.

        Args:
            item: The object, compared by identity.

        Returns:
            The row, or None when the model does not hold it.

        """
        return next((row for row, held in enumerate(self._rows) if held is item), None)

    def rowCount(self, parent: QModelIndex | QPmi | None = None) -> int:  # noqa: N802 - Qt API
        """
        Report the number of rows.

        Args:
            parent: Unused; this model is not hierarchical.

        Returns:
            The row count.

        """
        if parent is not None and parent.isValid():
            return 0
        return len(self._rows)

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
        return len(self._columns)

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
        row = self._rows[index.row()]
        column = self._columns[index.column()]

        if role == OBJECT_ROLE:
            return row
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return _RIGHT if column.numeric else None
        renderers: dict[int, Callable[[T], object] | None] = {
            Qt.ItemDataRole.DisplayRole: column.display,
            SORT_ROLE: column.sort_key,
            TONE_ROLE: column.tone,
        }
        render = renderers.get(role)
        return None if render is None else render(row)

    def headerData(  # noqa: N802 - Qt API
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:  # noqa: ANN401 - Qt returns a variant
        """
        Return a header label or tooltip.

        Args:
            section: Column or row index.
            orientation: Which header is being drawn.
            role: The Qt item data role.

        Returns:
            The header text or tooltip, or None when the role is not handled.

        """
        if orientation != Qt.Orientation.Horizontal:
            return None
        column = self._columns[section]
        if role == Qt.ItemDataRole.DisplayRole:
            return column.header
        if role == Qt.ItemDataRole.ToolTipRole and column.tooltip:
            return column.tooltip
        if role == Qt.ItemDataRole.TextAlignmentRole and column.numeric:
            return _RIGHT
        return None


class FlowTableModel(ObjectTableModel["Flow"]):
    """The flow table, with a precomputed search string per flow."""

    def __init__(self, parent: QObject | None = None) -> None:
        """
        Create an empty flow model.

        Args:
            parent: Optional Qt parent.

        """
        super().__init__(FLOW_COLUMNS, parent)
        self._search: list[str] = []

    def set_rows(self, rows: "Sequence[Flow]") -> None:
        """
        Replace the flows, rebuilding the search index.

        Args:
            rows: The flows to display.

        """
        self._search = [
            " ".join(
                (
                    endpoint(flow.ip_a, flow.port_a),
                    endpoint(flow.ip_b, flow.port_b),
                    protocol_label(flow.proto),
                    str(flow.termination_reason),
                    flow.flow_id,
                )
            ).lower()
            for flow in rows
        ]
        super().set_rows(rows)

    def search_text(self, row: int) -> str:
        """
        Return the lower-cased text a filter matches against.

        Args:
            row: The source model row.

        Returns:
            Endpoints, protocol, termination reason and flow id.

        """
        return self._search[row]


class FlowFilterProxy(QSortFilterProxyModel):
    """Filters flows by free text (all words must match) and by protocol."""

    def __init__(self, source: FlowTableModel, parent: QObject | None = None) -> None:
        """
        Wrap a flow model.

        Args:
            source: The model to filter.
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self._flows = source
        self._terms: list[str] = []
        self._proto: int | None = None
        self.setSourceModel(source)
        self.setSortRole(SORT_ROLE)

    def set_text(self, text: str) -> None:
        """
        Filter on free text: every whitespace-separated term must appear.

        Args:
            text: The filter text; empty shows every flow.

        """
        self.beginFilterChange()
        self._terms = text.lower().split()
        self.endFilterChange()

    def set_protocol(self, proto: int | None) -> None:
        """
        Filter on an IP protocol number.

        Args:
            proto: 6, 17, or None for every protocol.

        """
        self.beginFilterChange()
        self._proto = proto
        self.endFilterChange()

    def filterAcceptsRow(  # noqa: N802 - Qt API
        self, source_row: int, source_parent: QModelIndex | QPmi
    ) -> bool:
        """
        Decide whether a flow passes the current filters.

        Args:
            source_row: Row in the source model.
            source_parent: Unused; the model is flat.

        Returns:
            True when the flow matches every term and the protocol.

        """
        del source_parent
        if (
            self._proto is not None
            and self._flows.row_object(source_row).proto != self._proto
        ):
            return False
        text = self._flows.search_text(source_row)
        return all(term in text for term in self._terms)
