"""
Qt item models for flows and jobs.

The models keep SDK objects as they are and render cells on demand, so a
capture with hundreds of thousands of flows costs one Python object per flow
rather than one widget per cell. Columns are declared as data (`Column`), so
adding a column to a table is one line here.

Sorting and filtering the flow table stay in Python on purpose: a
``QSortFilterProxyModel`` asks the model for both cells of every comparison,
which costs one Python call per comparison and made a sort of 15,000 flows take
most of a second. `FlowFilterProxy` sorts once with ``sorted`` over cached keys
and filters with one pass over precomputed search text instead.
"""

import ipaddress
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
    QAbstractProxyModel,
    QAbstractTableModel,
    QModelIndex,
    QObject,
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
_DISPLAY = int(Qt.ItemDataRole.DisplayRole)
_ALIGNMENT = int(Qt.ItemDataRole.TextAlignmentRole)
_ASCENDING = Qt.SortOrder.AscendingOrder


@dataclass(frozen=True)
class Column[T]:
    """One column of a table: a header and how to render and sort a row."""

    header: str
    display: Callable[[T], str]
    sort_key: Callable[[T], object]
    numeric: bool = False
    tooltip: str = ""
    tone: Callable[[T], Tone] | None = None


def _endpoint_key(ip: str, port: int) -> tuple[int, int, str, int]:
    """
    Sort key for an endpoint that orders addresses by value, not as text.

    As text, ``10.0.0.10`` sorts before ``10.0.0.9``.

    Args:
        ip: The address.
        port: The port.

    Returns:
        IP version and address value, then the port. A string that is not an
        address sorts after every address, by its text.

    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return (_NOT_AN_ADDRESS, 0, ip, port)
    return (address.version, int(address), "", port)


_NOT_AN_ADDRESS = 99


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
        lambda f: _endpoint_key(f.ip_a, f.port_a),
        tooltip="Source of the segment's first packet (ip_a:port_a)",
    ),
    Column(
        "Endpoint B",
        lambda f: endpoint(f.ip_b, f.port_b),
        lambda f: _endpoint_key(f.ip_b, f.port_b),
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
        self._renderers = [_renderers(column) for column in self._columns]

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
        return self.cell(index.row(), index.column(), role)

    def cell(self, row: int, column: int, role: int) -> Any:  # noqa: ANN401 - Qt variant
        """
        Return the value of one cell, by position, for the requested role.

        Views ask for a dozen roles per cell and most go unanswered, so the
        role is looked up first and the row is only read for a role this
        column renders.

        Args:
            row: The source row.
            column: The column.
            role: The Qt item data role.

        Returns:
            The cell value, or None when the role is not handled.

        """
        render = self._renderers[column].get(role)
        return None if render is None else render(self._rows[row])

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


def _renderers[T](column: Column[T]) -> dict[int, Callable[[T], object]]:
    """
    Map each role a column answers to the function that renders it.

    Args:
        column: The column.

    Returns:
        Renderers keyed by role number.

    """
    renderers: dict[int, Callable[[T], object]] = {
        _DISPLAY: column.display,
        SORT_ROLE: column.sort_key,
        OBJECT_ROLE: lambda row: row,
    }
    if column.tone is not None:
        renderers[TONE_ROLE] = column.tone
    if column.numeric:
        renderers[_ALIGNMENT] = lambda _: _RIGHT
    return renderers


class FlowTableModel(ObjectTableModel["Flow"]):
    """The flow table, with precomputed search text, protocols and sort orders."""

    def __init__(self, parent: QObject | None = None) -> None:
        """
        Create an empty flow model.

        Args:
            parent: Optional Qt parent.

        """
        super().__init__(FLOW_COLUMNS, parent)
        self._search: list[str] = []
        self._protocols: list[int] = []
        self._orders: dict[tuple[int, Qt.SortOrder], list[int]] = {}

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
        self._protocols = [flow.proto for flow in rows]
        self._orders = {}
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

    def matching_rows(
        self, rows: Sequence[int], terms: Sequence[str], proto: int | None
    ) -> list[int]:
        """
        Keep the rows whose flow matches every term and the protocol.

        Args:
            rows: Source rows, in the order to keep.
            terms: Lower-case words that must all appear in the search text.
            proto: An IP protocol number, or None for every protocol.

        Returns:
            The matching rows, in the given order.

        """
        if proto is not None:
            protocols = self._protocols
            rows = [row for row in rows if protocols[row] == proto]
        search = self._search
        for term in terms:
            rows = [row for row in rows if term in search[row]]
        return list(rows)

    def sorted_rows(self, column: int, order: Qt.SortOrder) -> Sequence[int]:
        """
        Return the source rows ordered by one column.

        The order is computed once per column and direction, then cached until
        the rows change. Equal keys keep the backend order in both directions,
        as a stable sort does.

        Args:
            column: The column to sort by; a negative or unknown column
                keeps the backend order.
            order: Ascending or descending.

        Returns:
            Every source row, in sorted order.

        """
        if not 0 <= column < len(self.columns):
            return range(self.rowCount())
        cached = self._orders.get((column, order))
        if cached is None:
            sort_key = self.columns[column].sort_key
            keys: list[Any] = [sort_key(flow) for flow in self._rows]
            cached = sorted(
                range(len(keys)),
                key=keys.__getitem__,
                reverse=order != _ASCENDING,
            )
            self._orders[column, order] = cached
        return cached


class FlowFilterProxy(QAbstractProxyModel):
    """
    Sorts flows by a column and filters them by free text and by protocol.

    The mapping is two lists: proxy row to source row, and source row to proxy
    row (-1 when filtered out). Sorting keeps the rows and reorders them, so it
    is a layout change that carries the selection along; a filter change
    resets the model, as rows come and go.

    The source must announce every change with a model reset, as
    `ObjectTableModel.set_rows` does.
    """

    def __init__(self, source: FlowTableModel, parent: QObject | None = None) -> None:
        """
        Wrap a flow model.

        Args:
            source: The model to sort and filter.
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self._flows = source
        self._terms: list[str] = []
        self._proto: int | None = None
        self._sort_column = -1
        self._sort_order = _ASCENDING
        self._rows: list[int] = []
        self._positions: list[int] = []
        self.setSourceModel(source)
        source.modelAboutToBeReset.connect(self.beginResetModel)
        source.modelReset.connect(self._on_source_reset)
        self._remap()

    def set_text(self, text: str) -> None:
        """
        Filter on free text: every whitespace-separated term must appear.

        Args:
            text: The filter text; empty shows every flow.

        """
        self.set_filter(text, self._proto)

    def set_protocol(self, proto: int | None) -> None:
        """
        Filter on an IP protocol number.

        Args:
            proto: 6, 17, or None for every protocol.

        """
        self.set_filter(" ".join(self._terms), proto)

    def set_filter(self, text: str, proto: int | None) -> None:
        """
        Replace both filters at once, refiltering only if either changed.

        Args:
            text: The filter text; empty shows every flow.
            proto: An IP protocol number, or None for every protocol.

        """
        terms = text.lower().split()
        if terms == self._terms and proto == self._proto:
            return
        self.beginResetModel()
        self._terms = terms
        self._proto = proto
        self._remap()
        self.endResetModel()

    def sort(self, column: int, order: Qt.SortOrder = _ASCENDING) -> None:
        """
        Sort by one column, keeping every index the views hold on its flow.

        Args:
            column: The column; -1 restores the backend order.
            order: Ascending or descending.

        """
        self.layoutAboutToBeChanged.emit()
        held = self.persistentIndexList()
        flows = [(self._rows[index.row()], index.column()) for index in held]
        self._sort_column = column
        self._sort_order = order
        self._remap()
        self.changePersistentIndexList(
            held,
            [self.createIndex(self._positions[row], cell) for row, cell in flows],
        )
        self.layoutChanged.emit()

    def _remap(self) -> None:
        """Rebuild the row mapping from the sort and the filters."""
        ordered = self._flows.sorted_rows(self._sort_column, self._sort_order)
        if self._terms or self._proto is not None:
            self._rows = self._flows.matching_rows(ordered, self._terms, self._proto)
        else:
            self._rows = list(ordered)
        self._positions = [-1] * self._flows.rowCount()
        for position, row in enumerate(self._rows):
            self._positions[row] = position

    def _on_source_reset(self) -> None:
        """Remap after the source replaced its rows, then end the reset."""
        self._remap()
        self.endResetModel()

    def mapToSource(  # noqa: N802 - Qt API
        self,
        proxyIndex: QModelIndex | QPmi,  # noqa: N803 - Qt API
    ) -> QModelIndex:
        """
        Find the source cell behind a proxy cell.

        Args:
            proxyIndex: The proxy cell.

        Returns:
            The source cell, or an invalid index.

        """
        if not proxyIndex.isValid():
            return QModelIndex()
        return self._flows.index(self._rows[proxyIndex.row()], proxyIndex.column())

    def mapFromSource(  # noqa: N802 - Qt API
        self,
        sourceIndex: QModelIndex | QPmi,  # noqa: N803 - Qt API
    ) -> QModelIndex:
        """
        Find the proxy cell showing a source cell.

        Args:
            sourceIndex: The source cell.

        Returns:
            The proxy cell, or an invalid index when the flow is filtered out.

        """
        if not sourceIndex.isValid():
            return QModelIndex()
        position = self._positions[sourceIndex.row()]
        if position < 0:
            return QModelIndex()
        return self.createIndex(position, sourceIndex.column())

    def index(
        self, row: int, column: int, parent: QModelIndex | QPmi | None = None
    ) -> QModelIndex:
        """
        Create the index of a proxy cell.

        Args:
            row: The proxy row.
            column: The column.
            parent: Must be invalid; the model is flat.

        Returns:
            The index, or an invalid index when out of range.

        """
        if (
            (parent is not None and parent.isValid())
            or not 0 <= row < len(self._rows)
            or not 0 <= column < self._flows.columnCount()
        ):
            return QModelIndex()
        return self.createIndex(row, column)

    def parent(self, child: QModelIndex | QPmi | None = None) -> Any:  # noqa: ANN401 - Qt overloads parent() and parent(index)
        """
        Return the parent of a cell, or the Qt parent object when called bare.

        Args:
            child: A cell of this model; omitted for the ``QObject`` parent.

        Returns:
            An invalid index, as the model is flat; or the parent ``QObject``.

        """
        if child is None:
            return super().parent()
        return QModelIndex()

    def rowCount(self, parent: QModelIndex | QPmi | None = None) -> int:  # noqa: N802 - Qt API
        """
        Report the number of flows that pass the filters.

        Args:
            parent: Unused; the model is flat.

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
            parent: Unused; the model is flat.

        Returns:
            The column count.

        """
        if parent is not None and parent.isValid():
            return 0
        return self._flows.columnCount()

    def hasChildren(self, parent: QModelIndex | QPmi | None = None) -> bool:  # noqa: N802 - Qt API
        """
        Report whether a cell has children: only the root does, when not empty.

        Args:
            parent: The cell.

        Returns:
            True for the root of a non-empty model.

        """
        if parent is not None and parent.isValid():
            return False
        return bool(self._rows) and self._flows.columnCount() > 0

    def data(
        self,
        index: QModelIndex | QPmi,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:  # noqa: ANN401 - Qt returns a variant
        """
        Return the value of one cell, read from the source row it shows.

        Args:
            index: The proxy cell.
            role: The Qt item data role.

        Returns:
            The cell value, or None.

        """
        if not index.isValid():
            return None
        return self._flows.cell(self._rows[index.row()], index.column(), role)

    def headerData(  # noqa: N802 - Qt API
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:  # noqa: ANN401 - Qt returns a variant
        """
        Return the source's column header; the columns are not reordered.

        Args:
            section: Column or row index.
            orientation: Which header is being drawn.
            role: The Qt item data role.

        Returns:
            The header value, or None.

        """
        return self._flows.headerData(section, orientation, role)
