"""The flows page: a filterable table of flows and a detail panel."""

from typing import TYPE_CHECKING

from ciara_pcap_client import format_count
from PySide6.QtCore import QItemSelection, QModelIndex, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ciara_pcap_gui.models import FlowFilterProxy, FlowTableModel
from ciara_pcap_gui.pages.base import Page
from ciara_pcap_gui.widgets.detail import FlowDetailPanel
from ciara_pcap_gui.widgets.pill import PillDelegate

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import Flow

    from ciara_pcap_gui.state import AnalysisState

#: Protocol filter choices: label and IP protocol number (None for all).
PROTOCOL_CHOICES: tuple[tuple[str, int | None], ...] = (
    ("All protocols", None),
    ("TCP", 6),
    ("UDP", 17),
)

_ROW_HEIGHT = 32


class FlowsPage(Page):
    """Lists every flow segment and shows the features of the selected one."""

    title = "Flows"
    subtitle = "Flow segments built from the inner packets"

    def __init__(self, state: "AnalysisState", parent: QWidget | None = None) -> None:
        """
        Build the page.

        Args:
            state: The analysis on screen.
            parent: Optional Qt parent.

        """
        super().__init__(state, parent)
        self.model = FlowTableModel(self)
        self.proxy = FlowFilterProxy(self.model, self)
        self._shown: Flow | None = None

        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by address, port, protocol or reason…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._on_filter_changed)

        self.protocol = QComboBox()
        for label, proto in PROTOCOL_CHOICES:
            self.protocol.addItem(label, proto)
        self.protocol.currentIndexChanged.connect(self._on_filter_changed)

        self.count = QLabel()
        self.count.setProperty("role", "muted")
        self.export_button = QPushButton("Export CSV")
        self.export_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_button.setToolTip(
            "Write every flow as CSV in codebook column order"
        )
        self.export_button.clicked.connect(self.export_requested)

        toolbar = QHBoxLayout()
        toolbar.addWidget(self.search, stretch=1)
        toolbar.addWidget(self.protocol)
        toolbar.addWidget(self.count)
        toolbar.addWidget(self.export_button)

        self.table = self._build_table()

        self.detail = FlowDetailPanel()
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setChildrenCollapsible(False)

        content = QWidget()
        column = QVBoxLayout(content)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(16)
        column.addLayout(toolbar)
        column.addWidget(splitter, stretch=1)

        self.empty_state = self._build_empty_state()
        self._stack = QStackedWidget()
        self._stack.addWidget(self.empty_state)
        self._stack.addWidget(content)
        self.layout_root.addWidget(self._stack, stretch=1)
        self.refresh()

    def _build_table(self) -> QTableView:
        """
        Build the flow table over the filter proxy.

        Returns:
            The table, with pills on the categorical columns.

        """
        table = QTableView()
        table.setModel(self.proxy)
        table.setSortingEnabled(True)
        table.sortByColumn(-1, Qt.SortOrder.AscendingOrder)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(_ROW_HEIGHT)
        table.setMouseTracking(True)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        header.setHighlightSections(False)
        self._pills = PillDelegate(table)
        for column in range(self.model.columnCount()):
            if self.model.columns[column].tone is not None:
                table.setItemDelegateForColumn(column, self._pills)
        table.selectionModel().selectionChanged.connect(self._on_selection)
        return table

    def _build_empty_state(self) -> QFrame:
        """
        Build what the page shows before any flow is loaded.

        Returns:
            The empty state.

        """
        frame = QFrame()
        frame.setObjectName("EmptyState")
        title = QLabel("No flows yet")
        title.setObjectName("DropTitle")
        hint = QLabel(
            "Open a capture, or reopen a finished analysis from History,\n"
            "and every flow segment appears here with its codebook features."
        )
        hint.setProperty("role", "muted")
        self.empty_open_button = QPushButton("Open capture…")
        self.empty_open_button.setObjectName("PrimaryButton")
        self.empty_open_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.empty_open_button.clicked.connect(self.open_requested)
        layout = QVBoxLayout(frame)
        layout.addStretch(1)
        for widget in (title, hint):
            widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(widget)
        layout.addSpacing(16)
        layout.addWidget(self.empty_open_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)
        return frame

    def refresh(self) -> None:
        """Redraw from the shared state."""
        self.model.set_rows(self.state.flows)
        self._stack.setCurrentIndex(1 if self.state.flows else 0)
        self.export_button.setEnabled(bool(self.state.flows))
        self.table.resizeColumnsToContents()
        self._show_detail(None)
        self._update_count()

    def badge(self) -> str:
        """
        Show the number of loaded flows in the sidebar.

        Returns:
            The count, or an empty string before anything is loaded.

        """
        return format_count(len(self.state.flows)) if self.state.flows else ""

    def apply_filter(self, text: str = "", protocol: str = "") -> None:
        """
        Replace the filters, for drill-downs from other pages.

        Args:
            text: The search text.
            protocol: A protocol label such as ``TCP``; empty for all. A label
                the protocol box does not offer is searched for as text.

        """
        position = self.protocol.findText(protocol) if protocol else 0
        if position < 0:
            position = 0
            text = f"{protocol} {text}".strip()
        self.protocol.setCurrentIndex(position)
        self.search.setText(text)

    def reveal(self, flow: "Flow") -> None:
        """
        Clear the filters, then select and scroll to one flow.

        Args:
            flow: A flow of the loaded analysis.

        """
        self.apply_filter()
        row = self.model.row_of(flow)
        if row is None:
            return
        index = self.proxy.mapFromSource(self.model.index(row, 0))
        self.table.selectRow(index.row())
        self.table.scrollTo(index, QAbstractItemView.ScrollHint.PositionAtCenter)

    def focus_search(self) -> None:
        """Put the keyboard focus in the filter box."""
        self.search.setFocus()
        self.search.selectAll()

    def selected_flow(self) -> "Flow | None":
        """
        Return the flow selected in the table.

        Returns:
            The flow, or None when nothing is selected.

        """
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.model.row_object(self.proxy.mapToSource(rows[0]).row())

    def _on_filter_changed(self) -> None:
        """
        Apply the search text and protocol choice to the table.

        A filter change resets the table, which drops the selection: the
        selected flow is selected again, and scrolled to, while it matches.
        """
        selected = self.selected_flow()
        self.proxy.set_filter(self.search.text(), self.protocol.currentData())
        self._update_count()
        if selected is None or self.selected_flow() is selected:
            return
        row = self.model.row_of(selected)
        index = (
            QModelIndex()
            if row is None
            else self.proxy.mapFromSource(self.model.index(row, 0))
        )
        if index.isValid():
            self.table.selectRow(index.row())
            self.table.scrollTo(index)
        else:
            self._show_detail(None)

    def _on_selection(
        self, selected: QItemSelection, deselected: QItemSelection
    ) -> None:
        """
        Show the newly selected flow in the detail panel.

        Args:
            selected: Unused; the selection model is read instead.
            deselected: Unused.

        """
        del selected, deselected
        self._show_detail(self.selected_flow())

    def _show_detail(self, flow: "Flow | None") -> None:
        """
        Show a flow in the detail panel, unless it is already shown.

        Args:
            flow: The flow, or None to clear the panel.

        """
        if flow is self._shown:
            return
        self._shown = flow
        self.detail.show_flow(flow)

    def _update_count(self) -> None:
        """Show how many flows pass the filter."""
        total = self.model.rowCount()
        shown = self.proxy.rowCount()
        self.count.setText(
            f"{format_count(shown)} of {format_count(total)} flows"
            if total
            else "No flows loaded"
        )
