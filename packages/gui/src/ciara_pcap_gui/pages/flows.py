"""The flows page: a filterable table of flows and a detail panel."""

from typing import TYPE_CHECKING

from ciara_pcap_client import format_count
from PySide6.QtCore import QItemSelection, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QWidget,
)

from ciara_pcap_gui.models import FlowFilterProxy, FlowTableModel
from ciara_pcap_gui.pages.base import Page
from ciara_pcap_gui.widgets.detail import FlowDetailPanel

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import Flow

    from ciara_pcap_gui.state import AnalysisState

#: Protocol filter choices: label and IP protocol number (None for all).
PROTOCOL_CHOICES: tuple[tuple[str, int | None], ...] = (
    ("All protocols", None),
    ("TCP", 6),
    ("UDP", 17),
)


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
        self.export_button.setToolTip(
            "Write every flow as CSV in codebook column order"
        )
        self.export_button.clicked.connect(self.export_requested)

        toolbar = QHBoxLayout()
        toolbar.addWidget(self.search, stretch=1)
        toolbar.addWidget(self.protocol)
        toolbar.addWidget(self.count)
        toolbar.addWidget(self.export_button)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(-1, Qt.SortOrder.AscendingOrder)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.table.selectionModel().selectionChanged.connect(self._on_selection)

        self.detail = FlowDetailPanel()
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setChildrenCollapsible(False)

        self.layout_root.addLayout(toolbar)
        self.layout_root.addWidget(splitter, stretch=1)
        self.refresh()

    def refresh(self) -> None:
        """Redraw from the shared state."""
        self.model.set_rows(self.state.flows)
        self.export_button.setEnabled(bool(self.state.flows))
        self.table.resizeColumnsToContents()
        self.detail.show_flow(None)
        self._update_count()

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
        """Apply the search text and protocol choice to the table."""
        self.proxy.set_text(self.search.text())
        self.proxy.set_protocol(self.protocol.currentData())
        self._update_count()

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
        self.detail.show_flow(self.selected_flow())

    def _update_count(self) -> None:
        """Show how many flows pass the filter."""
        total = self.model.rowCount()
        shown = self.proxy.rowCount()
        self.count.setText(
            f"{format_count(shown)} of {format_count(total)} flows"
            if total
            else "No flows loaded"
        )
