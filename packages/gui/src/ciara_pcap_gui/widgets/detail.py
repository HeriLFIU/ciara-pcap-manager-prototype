"""The flow detail panel: every codebook feature of the selected flow."""

from typing import TYPE_CHECKING

from ciara_pcap_client import endpoint, protocol_label
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QLabel,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ciara_pcap_gui.features import feature_rows, format_feature

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import Flow


class FlowDetailPanel(QFrame):
    """Lists the selected flow's features, grouped as in the codebook."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """
        Build an empty panel.

        Args:
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumWidth(320)

        self._title = QLabel("No flow selected")
        self._title.setObjectName("SectionTitle")
        self._title.setWordWrap(True)
        self._subtitle = QLabel("Select a row to see all of its codebook features.")
        self._subtitle.setProperty("role", "muted")
        self._subtitle.setWordWrap(True)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(["Feature", "Value"])
        self._tree.setRootIsDecorated(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.setUniformRowHeights(True)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)

        copy = QShortcut(QKeySequence.StandardKey.Copy, self._tree)
        copy.activated.connect(self.copy_selection)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)
        layout.addWidget(self._tree, stretch=1)

    @property
    def title(self) -> str:
        """
        The panel heading currently shown.

        Returns:
            The heading text.

        """
        return self._title.text()

    def feature_value(self, column: str) -> str | None:
        """
        Read the rendered value of one feature, for tests and automation.

        Args:
            column: The codebook column name.

        Returns:
            The value text, or None when the feature is not shown.

        """
        matches = self._tree.findItems(
            column, Qt.MatchFlag.MatchExactly | Qt.MatchFlag.MatchRecursive
        )
        return matches[0].text(1) if matches else None

    def show_flow(self, flow: "Flow | None") -> None:
        """
        Display a flow's features, or clear the panel.

        Args:
            flow: The flow to show, or None to clear.

        """
        self._tree.clear()
        if flow is None:
            self._title.setText("No flow selected")
            self._subtitle.setText("Select a row to see all of its codebook features.")
            return

        self._title.setText(
            f"{endpoint(flow.ip_a, flow.port_a)}  ⇄  {endpoint(flow.ip_b, flow.port_b)}"
        )
        self._subtitle.setText(
            f"{protocol_label(flow.proto)} · segment {flow.flow_segment_id} · "
            f"{flow.termination_reason}"
        )
        values = flow.to_dict()
        for group, rows in feature_rows(values):
            parent = QTreeWidgetItem(self._tree, [group])
            parent.setFirstColumnSpanned(True)
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for column, value in rows:
                item = QTreeWidgetItem(parent, [column, format_feature(column, value)])
                item.setToolTip(1, "" if value is None else str(value))
            parent.setExpanded(True)

    def copy_selection(self) -> None:
        """Copy the selected features to the clipboard as ``name<TAB>value`` lines."""
        lines = [
            f"{item.text(0)}\t{item.toolTip(1) or item.text(1)}"
            for item in self._tree.selectedItems()
            if item.parent() is not None
        ]
        if lines:
            QGuiApplication.clipboard().setText("\n".join(lines))
