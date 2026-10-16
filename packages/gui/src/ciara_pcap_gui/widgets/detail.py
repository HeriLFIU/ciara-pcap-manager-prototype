"""The flow detail panel: a summary and every codebook feature of the selected flow."""

from typing import TYPE_CHECKING

from ciara_pcap_client import (
    endpoint,
    format_bytes,
    format_count,
    format_duration,
    format_nanoseconds,
    protocol_label,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ciara_pcap_gui.features import feature_rows, format_feature
from ciara_pcap_gui.tones import Tone, protocol_tone, termination_tone
from ciara_pcap_gui.widgets.pill import Pill

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import Flow

_METRICS = ("Packets", "Bytes", "Duration", "INT latency")
_METRIC_COLUMNS = 2
_SHARE_RESOLUTION = 1000


class FlowDetailPanel(QFrame):
    """Summarises the selected flow and lists its features by codebook group."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """
        Build an empty panel.

        Args:
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumWidth(360)

        self._title = QLabel("No flow selected")
        self._title.setObjectName("SectionTitle")
        self._title.setWordWrap(True)
        self._title.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._subtitle = QLabel("Select a row to see all of its codebook features.")
        self._subtitle.setProperty("role", "muted")
        self._subtitle.setWordWrap(True)

        self._summary = self._build_summary()
        tools = self._build_tools()
        self._tree = self._build_tree()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)
        layout.addWidget(self._summary)
        layout.addLayout(tools)
        layout.addWidget(self._tree, stretch=1)
        self.show_flow(None)

    def _build_summary(self) -> QWidget:
        """
        Build the pills, the metric tiles and the direction bar.

        Returns:
            The summary block.

        """
        self._pills = [Pill(), Pill(), Pill()]
        pill_row = QHBoxLayout()
        pill_row.setSpacing(6)
        for pill in self._pills:
            pill_row.addWidget(pill)
        pill_row.addStretch(1)

        self._metrics: dict[str, QLabel] = {}
        metrics = QGridLayout()
        metrics.setSpacing(8)
        for position, name in enumerate(_METRICS):
            metrics.addWidget(
                self._metric_tile(name),
                position // _METRIC_COLUMNS,
                position % _METRIC_COLUMNS,
            )

        self._direction = QProgressBar()
        self._direction.setObjectName("DirectionBar")
        self._direction.setTextVisible(False)
        self._direction.setRange(0, _SHARE_RESOLUTION)
        self._legend_a = QLabel()
        self._legend_a.setObjectName("LegendA")
        self._legend_b = QLabel()
        self._legend_b.setObjectName("LegendB")
        legend = QHBoxLayout()
        legend.addWidget(self._legend_a)
        legend.addStretch(1)
        legend.addWidget(self._legend_b)

        block = QWidget()
        summary = QVBoxLayout(block)
        summary.setContentsMargins(0, 4, 0, 4)
        summary.setSpacing(10)
        summary.addLayout(pill_row)
        summary.addLayout(metrics)
        summary.addWidget(self._direction)
        summary.addLayout(legend)
        return block

    def _build_tools(self) -> QHBoxLayout:
        """
        Build the feature filter and the copy button.

        Returns:
            The toolbar row.

        """
        self.feature_filter = QLineEdit()
        self.feature_filter.setPlaceholderText("Filter features…")
        self.feature_filter.setClearButtonEnabled(True)
        self.feature_filter.textChanged.connect(self._apply_filter)
        self._copy = QPushButton("Copy all")
        self._copy.setObjectName("GhostButton")
        self._copy.setToolTip("Copy every shown feature as name<TAB>value lines")
        self._copy.setCursor(Qt.CursorShape.PointingHandCursor)
        self._copy.clicked.connect(self.copy_all)
        tools = QHBoxLayout()
        tools.setSpacing(8)
        tools.addWidget(self.feature_filter, stretch=1)
        tools.addWidget(self._copy)
        return tools

    def _build_tree(self) -> QTreeWidget:
        """
        Build the grouped feature tree.

        Returns:
            The tree.

        """
        tree = QTreeWidget()
        tree.setColumnCount(2)
        tree.setHeaderLabels(["Feature", "Value"])
        tree.setRootIsDecorated(True)
        tree.setAlternatingRowColors(True)
        tree.setUniformRowHeights(True)
        tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        header = tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        header.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )

        copy = QShortcut(QKeySequence.StandardKey.Copy, tree)
        copy.activated.connect(self.copy_selection)
        return tree

    def _metric_tile(self, name: str) -> QFrame:
        """
        Build one small labelled number.

        Args:
            name: The metric name, also the key of `summary_metric`.

        Returns:
            The tile.

        """
        tile = QFrame()
        tile.setObjectName("MetricTile")
        label = QLabel(name.upper())
        label.setObjectName("MetricLabel")
        value = QLabel("—")
        value.setObjectName("MetricValue")
        self._metrics[name] = value
        column = QVBoxLayout(tile)
        column.setContentsMargins(12, 8, 12, 8)
        column.setSpacing(2)
        column.addWidget(label)
        column.addWidget(value)
        return tile

    @property
    def title(self) -> str:
        """
        The panel heading currently shown.

        Returns:
            The heading text.

        """
        return self._title.text()

    def summary_metric(self, name: str) -> str:
        """
        Read one summary metric as shown.

        Args:
            name: ``Packets``, ``Bytes``, ``Duration`` or ``INT latency``.

        Returns:
            The rendered value.

        """
        return self._metrics[name].text()

    def direction_share(self) -> float:
        """
        Read the share of packets sent from A to B, as drawn by the bar.

        Returns:
            0 to 1.

        """
        return self._direction.value() / _SHARE_RESOLUTION

    def badges(self) -> list[str]:
        """
        Read the protocol and termination pills.

        Returns:
            Their texts, in order.

        """
        return [pill.text() for pill in self._pills[:2]]

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

    def _features(self) -> list[QTreeWidgetItem]:
        """
        List every feature row, skipping the group headings.

        Returns:
            The rows, in display order.

        """
        rows: list[QTreeWidgetItem] = []
        for index in range(self._tree.topLevelItemCount()):
            group = self._tree.topLevelItem(index)
            if group is None:
                continue
            for child_index in range(group.childCount()):
                child = group.child(child_index)
                if child is not None:
                    rows.append(child)
        return rows

    def visible_features(self) -> list[str]:
        """
        List the features the filter lets through.

        Returns:
            Column names, in display order.

        """
        return [item.text(0) for item in self._features() if not item.isHidden()]

    def show_flow(self, flow: "Flow | None") -> None:
        """
        Display a flow's summary and features, or clear the panel.

        Args:
            flow: The flow to show, or None to clear.

        """
        self._tree.clear()
        has_flow = flow is not None
        self._summary.setVisible(has_flow)
        self._tree.setVisible(has_flow)
        self.feature_filter.setEnabled(has_flow)
        self._copy.setEnabled(has_flow)
        if flow is None:
            self._title.setText("No flow selected")
            self._subtitle.setText(
                "Select a row to see its summary and all of its codebook features."
            )
            return

        self._title.setText(
            f"{endpoint(flow.ip_a, flow.port_a)}  ⇄  {endpoint(flow.ip_b, flow.port_b)}"
        )
        self._subtitle.setText(
            f"Segment {flow.flow_segment_id} of {flow.base_flow_key}"
        )
        self._show_summary(flow)

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
        self._apply_filter(self.feature_filter.text())

    def _show_summary(self, flow: "Flow") -> None:
        """
        Fill the pills, the metric tiles and the direction bar.

        Args:
            flow: The flow on screen.

        """
        label = protocol_label(flow.proto)
        reason = str(flow.termination_reason)
        for pill, text, tone in zip(
            self._pills,
            (label, reason, f"segment {flow.flow_segment_id}"),
            (protocol_tone(label), termination_tone(reason), Tone.NEUTRAL),
            strict=True,
        ):
            pill.setText(text)
            pill.set_tone(tone)

        self._metrics["Packets"].setText(format_count(flow.pkts_total))
        self._metrics["Bytes"].setText(format_bytes(flow.bytes_total))
        self._metrics["Duration"].setText(format_duration(flow.duration))
        self._metrics["INT latency"].setText(format_nanoseconds(flow.mean_hop_latency))

        share = flow.pkts_fwd / flow.pkts_total if flow.pkts_total else 0.0
        self._direction.setValue(round(share * _SHARE_RESOLUTION))
        self._direction.setToolTip(
            f"{share:.0%} of packets went from A to B, {1 - share:.0%} from B to A"
        )
        self._legend_a.setText(f"A→B  {format_count(flow.pkts_fwd)} pkts")
        self._legend_b.setText(f"{format_count(flow.pkts_bwd)} pkts  B→A")

    def _apply_filter(self, text: str) -> None:
        """
        Hide the features whose name does not contain the filter text.

        A group whose features are all hidden is hidden too.

        Args:
            text: The filter; matched case-insensitively, empty shows all.

        """
        needle = text.strip().lower()
        for item in self._features():
            item.setHidden(needle not in item.text(0).lower())
        for index in range(self._tree.topLevelItemCount()):
            group = self._tree.topLevelItem(index)
            if group is None:
                continue
            children = (group.child(i) for i in range(group.childCount()))
            group.setHidden(
                all(child is None or child.isHidden() for child in children)
            )

    def copy_selection(self) -> None:
        """Copy the selected features to the clipboard as ``name<TAB>value`` lines."""
        self._copy_items(self._tree.selectedItems())

    def copy_all(self) -> None:
        """Copy every feature the filter shows as ``name<TAB>value`` lines."""
        self._copy_items([item for item in self._features() if not item.isHidden()])

    def _copy_items(self, items: list[QTreeWidgetItem]) -> None:
        """
        Put features on the clipboard.

        Args:
            items: Tree items; group headings are skipped.

        """
        lines = [
            f"{item.text(0)}\t{item.toolTip(1) or item.text(1)}"
            for item in items
            if item.parent() is not None
        ]
        if lines:
            QGuiApplication.clipboard().setText("\n".join(lines))
