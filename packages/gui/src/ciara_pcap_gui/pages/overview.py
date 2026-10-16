"""The overview page: headline numbers and breakdowns of one analysis."""

from typing import TYPE_CHECKING

from ciara_pcap_client import (
    endpoint,
    format_bytes,
    format_count,
    format_duration,
    format_percent,
    format_timestamp,
    int_coverage,
    protocol_label,
    ranked_counts,
    value_or,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ciara_pcap_gui.pages.base import Page
from ciara_pcap_gui.tones import Tone, protocol_tone, termination_tone
from ciara_pcap_gui.widgets.breakdown import BreakdownList
from ciara_pcap_gui.widgets.cards import Card, StatCard
from ciara_pcap_gui.widgets.drop_zone import DropZone
from ciara_pcap_gui.widgets.pill import Pill

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import AnalysisJob, Flow, FlowSummary

    from ciara_pcap_gui.state import AnalysisState

_TOP_FLOWS = 5
_CARD_COLUMNS = 3
_FLOW_ROW_HEIGHT = 38
_PROTOCOL_WIDTH = 52
_BYTES_WIDTH = 84
#: A right-pointing chevron, written as an escape so it is not taken for a quote.
_CHEVRON = "\u203a"


def _hint(text: str) -> QLabel:
    """
    Build the small line under a card title that says what clicking does.

    Args:
        text: The hint.

    Returns:
        The label.

    """
    label = QLabel(text)
    label.setObjectName("SectionHint")
    return label


class OverviewPage(Page):
    """Summarises the loaded capture, or invites the user to open one."""

    title = "Overview"
    subtitle = "What the decoder found in the capture"

    flows_requested = Signal(str, str)
    """Show the flows matching a search text and a protocol label ("" for any)."""

    flow_activated = Signal(object)
    """Open one flow (an SDK ``Flow``) in the flow browser."""

    def __init__(self, state: "AnalysisState", parent: QWidget | None = None) -> None:
        """
        Build the page.

        Args:
            state: The analysis on screen.
            parent: Optional Qt parent.

        """
        super().__init__(state, parent)
        self.drop_zone = DropZone()
        self.drop_zone.browse_requested.connect(self.open_requested)

        self.cards = {
            "flows": StatCard("Flows", Tone.ACCENT),
            "packets": StatCard("Inner packets", Tone.SECONDARY),
            "bytes": StatCard("Inner bytes", Tone.ACCENT),
            "span": StatCard("Capture span", Tone.NEUTRAL),
            "int": StatCard("INT coverage", Tone.SUCCESS),
            "order": StatCard("Reordered packets", Tone.WARNING),
        }
        self.protocols = BreakdownList(
            "No flows.",
            interactive=True,
            tone_for=protocol_tone,
            action_hint="Show the {name} flows",
        )
        self.protocols.entry_activated.connect(self._show_protocol)
        self.terminations = BreakdownList(
            "No flows.",
            interactive=True,
            tone_for=termination_tone,
            action_hint="Show the flows ended by {name}",
        )
        self.terminations.entry_activated.connect(self._show_termination)
        self.decode = BreakdownList(
            "Every frame was decoded.", tone_for=lambda _: Tone.WARNING
        )
        self.top_flows = QVBoxLayout()
        self.top_flows.setSpacing(2)
        self.top_flow_buttons: list[QPushButton] = []
        self.headline = QLabel()
        self.headline.setObjectName("Headline")
        self.detail = QLabel()
        self.detail.setProperty("role", "muted")

        self._stack = QStackedWidget()
        self._stack.addWidget(self.drop_zone)
        self._stack.addWidget(self._build_content())
        self.layout_root.addWidget(self._stack)
        self.refresh()

    def _show_protocol(self, label: str) -> None:
        """
        Ask for the flows of one protocol.

        Args:
            label: The protocol label, such as ``UDP``.

        """
        self.flows_requested.emit("", label)

    def _show_termination(self, reason: str) -> None:
        """
        Ask for the flows that ended for one reason.

        Args:
            reason: The termination reason.

        """
        self.flows_requested.emit(reason, "")

    def _build_content(self) -> QWidget:
        """
        Lay out the cards and breakdowns shown once a capture is loaded.

        Returns:
            The scrollable content widget.

        """
        content = QWidget()
        column = QVBoxLayout(content)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(16)
        heading = QVBoxLayout()
        heading.setSpacing(2)
        heading.addWidget(self.headline)
        heading.addWidget(self.detail)
        column.addLayout(heading)

        grid = QGridLayout()
        grid.setSpacing(12)
        for position, card in enumerate(self.cards.values()):
            grid.addWidget(card, position // _CARD_COLUMNS, position % _CARD_COLUMNS)
        column.addLayout(grid)

        breakdowns = QHBoxLayout()
        breakdowns.setSpacing(12)
        for title, widget in (
            ("Flows by protocol", self.protocols),
            ("Flows by termination reason", self.terminations),
        ):
            card = Card(title)
            card.body.addWidget(_hint("Click a row to list those flows."))
            card.body.addWidget(widget)
            card.body.addStretch(1)
            breakdowns.addWidget(card)
        column.addLayout(breakdowns)

        lower = QHBoxLayout()
        lower.setSpacing(12)
        decode_card = Card("Frames skipped by the decoder")
        decode_card.body.addWidget(self.decode)
        decode_card.body.addStretch(1)
        top_card = Card("Largest flows by bytes")
        top_card.body.addWidget(_hint("Click a flow to open it in the flow browser."))
        top_card.body.addLayout(self.top_flows)
        top_card.body.addStretch(1)
        lower.addWidget(decode_card)
        lower.addWidget(top_card, stretch=2)
        column.addLayout(lower)
        column.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        return scroll

    def refresh(self) -> None:
        """Redraw from the shared state."""
        job = self.state.job
        summary = None if job is None else value_or(job.summary, None)
        if job is None or summary is None:
            self._stack.setCurrentIndex(0)
            return
        self._stack.setCurrentIndex(1)
        self._show(job, summary, self.state.flows)

    def _show(
        self, job: "AnalysisJob", summary: "FlowSummary", flows: "list[Flow]"
    ) -> None:
        """
        Fill every card from a finished analysis.

        Args:
            job: The finished job.
            summary: Its summary.
            flows: Its flows.

        """
        decode = summary.decode
        first, last = (
            value_or(summary.first_seen, None),
            value_or(summary.last_seen, None),
        )
        self.headline.setText(job.filename)
        self.detail.setText(
            "No inner packets were decoded."
            if first is None or last is None
            else f"{format_timestamp(first)} → {format_timestamp(last)} UTC"
        )

        self.cards["flows"].set_value(
            format_count(summary.flow_count), "Bidirectional flow segments"
        )
        self.cards["packets"].set_value(
            format_count(decode.inner_packets),
            f"of {format_count(decode.frames_read)} frames read",
        )
        self.cards["bytes"].set_value(
            format_bytes(summary.byte_count), "Sum of inner IPv4 Total Length"
        )
        self.cards["span"].set_value(
            "—" if first is None or last is None else format_duration(last - first),
            "First to last inner packet",
        )
        self.cards["int"].set_value(
            format_percent(int_coverage(summary)),
            f"{format_count(decode.packets_with_int_hops)} packets carried INT hops",
        )
        self.cards["order"].set_value(
            format_count(decode.packets_out_of_order),
            f"{format_count(decode.packets_late)} arrived beyond the reorder window",
        )

        self.protocols.set_entries(ranked_counts(summary.flows_by_protocol))
        self.terminations.set_entries(ranked_counts(summary.flows_by_termination))
        self.decode.set_entries(ranked_counts(decode.skipped))

        largest = sorted(flows, key=lambda flow: -flow.bytes_total)[:_TOP_FLOWS]
        self._show_top_flows(largest)

    def _show_top_flows(self, flows: "list[Flow]") -> None:
        """
        Replace the rows of the largest-flows card.

        Args:
            flows: The flows to list, largest first.

        """
        while (item := self.top_flows.takeAt(0)) is not None:
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()
        self.top_flow_buttons = [
            self._flow_row(rank, flow) for rank, flow in enumerate(flows, start=1)
        ]
        for button in self.top_flow_buttons:
            self.top_flows.addWidget(button)
        if not flows:
            empty = QLabel("No flows.")
            empty.setProperty("role", "muted")
            self.top_flows.addWidget(empty)

    def _flow_row(self, rank: int, flow: "Flow") -> QPushButton:
        """
        Build one clickable row of the largest-flows card.

        Args:
            rank: 1 for the largest flow.
            flow: The flow.

        Returns:
            The row.

        """
        button = QPushButton()
        button.setObjectName("FlowRow")
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setToolTip("Open this flow in the flow browser")
        button.setMinimumHeight(_FLOW_ROW_HEIGHT)
        button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        button.clicked.connect(lambda: self.flow_activated.emit(flow))

        number = QLabel(f"{rank}")
        number.setProperty("role", "muted")
        number.setFixedWidth(14)
        endpoints = QLabel(
            f"{endpoint(flow.ip_a, flow.port_a)}  ⇄  {endpoint(flow.ip_b, flow.port_b)}"
        )
        endpoints.setProperty("role", "mono")
        label = protocol_label(flow.proto)
        pill = Pill(label, protocol_tone(label))
        pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pill.setFixedWidth(_PROTOCOL_WIDTH)
        size = QLabel(format_bytes(flow.bytes_total))
        size.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        size.setMinimumWidth(_BYTES_WIDTH)
        arrow = QLabel(_CHEVRON)
        arrow.setObjectName("RowHint")

        row = QHBoxLayout(button)
        row.setContentsMargins(10, 0, 10, 0)
        row.setSpacing(12)
        row.addWidget(number)
        row.addWidget(endpoints, stretch=1)
        row.addWidget(pill, alignment=Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(size)
        row.addWidget(arrow)
        return button
