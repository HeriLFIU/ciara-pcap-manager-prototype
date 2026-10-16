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
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ciara_pcap_gui.pages.base import Page
from ciara_pcap_gui.widgets.breakdown import BreakdownList
from ciara_pcap_gui.widgets.cards import Card, StatCard
from ciara_pcap_gui.widgets.drop_zone import DropZone

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import AnalysisJob, Flow, FlowSummary

    from ciara_pcap_gui.state import AnalysisState

_TOP_FLOWS = 5
_CARD_COLUMNS = 3


class OverviewPage(Page):
    """Summarises the loaded capture, or invites the user to open one."""

    title = "Overview"
    subtitle = "What the decoder found in the capture"

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
            "flows": StatCard("Flows"),
            "packets": StatCard("Inner packets"),
            "bytes": StatCard("Inner bytes"),
            "span": StatCard("Capture span"),
            "int": StatCard("INT coverage"),
            "order": StatCard("Reordered packets"),
        }
        self.protocols = BreakdownList("No flows.")
        self.terminations = BreakdownList("No flows.")
        self.decode = BreakdownList("Every frame was decoded.")
        self.top_flows = QLabel()
        self.top_flows.setProperty("role", "mono")
        self.top_flows.setWordWrap(True)
        self.headline = QLabel()
        self.headline.setObjectName("SectionTitle")
        self.detail = QLabel()
        self.detail.setProperty("role", "muted")

        self._stack = QStackedWidget()
        self._stack.addWidget(self.drop_zone)
        self._stack.addWidget(self._build_content())
        self.layout_root.addWidget(self._stack)
        self.refresh()

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
        column.addWidget(self.headline)
        column.addWidget(self.detail)

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
        top_card.body.addWidget(self.top_flows)
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
        self.top_flows.setText(
            "\n".join(
                f"{endpoint(f.ip_a, f.port_a):>22} ⇄ {endpoint(f.ip_b, f.port_b):<22} "
                f"{protocol_label(f.proto):<4} {format_bytes(f.bytes_total):>9}"
                for f in largest
            )
            or "No flows."
        )
