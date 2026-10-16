"""A compact list of labelled bars, for ``{name: count}`` breakdowns."""

from ciara_pcap_client import format_count
from PySide6.QtWidgets import QGridLayout, QLabel, QProgressBar, QWidget

_BAR_RESOLUTION = 1000


class BreakdownList(QWidget):
    """Shows each name with its count and a bar proportional to the total."""

    def __init__(
        self, empty_text: str = "Nothing to show.", parent: QWidget | None = None
    ) -> None:
        """
        Create an empty breakdown.

        Args:
            empty_text: What to say when there are no entries.
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self._empty_text = empty_text
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setHorizontalSpacing(12)
        self._grid.setVerticalSpacing(8)
        self._grid.setColumnStretch(1, 1)
        self._entries: list[tuple[str, int]] = []
        self.set_entries([])

    @property
    def entries(self) -> list[tuple[str, int]]:
        """
        The ``(name, count)`` pairs currently shown.

        Returns:
            A copy of the entries.

        """
        return list(self._entries)

    def set_entries(self, entries: list[tuple[str, int]]) -> None:
        """
        Replace the bars.

        Args:
            entries: ``(name, count)`` pairs, in display order.

        """
        while (item := self._grid.takeAt(0)) is not None:
            widget = item.widget()
            if widget is not None:
                # Hide now: deleteLater only runs once the event loop is idle,
                # and until then the old row would still paint under the new one.
                widget.hide()
                widget.deleteLater()
        self._entries = list(entries)

        if not entries:
            empty = QLabel(self._empty_text)
            empty.setProperty("role", "muted")
            self._grid.addWidget(empty, 0, 0, 1, 3)
            return

        total = sum(count for _, count in entries) or 1
        for row, (name, count) in enumerate(entries):
            label = QLabel(name)
            bar = QProgressBar()
            bar.setObjectName("BarMeter")
            bar.setTextVisible(False)
            bar.setRange(0, _BAR_RESOLUTION)
            bar.setValue(round(count / total * _BAR_RESOLUTION))
            value = QLabel(f"{format_count(count)}  ({count / total:.0%})")
            value.setProperty("role", "muted")
            self._grid.addWidget(label, row, 0)
            self._grid.addWidget(bar, row, 1)
            self._grid.addWidget(value, row, 2)
