"""A compact list of labelled bars, for ``{name: count}`` breakdowns."""

from collections.abc import Callable

from ciara_pcap_client import format_count
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ciara_pcap_gui.tones import Tone

_BAR_RESOLUTION = 1000
_NAME_WIDTH = 120
_VALUE_WIDTH = 104
_ROW_HEIGHT = 34
#: A right-pointing chevron, written as an escape so it is not taken for a quote.
_CHEVRON = "\u203a"


def _accent(_: str) -> Tone:
    """
    Colour every entry in the accent.

    Returns:
        The accent tone.

    """
    return Tone.ACCENT


class BreakdownList(QWidget):
    """
    Shows each name with its count and a bar proportional to the total.

    When the list is *interactive* every entry is a button and clicking it
    emits `entry_activated` with the entry's name, so a page can drill down.
    """

    entry_activated = Signal(str)
    """The user clicked an entry; carries its name."""

    def __init__(
        self,
        empty_text: str = "Nothing to show.",
        parent: QWidget | None = None,
        *,
        interactive: bool = False,
        tone_for: Callable[[str], Tone] = _accent,
        action_hint: str = "",
    ) -> None:
        """
        Create an empty breakdown.

        Args:
            empty_text: What to say when there are no entries.
            parent: Optional Qt parent.
            interactive: Make each entry a clickable button.
            tone_for: Picks each bar's colour from the entry name.
            action_hint: Tooltip of an interactive entry; ``{name}`` is replaced.

        """
        super().__init__(parent)
        self._empty_text = empty_text
        self._interactive = interactive
        self._tone_for = tone_for
        self._action_hint = action_hint
        self._rows = QVBoxLayout(self)
        self._rows.setContentsMargins(0, 0, 0, 0)
        self._rows.setSpacing(2)
        self._entries: list[tuple[str, int]] = []
        self._buttons: dict[str, QPushButton] = {}
        self.set_entries([])

    @property
    def entries(self) -> list[tuple[str, int]]:
        """
        The ``(name, count)`` pairs currently shown.

        Returns:
            A copy of the entries.

        """
        return list(self._entries)

    def entry_button(self, name: str) -> QPushButton | None:
        """
        Return the button of an interactive entry.

        Args:
            name: The entry name.

        Returns:
            The button, or None when the list is not interactive or has no
            such entry.

        """
        return self._buttons.get(name)

    def set_entries(self, entries: list[tuple[str, int]]) -> None:
        """
        Replace the bars.

        Args:
            entries: ``(name, count)`` pairs, in display order.

        """
        while (item := self._rows.takeAt(0)) is not None:
            widget = item.widget()
            if widget is not None:
                # Hide now: deleteLater only runs once the event loop is idle,
                # and until then the old row would still paint under the new one.
                widget.hide()
                widget.deleteLater()
        self._entries = list(entries)
        self._buttons = {}

        if not entries:
            empty = QLabel(self._empty_text)
            empty.setProperty("role", "muted")
            self._rows.addWidget(empty)
            return

        total = sum(count for _, count in entries) or 1
        for name, count in entries:
            self._rows.addWidget(self._row(name, count, total))

    def _row(self, name: str, count: int, total: int) -> QWidget:
        """
        Build one entry: name, bar and count.

        Args:
            name: The entry name.
            count: Its count.
            total: The sum of every count.

        Returns:
            The row widget, a button when the list is interactive.

        """
        row: QWidget
        if self._interactive:
            button = QPushButton()
            button.setObjectName("BreakdownRow")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setToolTip(self._action_hint.format(name=name))
            button.setMinimumHeight(_ROW_HEIGHT)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(lambda: self.entry_activated.emit(name))
            self._buttons[name] = button
            row = button
        else:
            row = QWidget()
            row.setMinimumHeight(_ROW_HEIGHT - 6)

        layout = QHBoxLayout(row)
        layout.setContentsMargins(8, 0, 8, 0)
        layout.setSpacing(12)
        label = QLabel(name)
        label.setMinimumWidth(_NAME_WIDTH)
        bar = QProgressBar()
        bar.setObjectName("BarMeter")
        bar.setProperty("tone", str(self._tone_for(name)))
        bar.setTextVisible(False)
        bar.setRange(0, _BAR_RESOLUTION)
        bar.setValue(round(count / total * _BAR_RESOLUTION))
        value = QLabel(f"{format_count(count)}  ·  {count / total:.0%}")
        value.setProperty("role", "muted")
        value.setMinimumWidth(_VALUE_WIDTH)
        value.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(label)
        layout.addWidget(bar, stretch=1)
        layout.addWidget(value)
        if self._interactive:
            arrow = QLabel(_CHEVRON)
            arrow.setObjectName("RowHint")
            layout.addWidget(arrow)
        return row
