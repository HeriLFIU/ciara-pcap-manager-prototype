"""The empty state: a large target to drop a capture on, or click to browse."""

from pathlib import Path

from ciara_pcap_client import FLOW_CSV_COLUMNS
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDropEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ciara_pcap_gui.theme import repolish

#: File suffixes accepted by drag and drop.
CAPTURE_SUFFIXES = frozenset({".pcap", ".pcapng", ".cap"})

_ICON_WIDTH = 76
_ICON_HEIGHT = 92
_BUTTON_WIDTH = 180
_STEP_SIZE = 22


def capture_from_urls(paths: list[str]) -> Path | None:
    """
    Pick the first dropped local file that looks like a capture.

    Args:
        paths: Local file paths of the dropped items.

    Returns:
        The capture's path, or None when none of them is a capture.

    """
    for raw in paths:
        path = Path(raw)
        if path.suffix.lower() in CAPTURE_SUFFIXES and path.is_file():
            return path
    return None


def _step(number: int, text: str) -> QHBoxLayout:
    """
    Build one numbered line of the "how it works" list.

    Args:
        number: The step number.
        text: What happens in that step.

    Returns:
        The row.

    """
    badge = QLabel(str(number))
    badge.setObjectName("StepNumber")
    badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
    badge.setFixedSize(_STEP_SIZE, _STEP_SIZE)
    label = QLabel(text)
    label.setObjectName("StepText")
    row = QHBoxLayout()
    row.setSpacing(10)
    row.addWidget(badge)
    row.addWidget(label)
    row.addStretch(1)
    return row


class DropZone(QFrame):
    """Invites the user to drop a capture or open one with a button."""

    capture_dropped = Signal(Path)
    """Emitted with the path of a capture dropped onto the zone."""

    browse_requested = Signal()
    """Emitted when the user clicks the browse button."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """
        Build the drop zone.

        Args:
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(260)

        icon = QLabel("PCAP")
        icon.setObjectName("DropIcon")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(_ICON_WIDTH, _ICON_HEIGHT)
        title = QLabel("Analyse an INT telemetry capture")
        title.setObjectName("DropTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint = QLabel("Drop a .pcap or .pcapng file anywhere on this window.")
        hint.setProperty("role", "muted")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        browse = QPushButton("Open capture…")
        browse.setObjectName("PrimaryButton")
        browse.setCursor(Qt.CursorShape.PointingHandCursor)
        browse.setMinimumWidth(_BUTTON_WIDTH)
        browse.clicked.connect(self.browse_requested)
        shortcut = QLabel("or press Ctrl+O")
        shortcut.setObjectName("ShortcutHint")
        shortcut.setAlignment(Qt.AlignmentFlag.AlignCenter)

        steps_box = QWidget()
        steps = QVBoxLayout(steps_box)
        steps.setContentsMargins(0, 0, 0, 0)
        steps.setSpacing(10)
        for number, text in enumerate(
            (
                "The decoder unwraps each switch-to-collector telemetry report",
                "Flows are built from the inner packets only",
                (
                    f"Every flow carries the {len(FLOW_CSV_COLUMNS)} features "
                    "of the PIPELINE_V2 codebook"
                ),
            ),
            start=1,
        ):
            steps.addLayout(_step(number, text))

        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.addStretch(1)
        layout.addWidget(icon, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addSpacing(20)
        layout.addWidget(title)
        layout.addSpacing(6)
        layout.addWidget(hint)
        layout.addSpacing(20)
        layout.addWidget(browse, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addSpacing(6)
        layout.addWidget(shortcut)
        layout.addSpacing(32)
        layout.addWidget(steps_box, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)

    def _set_active(self, *, active: bool) -> None:
        """
        Highlight the zone while a drag hovers over it.

        Args:
            active: Whether a drag is in progress over the zone.

        """
        self.setProperty("active", "true" if active else "false")
        repolish(self)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802 - Qt API
        """
        Accept a drag that carries at least one capture file.

        Args:
            event: The drag event.

        """
        paths = [url.toLocalFile() for url in event.mimeData().urls()]
        if capture_from_urls(paths) is not None:
            event.acceptProposedAction()
            self._set_active(active=True)

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:  # noqa: N802 - Qt API
        """
        Remove the highlight when the drag leaves.

        Args:
            event: The drag event.

        """
        del event
        self._set_active(active=False)

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802 - Qt API
        """
        Emit the dropped capture.

        Args:
            event: The drop event.

        """
        self._set_active(active=False)
        paths = [url.toLocalFile() for url in event.mimeData().urls()]
        capture = capture_from_urls(paths)
        if capture is not None:
            event.acceptProposedAction()
            self.capture_dropped.emit(capture)
