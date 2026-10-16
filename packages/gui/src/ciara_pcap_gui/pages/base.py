"""
The contract every page of the window follows.

A page is a view. It renders `AnalysisState` and emits signals when the user
asks for something that needs the backend or the file system; the main window
performs the request. That keeps network code in one place and makes every
page testable without a server.

To add a page: subclass `Page`, set `title` and `subtitle`, build the widgets in
``__init__``, redraw in `refresh`, and append the class to
``ciara_pcap_gui.pages.PAGES``. The sidebar, the header and the keyboard
shortcut (Ctrl+<position>) follow automatically.
"""

from typing import ClassVar

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QVBoxLayout, QWidget

from ciara_pcap_gui.state import AnalysisState


class Page(QWidget):
    """Base class for a top-level page shown in the window's content area."""

    title: ClassVar[str] = "Page"
    """Shown in the sidebar and as the header title."""

    subtitle: ClassVar[str] = ""
    """Shown under the header title."""

    open_requested = Signal()
    """The user asked to open a capture file."""

    export_requested = Signal()
    """The user asked to export the loaded flows as CSV."""

    def __init__(self, state: AnalysisState, parent: QWidget | None = None) -> None:
        """
        Create the page and subscribe it to the shared state.

        Args:
            state: The analysis on screen.
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self.setObjectName("Page")
        self.state = state
        self.layout_root = QVBoxLayout(self)
        self.layout_root.setContentsMargins(24, 20, 24, 20)
        self.layout_root.setSpacing(16)
        state.analysis_changed.connect(self.refresh)

    def refresh(self) -> None:
        """Redraw the page from the shared state. Subclasses override this."""

    def badge(self) -> str:
        """
        Return a short count shown next to the page in the sidebar.

        Returns:
            The badge text; empty hides the badge. Subclasses override this.

        """
        return ""
