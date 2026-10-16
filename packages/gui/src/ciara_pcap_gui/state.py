"""
The analysis currently on screen, shared by every page.

Pages never talk to each other. They read this object and redraw when it
announces a change, so a new page only needs to listen to `analysis_changed`.
"""

from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, Signal

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ciara_pcap_sdk.models import AnalysisJob, Flow


class AnalysisState(QObject):
    """Holds the loaded job and its flows and announces changes."""

    analysis_changed = Signal()
    """Emitted after a different analysis was loaded or the state was cleared."""

    def __init__(self, parent: QObject | None = None) -> None:
        """
        Create an empty state.

        Args:
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self._job: AnalysisJob | None = None
        self._flows: list[Flow] = []

    @property
    def job(self) -> "AnalysisJob | None":
        """
        The loaded job, or None before anything was analysed.

        Returns:
            The job.

        """
        return self._job

    @property
    def flows(self) -> "list[Flow]":
        """
        The loaded job's flows, in backend order.

        Returns:
            The flows.

        """
        return self._flows

    def load(self, job: "AnalysisJob", flows: "Sequence[Flow]") -> None:
        """
        Replace the analysis on screen.

        Args:
            job: The finished job.
            flows: Its flows.

        """
        self._job = job
        self._flows = list(flows)
        self.analysis_changed.emit()

    def clear(self) -> None:
        """Forget the analysis on screen."""
        self._job = None
        self._flows = []
        self.analysis_changed.emit()
