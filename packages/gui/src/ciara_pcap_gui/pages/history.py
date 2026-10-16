"""The history page: every analysis job the backend knows about."""

from typing import TYPE_CHECKING
from uuid import UUID

from ciara_pcap_sdk.types import Unset
from PySide6.QtCore import QModelIndex, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableView,
    QWidget,
)

from ciara_pcap_gui.models import JOB_COLUMNS, ObjectTableModel
from ciara_pcap_gui.pages.base import Page

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import AnalysisJob

    from ciara_pcap_gui.state import AnalysisState


class HistoryPage(Page):
    """Lists past analyses and reopens one on request."""

    title = "History"
    subtitle = "Analyses held by the backend (kept in memory until it restarts)"

    refresh_requested = Signal()
    """The user asked to reload the job list."""

    job_activated = Signal(UUID)
    """The user asked to open a finished job."""

    def __init__(self, state: "AnalysisState", parent: QWidget | None = None) -> None:
        """
        Build the page.

        Args:
            state: The analysis on screen.
            parent: Optional Qt parent.

        """
        super().__init__(state, parent)
        self.model: ObjectTableModel[AnalysisJob] = ObjectTableModel(JOB_COLUMNS, self)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_requested)
        self.open_button = QPushButton("Open selected")
        self.open_button.setObjectName("PrimaryButton")
        self.open_button.clicked.connect(self._open_selected)
        self.message = QLabel("Press Refresh to list the backend's analyses.")
        self.message.setProperty("role", "muted")

        toolbar = QHBoxLayout()
        toolbar.addWidget(self.message, stretch=1)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.open_button)

        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(self._on_double_click)

        self.layout_root.addLayout(toolbar)
        self.layout_root.addWidget(self.table, stretch=1)

    def set_jobs(self, jobs: "list[AnalysisJob]") -> None:
        """
        Show a fresh job list.

        Args:
            jobs: The jobs, newest first.

        """
        self.model.set_rows(jobs)
        self.message.setText(
            f"{len(jobs)} analyses. Double-click a succeeded one to open it."
            if jobs
            else "The backend has no analyses yet."
        )

    def set_error(self, message: str) -> None:
        """
        Report that the job list could not be loaded.

        Args:
            message: What went wrong.

        """
        self.message.setText(message)

    def _on_double_click(self, index: QModelIndex) -> None:
        """
        Open the job on the double-clicked row.

        Args:
            index: The clicked cell.

        """
        self._activate(index.row())

    def _open_selected(self) -> None:
        """Open the job on the selected row, if any."""
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self._activate(rows[0].row())

    def _activate(self, row: int) -> None:
        """
        Ask the window to open a job, if it finished successfully.

        Args:
            row: The model row.

        """
        job = self.model.row_object(row)
        if job.status != "succeeded" or isinstance(job.job_id, Unset):
            self.message.setText(
                f"{job.filename} is {job.status}; only succeeded analyses open."
            )
            return
        self.job_activated.emit(job.job_id)
