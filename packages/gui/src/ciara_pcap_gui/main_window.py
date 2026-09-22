"""
The desktop analyst window.

The upload, the polling and the paging all run as coroutines on the Qt event
loop courtesy of ``qasync``: the window keeps repainting, the progress bar
keeps animating and the user can still sort the table while a capture is being
parsed on the server. No worker threads, no cross-thread signal marshalling.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from ciara_pcap_client import (
    DEFAULT_BASE_URL,
    ApiError,
    analyze_capture,
    build_client,
    check_health,
    format_bytes,
    ranked_applications,
    value_or,
)
from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTableView,
    QVBoxLayout,
    QWidget,
)
from qasync import (  # pyright: ignore[reportMissingTypeStubs] - qasync ships no stubs
    asyncSlot,  # pyright: ignore[reportUnknownVariableType]
)

from ciara_pcap_gui.models import SORT_ROLE, FlowTableModel

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import AnalysisJob

logger = logging.getLogger(__name__)

CAPTURE_FILTER = "Packet captures (*.pcap *.pcapng *.cap);;All files (*)"

#: Applications named in the one-line summary above the table.
_TOP_APPLICATIONS = 5


class MainWindow(QMainWindow):
    """Lets an analyst pick a capture, upload it and read the resulting flows."""

    def __init__(self, api_url: str = DEFAULT_BASE_URL) -> None:
        """
        Build the window.

        Args:
            api_url: Backend URL pre-filled in the toolbar.

        """
        super().__init__()
        self.setWindowTitle("CIARA PCAP Analyzer")
        self.resize(1180, 720)

        self._model = FlowTableModel(self)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setSortRole(SORT_ROLE)
        self._proxy.setFilterKeyColumn(-1)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        self._api_url = QLineEdit(api_url)
        self._api_url.setPlaceholderText(DEFAULT_BASE_URL)
        self._api_url.setClearButtonEnabled(True)

        self._open_button = QPushButton("Open capture…")
        self._open_button.setDefault(True)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Filter flows (IP, port, application, SNI)…")
        self._filter.setClearButtonEnabled(True)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._progress.setMaximumWidth(220)

        self._summary = QLabel("No capture loaded.")
        self._summary.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._summary.setWordWrap(True)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self._table.horizontalHeader().setStretchLastSection(True)

        self.setStatusBar(QStatusBar())
        self._build_layout()
        self._build_actions()

        self._open_button.clicked.connect(self._on_open_capture)
        self._filter.textChanged.connect(self._proxy.setFilterFixedString)

        self._busy = False
        self._set_status("Ready. Choose a capture to analyse.")

    def _build_layout(self) -> None:
        """Assemble the widget tree."""
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("API"))
        toolbar.addWidget(self._api_url, stretch=1)
        toolbar.addWidget(self._open_button)
        toolbar.addWidget(self._progress)

        root = QVBoxLayout()
        root.addLayout(toolbar)
        root.addWidget(self._summary)
        root.addWidget(self._filter)
        root.addWidget(self._table, stretch=1)

        container = QWidget()
        container.setLayout(root)
        self.setCentralWidget(container)

    def _build_actions(self) -> None:
        """Register the window's menu actions and shortcuts."""
        open_action = QAction("&Open capture…", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._on_open_capture)

        health_action = QAction("Check &backend", self)
        health_action.triggered.connect(self._on_check_health)

        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)

        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction(open_action)
        file_menu.addAction(health_action)
        file_menu.addSeparator()
        file_menu.addAction(quit_action)

    @asyncSlot()
    async def _on_check_health(self) -> None:
        """Confirm the configured backend is reachable and report the result."""
        url = self._api_url.text().strip() or DEFAULT_BASE_URL
        try:
            async with build_client(url) as client:
                payload = await check_health(client)
        except (ApiError, OSError) as exc:
            QMessageBox.critical(self, "Backend unreachable", f"{url}\n\n{exc}")
            return
        self._set_status(f"{payload.service} at {url} is {payload.status}.")

    @asyncSlot()
    async def _on_open_capture(self) -> None:
        """Pick a capture, upload it and display the flows it produced."""
        if self._busy:
            return

        selected, _ = QFileDialog.getOpenFileName(
            self, "Select a packet capture", "", CAPTURE_FILTER
        )
        if not selected:
            return

        await self._analyze(Path(selected))

    async def _analyze(self, pcap_path: Path) -> None:
        """
        Run the analysis workflow against the backend and render the result.

        Args:
            pcap_path: The capture the user selected.

        """
        url = self._api_url.text().strip() or DEFAULT_BASE_URL
        self._set_busy(busy=True)
        self._model.set_flows([])
        self._summary.setText(f"Uploading {pcap_path.name}…")

        try:
            async with build_client(url) as client:
                job, flows = await analyze_capture(
                    client,
                    pcap_path,
                    on_update=self._on_job_update,
                    on_page=self._on_flow_page,
                )
        except (ApiError, OSError) as exc:
            self._summary.setText("Analysis failed.")
            self._set_status("Analysis failed.")
            QMessageBox.critical(self, "Analysis failed", str(exc))
            return
        finally:
            self._set_busy(busy=False)

        if job.status != "succeeded":
            detail = job.error or "The backend gave no detail."
            self._summary.setText(f"Analysis of {job.filename} failed.")
            QMessageBox.warning(self, "Analysis failed", detail)
            self._set_status("Analysis failed.")
            return

        self._model.set_flows(flows)
        self._table.resizeColumnsToContents()
        self._summary.setText(self._describe(job))
        self._set_status(f"Loaded {len(flows)} flows from {job.filename}.")

    def _on_job_update(self, job: "AnalysisJob") -> None:
        """
        Report a polled job state in the status bar.

        Args:
            job: The job state just read from the backend.

        """
        self._set_status(f"Job {job.job_id} is {job.status}…")

    def _on_flow_page(self, loaded: int, total: int) -> None:
        """
        Report flow download progress.

        Args:
            loaded: Flows received so far.
            total: Flows the backend holds for this job.

        """
        if total:
            self._progress.setRange(0, total)
            self._progress.setValue(loaded)
        self._set_status(f"Fetched {loaded} of {total} flows…")

    def _set_busy(self, *, busy: bool) -> None:
        """
        Reflect whether an analysis is in flight.

        Args:
            busy: True while the workflow is running.

        """
        self._busy = busy
        self._open_button.setEnabled(not busy)
        self._api_url.setEnabled(not busy)
        self._progress.setVisible(busy)
        if busy:
            self._progress.setRange(0, 0)

    def _set_status(self, message: str) -> None:
        """
        Write a message to the status bar.

        Args:
            message: The message to show.

        """
        self.statusBar().showMessage(message)

    @staticmethod
    def _describe(job: "AnalysisJob") -> str:
        """
        Build the one-line capture summary shown above the table.

        Args:
            job: The completed job.

        Returns:
            A human-readable summary.

        """
        summary = value_or(job.summary, None)
        if summary is None:
            return f"{job.filename}: analysed."

        headline = (
            f"{job.filename} — {summary.flow_count} flows, "
            f"{summary.packet_count} packets, {format_bytes(summary.byte_count)}"
        )
        top = ", ".join(
            f"{name} ({count})"
            for name, count in ranked_applications(summary, top=_TOP_APPLICATIONS)
        )
        return f"{headline} — top applications: {top}" if top else headline
