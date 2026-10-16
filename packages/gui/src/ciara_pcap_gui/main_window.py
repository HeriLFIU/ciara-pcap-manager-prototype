"""
The application shell: sidebar, header, pages and the controller logic.

The window owns every side effect -- HTTP calls through
:mod:`ciara_pcap_client`, file dialogs, CSV export and settings -- and the
pages stay pure views (see :mod:`ciara_pcap_gui.pages.base`).

Uploads, polling and paging run as coroutines on the Qt event loop courtesy
of ``qasync``: the window keeps repainting and stays usable while the backend
parses a capture. No worker threads, no cross-thread signal marshalling.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from ciara_pcap_client import (
    DEFAULT_BASE_URL,
    ApiError,
    analyze_capture,
    build_client,
    check_health,
    fetch_all_flows,
    format_count,
    get_job,
    list_jobs,
    write_flows_csv,
)
from PySide6.QtCore import QSettings, Qt, QTimer, Signal
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QDragEnterEvent,
    QDropEvent,
    QKeySequence,
)
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)
from qasync import (  # pyright: ignore[reportMissingTypeStubs] - qasync ships no stubs
    asyncSlot,  # pyright: ignore[reportUnknownVariableType]
)

from ciara_pcap_gui.pages import PAGES, FlowsPage, HistoryPage, OverviewPage, Page
from ciara_pcap_gui.state import AnalysisState
from ciara_pcap_gui.theme import ThemeMode, apply_theme, repolish, resolve_theme
from ciara_pcap_gui.widgets.drop_zone import capture_from_urls

if TYPE_CHECKING:
    from collections.abc import Callable

    from ciara_pcap_sdk.models import AnalysisJob

logger = logging.getLogger(__name__)

APP_TITLE = "CIARA PCAP Analyzer"
CAPTURE_FILTER = "Packet captures (*.pcap *.pcapng *.cap);;All files (*)"
CSV_FILTER = "CSV files (*.csv);;All files (*)"

SETTING_API_URL = "api_url"
SETTING_THEME = "theme"
SETTING_GEOMETRY = "geometry"


class MainWindow(QMainWindow):
    """Lets an analyst open a capture, read its flows and export them."""

    capture_requested = Signal(Path)
    """A capture was dropped onto the window and should be analysed."""

    def __init__(
        self,
        api_url: str = DEFAULT_BASE_URL,
        *,
        settings: QSettings | None = None,
        check_backend_on_start: bool = True,
    ) -> None:
        """
        Build the window.

        Args:
            api_url: Backend URL used when no URL was saved in the settings.
            settings: Where to persist the URL, theme and geometry. Defaults to
                the per-user application settings; tests pass a temporary file.
            check_backend_on_start: Ping the backend once the loop is running.

        """
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1320, 820)
        self.setAcceptDrops(True)

        self.settings = settings or QSettings()
        self.state = AnalysisState(self)
        self._busy = False

        self.pages: list[Page] = [page_class(self.state) for page_class in PAGES]
        self.overview = self._page(OverviewPage)
        self.flows = self._page(FlowsPage)
        self.history = self._page(HistoryPage)

        self._build_header_widgets(api_url)
        self.setCentralWidget(self._build_shell())
        self.setStatusBar(QStatusBar())
        self.statusBar().addPermanentWidget(self.progress)
        self._build_menus()
        self._connect_pages()

        self.theme = ThemeMode.LIGHT
        app = QApplication.instance()
        if isinstance(app, QApplication):
            self.theme = resolve_theme(self.settings.value(SETTING_THEME), app)
            apply_theme(app, self.theme)
        geometry = self.settings.value(SETTING_GEOMETRY)
        if geometry is not None:
            self.restoreGeometry(geometry)  # pyright: ignore[reportArgumentType]

        self.show_page(0)
        self.set_status("Ready. Open a capture of INT telemetry reports to begin.")
        if check_backend_on_start:
            QTimer.singleShot(0, self._on_check_backend)

    # -- Construction --------------------------------------------------------

    def _build_header_widgets(self, api_url: str) -> None:
        """
        Create the header's widgets, the page stack and the progress bar.

        Args:
            api_url: Backend URL used when no URL was saved in the settings.

        """
        saved_url = self.settings.value(SETTING_API_URL, api_url, type=str)
        self.api_url = QLineEdit(str(saved_url))
        self.api_url.setPlaceholderText(DEFAULT_BASE_URL)
        self.api_url.setToolTip("Base URL of the CIARA PCAP API")
        self.api_url.setMinimumWidth(240)
        self.api_url.editingFinished.connect(self._on_api_url_edited)
        self.api_url.editingFinished.connect(self._on_check_backend)
        self.backend_chip = QLabel("● Backend unknown")
        self.backend_chip.setObjectName("Chip")
        self.open_button = QPushButton("Open capture…")
        self.open_button.setObjectName("PrimaryButton")
        self.open_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_button.clicked.connect(self._on_open_capture)

        self.page_title = QLabel()
        self.page_title.setObjectName("PageTitle")
        self.page_subtitle = QLabel()
        self.page_subtitle.setObjectName("PageSubtitle")

        self.stack = QStackedWidget()
        self.nav = QButtonGroup(self)
        self.nav.setExclusive(True)
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setVisible(False)

    def _page[P: Page](self, page_class: type[P]) -> P:
        """
        Find the instance of a registered page class.

        Args:
            page_class: The page class.

        Returns:
            The page instance.

        Raises:
            LookupError: If the class is not registered in ``PAGES``.

        """
        for page in self.pages:
            if isinstance(page, page_class):
                return page
        msg = f"{page_class.__name__} is not registered in PAGES"
        raise LookupError(msg)

    def _build_shell(self) -> QWidget:
        """
        Assemble the sidebar, the header and the page stack.

        Returns:
            The central widget.

        """
        content = QWidget()
        column = QVBoxLayout(content)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(self._build_header())
        column.addWidget(self.stack, stretch=1)

        shell = QWidget()
        row = QHBoxLayout(shell)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addWidget(self._build_sidebar())
        row.addWidget(content, stretch=1)
        return shell

    def _build_sidebar(self) -> QFrame:
        """
        Build the navigation sidebar and register every page in the stack.

        Returns:
            The sidebar.

        """
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(208)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 18, 0, 14)
        side.setSpacing(2)
        brand = QLabel("CIARA")
        brand.setObjectName("Brand")
        caption = QLabel("INT flow analyzer")
        caption.setObjectName("BrandCaption")
        for label in (brand, caption):
            label.setContentsMargins(18, 0, 18, 0)
            side.addWidget(label)
        side.addSpacing(22)

        for position, page in enumerate(self.pages):
            self.stack.addWidget(page)
            button = QPushButton(page.title)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setToolTip(f"{page.subtitle} (Ctrl+{position + 1})")
            self.nav.addButton(button, position)
            side.addWidget(button)
        self.nav.idClicked.connect(self.show_page)
        side.addStretch(1)
        footer = QLabel(
            "Flows use the inner packets only; the outer report envelope is "
            "decoded, checked and discarded."
        )
        footer.setObjectName("SidebarFooter")
        footer.setWordWrap(True)
        footer.setContentsMargins(18, 0, 18, 0)
        side.addWidget(footer)

        return sidebar

    def _build_header(self) -> QFrame:
        """
        Build the header with the page title and the backend controls.

        Returns:
            The header bar.

        """
        header = QFrame()
        header.setObjectName("HeaderBar")
        top = QHBoxLayout(header)
        top.setContentsMargins(24, 14, 24, 14)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(self.page_title)
        titles.addWidget(self.page_subtitle)
        top.addLayout(titles, stretch=1)
        center = Qt.AlignmentFlag.AlignVCenter
        top.addWidget(self.backend_chip, alignment=center)
        top.addWidget(self.api_url, alignment=center)
        top.addWidget(self.open_button, alignment=center)

        return header

    def _build_menus(self) -> None:
        """Register the menu bar actions and their shortcuts."""
        file_menu = self.menuBar().addMenu("&File")
        self.open_action = self._action(
            "&Open capture…", self._on_open_capture, QKeySequence.StandardKey.Open
        )
        self.export_action = self._action(
            "&Export flows as CSV…", self._on_export, QKeySequence("Ctrl+E")
        )
        file_menu.addAction(self.open_action)
        file_menu.addAction(self.export_action)
        file_menu.addSeparator()
        file_menu.addAction(
            self._action("&Quit", self.close, QKeySequence.StandardKey.Quit)
        )

        view_menu = self.menuBar().addMenu("&View")
        for position, page in enumerate(self.pages):
            view_menu.addAction(
                self._action(
                    page.title,
                    self._page_switcher(position),
                    QKeySequence(f"Ctrl+{position + 1}"),
                )
            )
        view_menu.addSeparator()
        view_menu.addAction(
            self._action("&Find flows", self._on_find, QKeySequence.StandardKey.Find)
        )
        view_menu.addAction(
            self._action(
                "Toggle &dark theme", self.toggle_theme, QKeySequence("Ctrl+T")
            )
        )

        backend_menu = self.menuBar().addMenu("&Backend")
        backend_menu.addAction(
            self._action("&Check connection", self._on_check_backend)
        )
        backend_menu.addAction(
            self._action(
                "&Refresh history", self._on_refresh_history, QKeySequence("Ctrl+R")
            )
        )

        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction(self._action("&About", self._on_about))
        self.export_action.setEnabled(False)

    def _action(
        self,
        text: str,
        slot: "Callable[..., object]",
        shortcut: QKeySequence | QKeySequence.StandardKey | None = None,
    ) -> QAction:
        """
        Create a menu action.

        Args:
            text: The menu text.
            slot: Called when the action triggers.
            shortcut: Optional keyboard shortcut.

        Returns:
            The action, parented to the window.

        """
        action = QAction(text, self)
        if shortcut is not None:
            action.setShortcut(shortcut)
        action.triggered.connect(slot)
        return action

    def _page_switcher(self, index: int) -> "Callable[[], None]":
        """
        Build a slot that shows one page.

        Args:
            index: Position of the page in ``PAGES``.

        Returns:
            A zero-argument callable for a menu action.

        """

        def show() -> None:
            self.show_page(index)

        return show

    def _connect_pages(self) -> None:
        """Route the pages' requests to the controller methods."""
        for page in self.pages:
            page.open_requested.connect(self._on_open_capture)
            page.export_requested.connect(self._on_export)
        self.history.refresh_requested.connect(self._on_refresh_history)
        self.history.job_activated.connect(self._on_open_job)
        self.overview.drop_zone.capture_dropped.connect(self._on_capture_dropped)
        self.capture_requested.connect(self._on_capture_dropped)
        self.state.analysis_changed.connect(self._on_analysis_changed)

    # -- Presentation ----------------------------------------------------------

    def show_page(self, index: int) -> None:
        """
        Switch to a page.

        Args:
            index: Position of the page in ``PAGES``.

        """
        page = self.pages[index]
        self.stack.setCurrentWidget(page)
        self.nav.button(index).setChecked(True)
        self.page_title.setText(page.title)
        self.page_subtitle.setText(page.subtitle)

    def current_page(self) -> Page:
        """
        Return the page on screen.

        Returns:
            The current page.

        """
        widget = self.stack.currentWidget()
        assert isinstance(widget, Page)  # noqa: S101 - the stack only holds pages
        return widget

    def set_status(self, message: str) -> None:
        """
        Write a message to the status bar.

        Args:
            message: The message to show.

        """
        self.statusBar().showMessage(message)

    def set_backend_state(self, state: str, text: str) -> None:
        """
        Update the backend connection chip.

        Args:
            state: ``ok``, ``busy`` or ``error``; selects the chip colour.
            text: The chip text.

        """
        self.backend_chip.setText(f"● {text}")
        self.backend_chip.setProperty("state", state)
        repolish(self.backend_chip)

    def toggle_theme(self) -> None:
        """Switch between the light and the dark theme and remember the choice."""
        self.theme = (
            ThemeMode.DARK if self.theme == ThemeMode.LIGHT else ThemeMode.LIGHT
        )
        self.settings.setValue(SETTING_THEME, self.theme.value)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, self.theme)

    def _set_busy(self, *, busy: bool) -> None:
        """
        Reflect whether a backend operation is in flight.

        Args:
            busy: True while a workflow is running.

        """
        self._busy = busy
        self.open_button.setEnabled(not busy)
        self.open_action.setEnabled(not busy)
        self.api_url.setEnabled(not busy)
        self.export_action.setEnabled(not busy and bool(self.state.flows))
        self.flows.export_button.setEnabled(not busy and bool(self.state.flows))
        self.progress.setVisible(busy)
        if busy:
            self.progress.setRange(0, 0)

    def _on_analysis_changed(self) -> None:
        """Enable the export once flows are loaded."""
        has_flows = bool(self.state.flows)
        self.export_action.setEnabled(has_flows and not self._busy)

    def _url(self) -> str:
        """
        Read the backend URL from the header.

        Returns:
            The URL, or the default when the field is empty.

        """
        return self.api_url.text().strip() or DEFAULT_BASE_URL

    def _on_api_url_edited(self) -> None:
        """Remember the backend URL."""
        self.settings.setValue(SETTING_API_URL, self._url())

    def _on_find(self) -> None:
        """Jump to the flows page and focus its filter."""
        self.show_page(self.pages.index(self.flows))
        self.flows.focus_search()

    def _on_about(self) -> None:
        """Explain what the application does."""
        QMessageBox.about(
            self,
            f"About {APP_TITLE}",
            "Builds bidirectional flows from the inner packets of INT telemetry "
            "reports, with the PIPELINE_V2 codebook's features.\n\n"
            "The outer Ethernet/IPv4/UDP envelope and the telemetry report header "
            "are decoded and discarded; only the inner packet and its INT "
            "metadata feed the flows. See docs/ in the repository.",
        )

    # -- Backend workflows -------------------------------------------------------

    @asyncSlot()
    async def _on_check_backend(self) -> None:
        """Ping the backend and show the result on the chip."""
        await self.check_backend()

    async def check_backend(self) -> bool:
        """
        Ping the backend.

        Returns:
            True when it answered.

        """
        url = self._url()
        self.set_backend_state("busy", "Connecting…")
        try:
            async with build_client(url, timeout=5.0) as client:
                await check_health(client)
        except (ApiError, OSError) as exc:
            logger.info("Backend at %s is unreachable: %s", url, exc)
            self.set_backend_state("error", "Backend offline")
            self.set_status(
                f"Backend at {url} is unreachable. Start it with: uv run ciara-pcap-api"
            )
            return False
        self.set_backend_state("ok", "Backend online")
        return True

    @asyncSlot()
    async def _on_open_capture(self) -> None:
        """Pick a capture with a file dialog and analyse it."""
        if self._busy:
            return
        selected, _ = QFileDialog.getOpenFileName(
            self, "Select a packet capture", "", CAPTURE_FILTER
        )
        if selected:
            await self.analyze_path(Path(selected))

    @asyncSlot(Path)
    async def _on_capture_dropped(self, path: Path) -> None:
        """
        Analyse a capture dropped onto the window.

        Args:
            path: The dropped capture.

        """
        if not self._busy:
            await self.analyze_path(path)

    async def analyze_path(self, pcap_path: Path) -> bool:
        """
        Upload a capture, wait for the analysis and show the result.

        Args:
            pcap_path: The capture to analyse.

        Returns:
            True when the analysis succeeded and is on screen.

        """
        self._set_busy(busy=True)
        self.set_status(f"Uploading {pcap_path.name}…")
        try:
            async with build_client(self._url()) as client:
                job, flows = await analyze_capture(
                    client,
                    pcap_path,
                    on_update=self._on_job_update,
                    on_page=self._on_flow_page,
                )
        except (ApiError, OSError) as exc:
            self.set_status("Analysis failed.")
            self.set_backend_state("error", "Request failed")
            QMessageBox.critical(self, "Analysis failed", str(exc))
            return False
        finally:
            self._set_busy(busy=False)

        if job.status != "succeeded":
            detail = job.error if isinstance(job.error, str) else "No detail given."
            self.set_status(f"Analysis of {job.filename} failed.")
            QMessageBox.warning(self, "Analysis failed", detail)
            return False

        self.set_backend_state("ok", "Backend online")
        self.state.load(job, flows)
        self.show_page(self.pages.index(self.overview))
        self.set_status(f"Loaded {format_count(len(flows))} flows from {job.filename}.")
        return True

    @asyncSlot()
    async def _on_refresh_history(self) -> None:
        """Reload the job list on the history page."""
        await self.refresh_history()

    async def refresh_history(self) -> None:
        """Fetch the job list from the backend and show it."""
        try:
            async with build_client(self._url()) as client:
                jobs = await list_jobs(client)
        except (ApiError, OSError) as exc:
            self.history.set_error(f"Could not list analyses: {exc}")
            self.set_backend_state("error", "Backend offline")
            return
        self.history.set_jobs(jobs)
        self.set_backend_state("ok", "Backend online")

    @asyncSlot(UUID)
    async def _on_open_job(self, job_id: UUID) -> None:
        """
        Open a finished job from the history page.

        Args:
            job_id: The job to open.

        """
        await self.open_job(job_id)

    async def open_job(self, job_id: UUID) -> bool:
        """
        Load a finished job and its flows from the backend.

        Args:
            job_id: The job to open.

        Returns:
            True when the job is on screen.

        """
        self._set_busy(busy=True)
        try:
            async with build_client(self._url()) as client:
                job = await get_job(client, job_id)
                flows = await fetch_all_flows(
                    client, job_id, on_page=self._on_flow_page
                )
        except (ApiError, OSError) as exc:
            QMessageBox.critical(self, "Could not open the analysis", str(exc))
            return False
        finally:
            self._set_busy(busy=False)
        self.state.load(job, flows)
        self.show_page(self.pages.index(self.overview))
        self.set_status(f"Opened {job.filename}: {format_count(len(flows))} flows.")
        return True

    def _on_job_update(self, job: "AnalysisJob") -> None:
        """
        Report a polled job state in the status bar.

        Args:
            job: The job state just read from the backend.

        """
        self.set_status(f"{job.filename}: {job.status}…")

    def _on_flow_page(self, loaded: int, total: int) -> None:
        """
        Report flow download progress.

        Args:
            loaded: Flows received so far.
            total: Flows the backend holds for this job.

        """
        if total:
            self.progress.setRange(0, total)
            self.progress.setValue(loaded)
        self.set_status(
            f"Downloaded {format_count(loaded)} of {format_count(total)} flows…"
        )

    # -- Export ------------------------------------------------------------------

    def _on_export(self) -> None:
        """Ask where to save the flows, then write them."""
        job = self.state.job
        if job is None or not self.state.flows:
            return
        suggested = f"{Path(job.filename).stem}_flows.csv"
        selected, _ = QFileDialog.getSaveFileName(
            self, "Export flows as CSV", suggested, CSV_FILTER
        )
        if selected:
            self.export_csv(Path(selected))

    def export_csv(self, path: Path) -> int:
        """
        Write the loaded flows to a CSV file in codebook column order.

        Args:
            path: Destination file.

        Returns:
            The number of rows written, or 0 when the write failed.

        """
        try:
            with path.open("w", encoding="utf-8", newline="") as handle:
                rows = write_flows_csv(self.state.flows, handle)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", f"{path}\n\n{exc}")
            return 0
        self.set_status(f"Wrote {format_count(rows)} flows to {path}.")
        return rows

    # -- Window events -------------------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802 - Qt API
        """
        Accept a capture dragged anywhere onto the window.

        Args:
            event: The drag event.

        """
        paths = [url.toLocalFile() for url in event.mimeData().urls()]
        if not self._busy and capture_from_urls(paths) is not None:
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802 - Qt API
        """
        Analyse a capture dropped anywhere onto the window.

        Args:
            event: The drop event.

        """
        paths = [url.toLocalFile() for url in event.mimeData().urls()]
        capture = capture_from_urls(paths)
        if capture is not None:
            event.acceptProposedAction()
            self.capture_requested.emit(capture)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt API
        """
        Remember the window geometry on close.

        Args:
            event: The close event.

        """
        self.settings.setValue(SETTING_GEOMETRY, self.saveGeometry())
        super().closeEvent(event)
