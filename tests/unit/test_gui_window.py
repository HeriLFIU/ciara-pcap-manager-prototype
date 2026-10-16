"""
Tests for the desktop window, its pages and widgets.

The workflow helpers are replaced, so no backend is needed, and modal dialogs
are stubbed so nothing waits for a click. These tests need the Qt widget
libraries (``libEGL`` on Linux); on a host without them the module is skipped
with the reason shown, and ``docs/developer-guide.md`` says how to install them.
"""

import csv
import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

try:
    from PySide6.QtWidgets import QApplication, QMessageBox
except ImportError as exc:  # pragma: no cover - depends on the host
    pytest.skip(
        f"Qt widget libraries are not installed on this host: {exc}",
        allow_module_level=True,
    )

from ciara_pcap_client import ApiError
from ciara_pcap_gui import main_window as window_module
from ciara_pcap_gui.main_window import MainWindow
from ciara_pcap_gui.pages import PAGES
from ciara_pcap_gui.theme import DARK, LIGHT, ThemeMode, build_stylesheet
from ciara_pcap_gui.widgets.drop_zone import capture_from_urls
from ciara_pcap_sdk.models import AnalysisJob, Flow
from PySide6.QtCore import QCoreApplication, QSettings

from tests.support.factories import make_flow, summary_payload

JOB_ID = UUID("11111111-2222-3333-4444-555555555555")


def sdk_job(status: str = "succeeded", **extra: Any) -> AnalysisJob:  # noqa: ANN401 - JSON
    """An SDK job with a summary of two flows."""
    payload: dict[str, Any] = {
        "job_id": str(JOB_ID),
        "status": status,
        "filename": "capture.pcap",
        "size_bytes": 4096,
        "created_at": "2026-10-15T12:00:00Z",
        "summary": summary_payload(make_flow(), make_flow(proto=17, port_a=5353)),
    } | extra
    return AnalysisJob.from_dict(payload)


def sdk_flows() -> list[Flow]:
    """A TCP flow and a UDP flow."""
    return [
        Flow.from_dict(json.loads(make_flow().model_dump_json())),
        Flow.from_dict(json.loads(make_flow(proto=17, port_a=5353).model_dump_json())),
    ]


class FakeClient:
    """Stands in for the SDK client; the workflow helpers are stubbed."""

    async def __aenter__(self) -> "FakeClient":
        """Enter the context."""
        return self

    async def __aexit__(self, *_: object) -> None:
        """Leave the context."""
        return


@pytest.fixture
def messages(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Capture modal message boxes instead of showing them."""
    shown: list[str] = []

    def record(*args: object, **_: object) -> None:
        shown.append(str(args[1]))

    for name in ("critical", "warning", "about"):
        monkeypatch.setattr(QMessageBox, name, record)
    return shown


@pytest.fixture
def window(
    qt_app: QCoreApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    messages: list[str],  # noqa: ARG001 - dialogs must be stubbed for every window
) -> MainWindow:
    """A window with temporary settings and a fake backend client."""
    assert isinstance(qt_app, QApplication)

    def fake_client(*_: object, **__: object) -> FakeClient:
        return FakeClient()

    monkeypatch.setattr(window_module, "build_client", fake_client)
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    return MainWindow("http://backend", settings=settings, check_backend_on_start=False)


def stub(monkeypatch: pytest.MonkeyPatch, name: str, result: Any) -> None:  # noqa: ANN401 - any outcome
    """Replace one workflow helper on the window module."""

    async def fake(*_: object, **__: object) -> Any:  # noqa: ANN401 - passthrough
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(window_module, name, fake)


def test_every_registered_page_gets_a_sidebar_button(window: MainWindow) -> None:
    assert [type(page) for page in window.pages] == list(PAGES)
    assert window.stack.count() == len(PAGES)
    assert [button.text() for button in window.nav.buttons()] == [
        p.title for p in PAGES
    ]


def test_switching_pages_updates_the_header(window: MainWindow) -> None:
    window.show_page(1)

    assert window.current_page() is window.flows
    assert window.page_title.text() == "Flows"
    assert window.nav.checkedId() == 1


def test_the_overview_starts_with_the_drop_zone(window: MainWindow) -> None:
    assert window.overview.drop_zone.isVisibleTo(window.overview)
    assert not window.export_action.isEnabled()


def test_loading_an_analysis_fills_the_cards(window: MainWindow) -> None:
    window.state.load(sdk_job(), sdk_flows())

    cards = window.overview.cards
    assert cards["flows"].value == "2"
    assert cards["packets"].value == "10"
    assert cards["packets"].caption == "of 12 frames read"
    assert cards["int"].value == "100.0%"
    assert cards["order"].value == "2"
    assert window.overview.protocols.entries == [("TCP", 1), ("UDP", 1)]
    assert window.overview.decode.entries == [("not_telemetry_port", 2)]
    assert window.export_action.isEnabled()


def test_selecting_a_flow_shows_its_features(window: MainWindow) -> None:
    window.state.load(sdk_job(), sdk_flows())

    window.flows.table.selectRow(0)

    selected = window.flows.selected_flow()
    assert selected is not None
    assert window.flows.detail.title.startswith(f"{selected.ip_a}:{selected.port_a}")
    assert window.flows.detail.feature_value("proto") == str(selected.proto)
    assert window.flows.detail.feature_value("pkts_total") == "3"


def test_the_flow_filters(window: MainWindow) -> None:
    window.state.load(sdk_job(), sdk_flows())

    window.flows.search.setText("5353")
    assert window.flows.count.text() == "1 of 2 flows"
    window.flows.search.setText("")
    window.flows.protocol.setCurrentIndex(1)  # TCP
    assert window.flows.count.text() == "1 of 2 flows"


def test_csv_export_writes_codebook_columns(window: MainWindow, tmp_path: Path) -> None:
    window.state.load(sdk_job(), sdk_flows())
    destination = tmp_path / "flows.csv"

    assert window.export_csv(destination) == 2

    with destination.open(encoding="utf-8", newline="") as handle:
        header, *rows = list(csv.reader(handle))
    assert header[:3] == ["base_flow_key", "flow_id", "flow_segment_id"]
    assert len(rows) == 2


def test_a_failed_export_is_reported(
    window: MainWindow, tmp_path: Path, messages: list[str]
) -> None:
    window.state.load(sdk_job(), sdk_flows())

    assert window.export_csv(tmp_path / "missing" / "flows.csv") == 0
    assert messages == ["Export failed"]


async def test_analyze_path_loads_the_result(
    window: MainWindow, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stub(monkeypatch, "analyze_capture", (sdk_job(), sdk_flows()))

    assert await window.analyze_path(tmp_path / "capture.pcap") is True

    assert len(window.state.flows) == 2
    assert window.current_page() is window.overview
    assert window.open_button.isEnabled()
    assert "Backend online" in window.backend_chip.text()


async def test_a_failed_job_is_reported(
    window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    messages: list[str],
) -> None:
    stub(monkeypatch, "analyze_capture", (sdk_job("failed", error="bad capture"), []))

    assert await window.analyze_path(tmp_path / "capture.pcap") is False
    assert messages == ["Analysis failed"]
    assert window.state.job is None


async def test_an_unreachable_backend_is_reported(
    window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    messages: list[str],
) -> None:
    stub(monkeypatch, "analyze_capture", ApiError("connection refused"))

    assert await window.analyze_path(tmp_path / "capture.pcap") is False
    assert messages == ["Analysis failed"]
    assert window.open_button.isEnabled()


async def test_the_backend_check_updates_the_chip(
    window: MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub(monkeypatch, "check_health", object())
    assert await window.check_backend() is True
    assert window.backend_chip.property("state") == "ok"

    stub(monkeypatch, "check_health", OSError("refused"))
    assert await window.check_backend() is False
    assert window.backend_chip.property("state") == "error"


async def test_history_lists_jobs_and_opens_one(
    window: MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub(monkeypatch, "list_jobs", [sdk_job(), sdk_job("failed")])
    stub(monkeypatch, "get_job", sdk_job())
    stub(monkeypatch, "fetch_all_flows", sdk_flows())
    opened: list[UUID] = []
    window.history.job_activated.connect(opened.append)

    await window.refresh_history()
    window.history.table.selectRow(1)
    window.history.open_button.click()
    window.history.table.selectRow(0)
    window.history.open_button.click()

    assert window.history.model.rowCount() == 2
    assert opened == [JOB_ID]
    assert await window.open_job(JOB_ID) is True
    assert len(window.state.flows) == 2


async def test_a_history_failure_is_shown_on_the_page(
    window: MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub(monkeypatch, "list_jobs", ApiError("down"))

    await window.refresh_history()

    assert "Could not list analyses" in window.history.message.text()


def test_the_theme_toggle_is_remembered(window: MainWindow) -> None:
    start = window.theme

    window.toggle_theme()

    assert window.theme != start
    assert window.settings.value("theme") == window.theme.value


def test_both_palettes_render_a_stylesheet() -> None:
    for palette in (LIGHT, DARK):
        sheet = build_stylesheet(palette)
        assert palette.accent in sheet
        assert "QFrame#Card" in sheet
    assert {mode.value for mode in ThemeMode} == {"light", "dark"}


def test_only_capture_files_are_accepted_by_drag_and_drop(tmp_path: Path) -> None:
    capture = tmp_path / "trace.PCAPNG"
    capture.write_bytes(b"x")
    notes = tmp_path / "notes.txt"
    notes.write_text("x", encoding="utf-8")

    assert capture_from_urls([str(notes), str(capture)]) == capture
    assert capture_from_urls([str(notes), str(tmp_path / "gone.pcap")]) is None
