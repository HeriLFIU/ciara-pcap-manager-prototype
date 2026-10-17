"""
Tests for the desktop window, its pages and widgets.

The workflow helpers are replaced, so no backend is needed, and modal dialogs
are stubbed so nothing waits for a click. These tests need the Qt widget
libraries (``libEGL`` on Linux); on a host without them the module is skipped
with the reason shown, and ``docs/developer-guide.md`` says how to install them.
"""

import asyncio
import csv
import json
import re
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

from ciara_pcap_client import FLOW_CSV_COLUMNS, ApiError
from ciara_pcap_gui import main_window as window_module
from ciara_pcap_gui.main_window import MainWindow
from ciara_pcap_gui.pages import PAGES, FlowsPage
from ciara_pcap_gui.state import AnalysisState
from ciara_pcap_gui.theme import (
    DARK,
    LIGHT,
    PALETTES,
    Palette,
    ThemeMode,
    build_stylesheet,
    contrast_ratio,
)
from ciara_pcap_gui.widgets.drop_zone import capture_from_urls
from ciara_pcap_gui.widgets.pill import PillDelegate
from ciara_pcap_sdk.models import AnalysisJob, Flow
from PySide6.QtCore import QCoreApplication, QRect, QSettings, Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPalette
from PySide6.QtWidgets import (
    QLabel,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QWidget,
)

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


def test_a_selected_flow_stays_selected_while_it_matches_the_filter(
    window: MainWindow,
) -> None:
    flows = sdk_flows()
    window.state.load(sdk_job(), flows)
    window.flows.table.selectRow(1)  # the UDP flow

    window.flows.search.setText("5353")

    assert window.flows.selected_flow() is flows[1]
    assert window.flows.detail.title.startswith(f"{flows[1].ip_a}:5353")


def test_filtering_out_the_selected_flow_clears_the_detail_panel(
    window: MainWindow,
) -> None:
    window.state.load(sdk_job(), sdk_flows())
    window.flows.table.selectRow(1)  # the UDP flow

    window.flows.protocol.setCurrentIndex(1)  # TCP

    assert window.flows.selected_flow() is None
    assert window.flows.detail.title == "No flow selected"


def test_sorting_keeps_the_selected_flow(window: MainWindow) -> None:
    flows = sdk_flows()
    window.state.load(sdk_job(), flows)
    window.flows.table.selectRow(0)
    column = [c.header for c in window.flows.model.columns].index("Endpoint A")

    window.flows.table.sortByColumn(column, Qt.SortOrder.DescendingOrder)

    assert window.flows.selected_flow() is flows[0]


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


async def test_opening_the_history_page_lists_the_jobs(
    window: MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub(monkeypatch, "list_jobs", [sdk_job(), sdk_job("failed")])

    window.show_page(window.pages.index(window.history))
    for _ in range(10):  # the refresh is a task; the stubs never wait on I/O
        await asyncio.sleep(0)

    assert window.history.model.rowCount() == 2


async def test_the_window_polls_the_job_quickly(
    window: MainWindow, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, object] = {}

    async def fake(*_: object, **kwargs: object) -> tuple[AnalysisJob, list[Flow]]:
        seen.update(kwargs)
        return sdk_job(), sdk_flows()

    monkeypatch.setattr(window_module, "analyze_capture", fake)

    await window.analyze_path(tmp_path / "capture.pcap")

    assert seen["poll_interval"] == pytest.approx(0.2)


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
        arrow = re.search(r'down-arrow \{ image: url\("([^"]+)"\)', sheet)
        assert arrow is not None
        assert Path(arrow.group(1)).is_file()
    assert {mode.value for mode in ThemeMode} == {"light", "dark"}


def test_only_capture_files_are_accepted_by_drag_and_drop(tmp_path: Path) -> None:
    capture = tmp_path / "trace.PCAPNG"
    capture.write_bytes(b"x")
    notes = tmp_path / "notes.txt"
    notes.write_text("x", encoding="utf-8")

    assert capture_from_urls([str(notes), str(capture)]) == capture
    assert capture_from_urls([str(notes), str(tmp_path / "gone.pcap")]) is None


# -- Contrast ------------------------------------------------------------------

#: WCAG 2.2: 4.5:1 for text (1.4.3), 3:1 for component boundaries (1.4.11).
AA_TEXT = 4.5
AA_NON_TEXT = 3.0
#: Body text is held to the enhanced level (1.4.6).
AAA_TEXT = 7.0


def contrast_pairs(p: Palette) -> list[tuple[str, str, str, float]]:
    """Every foreground and background the stylesheet puts together."""
    pairs: list[tuple[str, str, str, float]] = []
    for ground in ("window", "surface", "surface_alt"):
        pairs.append(("text", ground, getattr(p, ground), AAA_TEXT))
        pairs.append(("text_muted", ground, getattr(p, ground), AA_TEXT))
        pairs.append(("border_strong", ground, getattr(p, ground), AA_NON_TEXT))
    pairs += [
        ("text", "selection", p.selection, AAA_TEXT),
        ("text", "hover", p.hover, AAA_TEXT),
        ("accent_text", "accent", p.accent, AA_TEXT),
        ("accent_text", "accent_hover", p.accent_hover, AA_TEXT),
        ("accent", "surface", p.surface, AA_TEXT),
        ("accent", "accent_soft", p.accent_soft, AA_TEXT),
        ("sidebar_text", "sidebar", p.sidebar, AA_TEXT),
        ("sidebar_text", "sidebar_active", p.sidebar_active, AA_TEXT),
        ("sidebar_muted", "sidebar", p.sidebar, AA_TEXT),
        ("sidebar_strong", "sidebar_active", p.sidebar_active, AAA_TEXT),
    ]
    for tone in ("secondary", "success", "warning", "danger"):
        pairs.append((tone, "surface", p.surface, AA_TEXT))
        pairs.append((tone, f"{tone}_soft", getattr(p, f"{tone}_soft"), AA_TEXT))
    pairs.append(("text_muted", "neutral_soft", p.neutral_soft, AA_TEXT))
    return pairs


@pytest.mark.parametrize("palette", [LIGHT, DARK], ids=["light", "dark"])
def test_every_palette_meets_wcag_contrast(palette: Palette) -> None:
    failures = [
        f"{fg} on {bg}: {ratio:.2f} < {needed}"
        for fg, bg, ground, needed in contrast_pairs(palette)
        if (ratio := contrast_ratio(getattr(palette, fg), ground)) < needed
    ]

    assert failures == []


def test_contrast_ratio_matches_the_wcag_formula() -> None:
    assert contrast_ratio("#000000", "#FFFFFF") == pytest.approx(21.0)
    assert contrast_ratio("#FFFFFF", "#FFFFFF") == pytest.approx(1.0)
    assert contrast_ratio("#767676", "#FFFFFF") == pytest.approx(4.54, abs=0.01)


# -- Interaction ---------------------------------------------------------------


def test_a_protocol_breakdown_opens_the_matching_flows(window: MainWindow) -> None:
    window.state.load(sdk_job(), sdk_flows())

    button = window.overview.protocols.entry_button("UDP")
    assert button is not None
    button.click()

    assert window.current_page() is window.flows
    assert window.flows.protocol.currentText() == "UDP"
    assert window.flows.search.text() == ""
    assert window.flows.count.text() == "1 of 2 flows"


def test_a_termination_breakdown_filters_by_reason(window: MainWindow) -> None:
    window.state.load(sdk_job(), sdk_flows())
    reason = window.overview.terminations.entries[0][0]

    button = window.overview.terminations.entry_button(reason)
    assert button is not None
    button.click()

    assert window.current_page() is window.flows
    assert window.flows.search.text() == reason
    assert window.flows.protocol.currentIndex() == 0


def test_decoder_skips_are_not_clickable(window: MainWindow) -> None:
    window.state.load(sdk_job(), sdk_flows())

    assert window.overview.decode.entry_button("not_telemetry_port") is None


def test_a_largest_flow_opens_in_the_flow_browser(window: MainWindow) -> None:
    flows = sdk_flows()
    window.state.load(sdk_job(), flows)
    window.flows.search.setText("no such flow")
    largest = max(flows, key=lambda flow: flow.bytes_total)

    window.overview.top_flow_buttons[0].click()

    assert window.current_page() is window.flows
    assert window.flows.search.text() == ""
    assert window.flows.selected_flow() is largest
    assert window.flows.detail.title.startswith(f"{largest.ip_a}:{largest.port_a}")


def test_the_flows_page_shows_an_empty_state_until_flows_load(
    window: MainWindow,
) -> None:
    page = window.flows
    assert page.empty_state.isVisibleTo(page)
    assert not page.table.isVisibleTo(page)

    window.state.load(sdk_job(), sdk_flows())

    assert not page.empty_state.isVisibleTo(page)
    assert page.table.isVisibleTo(page)


def test_the_empty_state_offers_to_open_a_capture(qt_app: QCoreApplication) -> None:
    assert isinstance(qt_app, QApplication)
    # A page on its own: the window would run its async slot, which needs qasync.
    page = FlowsPage(AnalysisState())
    requested: list[bool] = []
    page.open_requested.connect(lambda: requested.append(True))

    page.empty_open_button.click()

    assert requested == [True]


def test_the_sidebar_badges_the_flow_count(window: MainWindow) -> None:
    badge = window.nav_badges[window.pages.index(window.flows)]
    assert not badge.isVisibleTo(window)
    assert not window.capture_card.isVisibleTo(window)

    window.state.load(sdk_job(), sdk_flows())

    assert badge.text() == "2"
    assert badge.isVisibleTo(window)
    assert window.capture_card.isVisibleTo(window)
    assert window.capture_name.text() == "capture.pcap"
    assert window.capture_name.toolTip() == "capture.pcap"


def test_a_long_capture_name_is_elided_with_the_full_name_in_the_tooltip(
    window: MainWindow,
) -> None:
    name = "a_very_long_capture_name_" * 4 + ".pcap"

    window.state.load(sdk_job(filename=name), sdk_flows())

    shown = window.capture_name.text()
    assert "…" in shown
    assert shown.endswith(".pcap")
    assert window.capture_name.toolTip() == name


def styled_background(widget: QWidget) -> str:
    """
    The background the winning stylesheet rule gives a widget.

    Qt's stylesheet engine copies that rule's ``background`` into the widget's
    palette when it polishes the widget; a transparent result means another
    rule outranked it.
    """
    widget.ensurePolished()
    color = widget.palette().color(QPalette.ColorRole.Window)
    return color.name(QColor.NameFormat.HexArgb).upper()


def test_styled_badges_keep_their_own_background(window: MainWindow) -> None:
    # A descendant rule such as "QFrame#Sidebar QLabel" once outranked these
    # widgets' own rules and left them transparent.
    accent = "#FF" + PALETTES[window.theme].accent.lstrip("#").upper()
    window.state.load(sdk_job(), sdk_flows())
    badge = window.nav_badges[window.pages.index(window.flows)]
    step = window.overview.drop_zone.findChildren(QLabel, "StepNumber")[0]

    assert styled_background(badge) == accent
    assert styled_background(step) == accent


def test_pills_are_sized_to_fit_their_padding(window: MainWindow) -> None:
    window.history.set_jobs([sdk_job()])
    table = window.history.table
    index = window.history.model.index(0, 1)
    plain = table.fontMetrics().horizontalAdvance("succeeded")

    option = QStyleOptionViewItem()
    option.font = table.font()  # pyright: ignore[reportAttributeAccessIssue] - Qt attribute

    hint = table.itemDelegateForColumn(1).sizeHint(option, index)

    assert hint.width() >= plain + 2 * (9 + 10)


def test_the_detail_panel_summarises_the_flow(window: MainWindow) -> None:
    window.state.load(sdk_job(), sdk_flows())

    window.flows.table.selectRow(0)
    flow = window.flows.selected_flow()

    assert flow is not None
    detail = window.flows.detail
    assert detail.summary_metric("Packets") == "3"
    assert detail.summary_metric("Bytes") == "1.6 KB"
    # The bar draws the share in thousandths.
    expected = flow.pkts_fwd / flow.pkts_total
    assert detail.direction_share() == pytest.approx(expected, abs=1e-3)
    assert detail.badges() == ["TCP", "end_of_input"]


def test_the_detail_panel_filters_features(window: MainWindow) -> None:
    window.state.load(sdk_job(), sdk_flows())
    window.flows.table.selectRow(0)
    detail = window.flows.detail

    detail.feature_filter.setText("PKTS_F")

    shown = detail.visible_features()
    assert "pkts_fwd" in shown
    assert all("pkts_f" in name for name in shown)
    detail.feature_filter.setText("")
    assert len(detail.visible_features()) == len(FLOW_CSV_COLUMNS)


def test_history_counts_in_good_english(window: MainWindow) -> None:
    window.history.set_jobs([sdk_job()])
    assert window.history.message.text().startswith("1 analysis.")

    window.history.set_jobs([sdk_job(), sdk_job()])
    assert window.history.message.text().startswith("2 analyses.")


def test_history_opens_only_with_a_selection(window: MainWindow) -> None:
    window.history.set_jobs([sdk_job()])
    assert not window.history.open_button.isEnabled()

    window.history.table.selectRow(0)

    assert window.history.open_button.isEnabled()


def test_the_header_theme_button_toggles_the_theme(window: MainWindow) -> None:
    start = window.theme

    window.theme_button.click()

    assert window.theme != start
    assert window.theme_button.toolTip().startswith("Switch to the")


def test_the_backend_chip_is_a_button_that_rechecks(window: MainWindow) -> None:
    assert window.backend_chip.toolTip() == "Check the connection again"
    assert window.backend_chip.isEnabled()


def test_a_pill_cell_is_painted_in_its_tone(window: MainWindow) -> None:
    palette = PALETTES[window.theme]
    window.history.set_jobs([sdk_job()])
    table = window.history.table
    delegate = table.itemDelegateForColumn(1)
    option = QStyleOptionViewItem()
    option.rect = QRect(0, 0, 160, 32)  # pyright: ignore[reportAttributeAccessIssue] - Qt attribute
    option.font = table.font()  # pyright: ignore[reportAttributeAccessIssue] - Qt attribute
    option.widget = table  # pyright: ignore[reportAttributeAccessIssue] - Qt attribute
    image = QImage(160, 32, QImage.Format.Format_ARGB32)
    image.fill(QColor(palette.surface))

    painter = QPainter(image)
    delegate.paint(painter, option, window.history.model.index(0, 1))
    painter.end()

    # Just inside the pill's left end, at mid-height: the success background.
    assert image.pixelColor(10 + 4, 16).name().upper() == palette.success_soft.upper()
    # Past the pill's right end: the row background is left alone.
    assert image.pixelColor(155, 16).name().upper() == palette.surface.upper()


def test_a_plain_cell_falls_back_to_the_default_painting(window: MainWindow) -> None:
    window.history.set_jobs([sdk_job()])
    table = window.history.table
    delegate = PillDelegate(table)
    option = QStyleOptionViewItem()
    option.rect = QRect(0, 0, 160, 32)  # pyright: ignore[reportAttributeAccessIssue] - Qt attribute
    option.widget = table  # pyright: ignore[reportAttributeAccessIssue] - Qt attribute
    index = window.history.model.index(0, 0)  # the capture name: no tone
    image = QImage(160, 32, QImage.Format.Format_ARGB32)

    painter = QPainter(image)
    delegate.paint(painter, option, index)
    painter.end()

    default = QStyledItemDelegate().sizeHint(option, index)
    assert delegate.sizeHint(option, index) == default
