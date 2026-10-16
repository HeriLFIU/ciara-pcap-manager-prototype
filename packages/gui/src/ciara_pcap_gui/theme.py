"""
Design tokens and the application stylesheet.

Every colour the interface uses is a named token on `Palette`; the stylesheet
is generated from those tokens, so restyling the whole application means
editing one dataclass, and a dark theme is just a second instance of it.

Both palettes are held to WCAG 2.2 contrast: body text at 7:1, every other
text at 4.5:1 and input borders at 3:1. ``tests/unit/test_gui_window.py``
checks each pair the stylesheet uses with `contrast_ratio`, so a token change
that hurts legibility fails the build.

Widgets opt into a style with ``setObjectName`` (``Card``, ``Sidebar``,
``PrimaryButton``...) or with a dynamic property (``role``, ``tone``,
``state``) for variants, never with inline ``setStyleSheet`` calls. That keeps
the look in this file and the layout in the widget code.
"""

import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QStyleFactory, QWidget

from ciara_pcap_gui.tones import Tone


class ThemeMode(StrEnum):
    """Which palette to apply."""

    LIGHT = "light"
    DARK = "dark"


@dataclass(frozen=True)
class Palette:
    """The colour tokens of one theme."""

    window: str
    surface: str
    surface_alt: str
    hover: str
    border: str
    border_strong: str
    text: str
    text_muted: str
    accent: str
    accent_hover: str
    accent_text: str
    accent_soft: str
    selection: str
    secondary: str
    secondary_soft: str
    success: str
    success_soft: str
    warning: str
    warning_soft: str
    danger: str
    danger_soft: str
    neutral_soft: str
    sidebar: str
    sidebar_edge: str
    sidebar_text: str
    sidebar_muted: str
    sidebar_strong: str
    sidebar_active: str


LIGHT = Palette(
    window="#EEF1F8",
    surface="#FFFFFF",
    surface_alt="#F6F8FC",
    hover="#F0F1FF",
    border="#DCE1EC",
    border_strong="#7C879C",
    text="#0B1222",
    text_muted="#4A5468",
    accent="#4F46E5",
    accent_hover="#4338CA",
    accent_text="#FFFFFF",
    accent_soft="#E8E9FF",
    selection="#E0E2FF",
    secondary="#0F766E",
    secondary_soft="#E0F7F2",
    success="#15803D",
    success_soft="#E3FBEA",
    warning="#B45309",
    warning_soft="#FEF6DC",
    danger="#B91C1C",
    danger_soft="#FEE9E9",
    neutral_soft="#EDF0F5",
    sidebar="#0F1433",
    sidebar_edge="#1B2150",
    sidebar_text="#C3C8E4",
    sidebar_muted="#8E96C2",
    sidebar_strong="#FFFFFF",
    sidebar_active="#262D63",
)

DARK = Palette(
    window="#0A0E1A",
    surface="#141A2C",
    surface_alt="#10162A",
    hover="#1A2142",
    border="#273150",
    border_strong="#6B7799",
    text="#EEF1FA",
    text_muted="#A7B0C8",
    accent="#8B93FF",
    accent_hover="#A9AFFF",
    accent_text="#0A0E1A",
    accent_soft="#252B5C",
    selection="#2B3270",
    secondary="#2DD4BF",
    secondary_soft="#0D3836",
    success="#4ADE80",
    success_soft="#123222",
    warning="#FBBF24",
    warning_soft="#3A2B0B",
    danger="#FB7185",
    danger_soft="#3F1520",
    neutral_soft="#1F2740",
    sidebar="#070A15",
    sidebar_edge="#141A3A",
    sidebar_text="#B4BBD9",
    sidebar_muted="#7F87B0",
    sidebar_strong="#FFFFFF",
    sidebar_active="#1D2353",
)

PALETTES: dict[ThemeMode, Palette] = {ThemeMode.LIGHT: LIGHT, ThemeMode.DARK: DARK}

_active: list[Palette] = [LIGHT]

#: Brand mark gradient; fixed across themes, white text is large and bold.
_BRAND_FROM = "#6366F1"
_BRAND_TO = "#0D9488"

_MONO = '"JetBrains Mono", "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace'
_SANS = '"Inter", "Segoe UI", "SF Pro Text", "Noto Sans", "DejaVu Sans", sans-serif'

_SRGB_KNEE = 0.04045

_CHEVRON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" '
    'viewBox="0 0 12 12"><path d="M2.5 4.5 6 8l3.5-3.5" fill="none" '
    'stroke="{color}" stroke-width="1.6" stroke-linecap="round" '
    'stroke-linejoin="round"/></svg>'
)


def _linear(channel: int) -> float:
    """
    Convert one 8-bit sRGB channel to linear light.

    Args:
        channel: 0 to 255.

    Returns:
        The linear value, 0 to 1.

    """
    value = channel / 255
    if value <= _SRGB_KNEE:
        return value / 12.92
    return ((value + 0.055) / 1.055) ** 2.4


def relative_luminance(color: str) -> float:
    """
    Compute the WCAG relative luminance of a colour.

    Args:
        color: ``#RRGGBB``.

    Returns:
        The luminance, 0 (black) to 1 (white).

    """
    qcolor = QColor(color)
    return (
        0.2126 * _linear(qcolor.red())
        + 0.7152 * _linear(qcolor.green())
        + 0.0722 * _linear(qcolor.blue())
    )


def contrast_ratio(foreground: str, background: str) -> float:
    """
    Compute the WCAG 2.2 contrast ratio of two colours.

    Args:
        foreground: ``#RRGGBB``.
        background: ``#RRGGBB``.

    Returns:
        The ratio, 1 (identical) to 21 (black on white).

    """
    lighter, darker = sorted(
        (relative_luminance(foreground), relative_luminance(background)),
        reverse=True,
    )
    return (lighter + 0.05) / (darker + 0.05)


def active_palette() -> Palette:
    """
    Return the palette applied last, for widgets that paint by hand.

    Returns:
        The palette.

    """
    return _active[0]


def tone_colors(p: Palette, tone: Tone | str) -> tuple[str, str]:
    """
    Resolve a tone to its text and background colours.

    Args:
        p: The colour tokens.
        tone: The tone, or its value.

    Returns:
        ``(foreground, background)``.

    """
    match Tone(tone):
        case Tone.ACCENT:
            return p.accent, p.accent_soft
        case Tone.SECONDARY:
            return p.secondary, p.secondary_soft
        case Tone.SUCCESS:
            return p.success, p.success_soft
        case Tone.WARNING:
            return p.warning, p.warning_soft
        case Tone.DANGER:
            return p.danger, p.danger_soft
        case Tone.NEUTRAL:
            return p.text_muted, p.neutral_soft


def _tone_rules(p: Palette) -> str:
    """
    Render the per-tone rules for pills, bars and stat card stripes.

    Args:
        p: The colour tokens.

    Returns:
        Stylesheet text.

    """
    rules: list[str] = []
    for tone in Tone:
        fg, bg = tone_colors(p, tone)
        rules.append(
            f'QLabel#Pill[tone="{tone}"] {{ color: {fg}; background: {bg}; }}\n'
            f'QProgressBar#BarMeter[tone="{tone}"]::chunk {{ background: {fg}; }}\n'
            f'QFrame#StatStripe[tone="{tone}"] {{ background: {fg}; }}'
        )
    return "\n".join(rules)


def _chevron(color: str) -> str:
    """
    Write a down-pointing chevron in one colour and return its path.

    Qt stylesheets take images only by URL, and styling the combo box's
    drop-down replaces the native arrow, so the arrow is drawn here as a tiny
    SVG in the user's temporary directory, once per colour.

    Args:
        color: ``#RRGGBB``.

    Returns:
        The file path, with forward slashes as Qt URLs need.

    """
    folder = Path(tempfile.gettempdir()) / "ciara-pcap-gui"
    path = folder / f"chevron-{color.lstrip('#').lower()}.svg"
    if not path.is_file():
        folder.mkdir(parents=True, exist_ok=True)
        path.write_text(_CHEVRON_SVG.format(color=color), encoding="utf-8")
    return path.as_posix()


def build_stylesheet(p: Palette) -> str:
    """
    Render the Qt stylesheet for a palette.

    Args:
        p: The colour tokens.

    Returns:
        The stylesheet text.

    """
    return f"""
    QMainWindow, QWidget#Page, QStackedWidget {{ background: {p.window}; }}
    QWidget {{ color: {p.text}; font-family: {_SANS}; font-size: 10pt; }}
    QToolTip {{ background: {p.text}; color: {p.surface}; border: none;
        padding: 6px 8px; border-radius: 6px; }}

    /* Sidebar. No descendant rules such as "QFrame#Sidebar QLabel": they
       outrank the "QLabel#BrandMark" rules below and erase their backgrounds. */
    QFrame#Sidebar {{ background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 {p.sidebar_edge}, stop:0.35 {p.sidebar}, stop:1 {p.sidebar});
        border: none; }}
    QLabel#BrandMark {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 {_BRAND_FROM}, stop:1 {_BRAND_TO}); color: #FFFFFF;
        border-radius: 10px; font-size: 15pt; font-weight: 800; }}
    QLabel#Brand {{ color: {p.sidebar_strong}; font-size: 14pt; font-weight: 800;
        letter-spacing: 1px; }}
    QLabel#BrandCaption {{ color: {p.sidebar_muted}; font-size: 8pt; }}
    QLabel#SidebarSection {{ color: {p.sidebar_muted}; font-size: 8pt;
        font-weight: 700; letter-spacing: 1px; }}
    QPushButton#NavButton {{ background: transparent; color: {p.sidebar_text};
        border: none; border-radius: 8px; text-align: left;
        padding: 9px 12px; font-weight: 600; }}
    QPushButton#NavButton:hover {{ background: {p.sidebar_active};
        color: {p.sidebar_strong}; }}
    QPushButton#NavButton:checked {{ background: {p.sidebar_active};
        color: {p.sidebar_strong}; }}
    QPushButton#NavButton:focus {{ outline: none; }}
    QFrame#NavIndicator {{ background: transparent; border-radius: 2px; }}
    QFrame#NavIndicator[active="true"] {{ background: {p.accent}; }}
    QLabel#NavBadge {{ background: {p.accent}; color: {p.accent_text};
        border-radius: 7px; padding: 1px 7px; font-size: 8pt; font-weight: 700; }}
    QFrame#CaptureCard {{ background: {p.sidebar_active}; border-radius: 10px; }}
    QLabel#CaptureName {{ color: {p.sidebar_strong}; font-weight: 700; }}
    QLabel#CaptureMeta {{ color: {p.sidebar_text}; font-size: 8pt; }}
    QLabel#SidebarFooter {{ color: {p.sidebar_muted}; font-size: 8pt; }}

    /* Header */
    QFrame#HeaderBar {{ background: {p.surface};
        border-bottom: 1px solid {p.border}; }}
    QLabel#PageTitle {{ font-size: 16pt; font-weight: 800; }}
    QLabel#PageSubtitle {{ color: {p.text_muted}; }}

    /* Cards */
    QFrame#Card {{ background: {p.surface}; border: 1px solid {p.border};
        border-radius: 12px; }}
    QFrame#StatStripe {{ border-radius: 2px; }}
    QLabel#CardTitle {{ color: {p.text_muted}; font-size: 8pt; font-weight: 700;
        letter-spacing: 0.8px; }}
    QLabel#CardValue {{ font-size: 21pt; font-weight: 800; }}
    QLabel#CardCaption {{ color: {p.text_muted}; font-size: 8pt; }}
    QLabel#SectionTitle {{ font-size: 11pt; font-weight: 700; }}
    QLabel#SectionHint {{ color: {p.text_muted}; font-size: 8pt; }}
    QLabel#Headline {{ font-size: 13pt; font-weight: 800; }}
    QLabel[role="muted"] {{ color: {p.text_muted}; }}
    QLabel[role="mono"] {{ font-family: {_MONO}; }}
    QLabel#MetricLabel {{ color: {p.text_muted}; font-size: 8pt; font-weight: 700;
        letter-spacing: 0.6px; }}
    QLabel#MetricValue {{ font-size: 12pt; font-weight: 800; }}
    QFrame#MetricTile {{ background: {p.surface_alt}; border: 1px solid {p.border};
        border-radius: 8px; }}

    /* Pills and status chips. Qt ignores a border-radius larger than half the
       widget's height, so each radius stays under half of its text height plus
       vertical padding. */
    QLabel#Pill {{ border-radius: 8px; padding: 3px 10px; font-size: 8pt;
        font-weight: 700; }}
    QPushButton#Chip {{ border-radius: 10px; padding: 4px 12px; font-size: 8pt;
        font-weight: 700; background: {p.neutral_soft}; color: {p.text_muted};
        border: 1px solid transparent; }}
    QPushButton#Chip:hover {{ border-color: {p.border_strong}; }}
    QPushButton#Chip[state="ok"] {{ color: {p.success};
        background: {p.success_soft}; }}
    QPushButton#Chip[state="busy"] {{ color: {p.warning};
        background: {p.warning_soft}; }}
    QPushButton#Chip[state="error"] {{ color: {p.danger};
        background: {p.danger_soft}; }}

    /* Buttons */
    QPushButton {{ background: {p.surface}; border: 1px solid {p.border_strong};
        border-radius: 8px; padding: 7px 14px; font-weight: 600; }}
    QPushButton:hover {{ border-color: {p.accent}; color: {p.accent};
        background: {p.accent_soft}; }}
    QPushButton:pressed {{ background: {p.selection}; }}
    QPushButton:focus {{ border-color: {p.accent}; }}
    QPushButton:disabled {{ color: {p.text_muted}; background: {p.surface_alt};
        border-color: {p.border}; }}
    QPushButton#PrimaryButton {{ background: {p.accent}; color: {p.accent_text};
        border: 1px solid {p.accent}; }}
    QPushButton#PrimaryButton:hover {{ background: {p.accent_hover};
        border-color: {p.accent_hover}; color: {p.accent_text}; }}
    QPushButton#PrimaryButton:disabled {{ background: {p.neutral_soft};
        border-color: {p.border}; color: {p.text_muted}; }}
    QPushButton#GhostButton {{ background: transparent; border: 1px solid {p.border};
        color: {p.text_muted}; padding: 7px 12px; }}
    QPushButton#GhostButton:hover {{ color: {p.accent}; border-color: {p.accent};
        background: {p.accent_soft}; }}
    QPushButton#BreakdownRow, QPushButton#FlowRow {{ background: transparent;
        border: 1px solid transparent; border-radius: 8px; padding: 0;
        text-align: left; }}
    QPushButton#BreakdownRow:hover, QPushButton#FlowRow:hover {{
        background: {p.hover}; border-color: {p.border}; color: {p.text}; }}
    QPushButton#BreakdownRow:focus, QPushButton#FlowRow:focus {{
        border-color: {p.accent}; }}
    QLabel#RowHint {{ color: {p.accent}; font-weight: 700; }}

    /* Inputs */
    QLineEdit, QComboBox {{ background: {p.surface};
        border: 1px solid {p.border_strong};
        border-radius: 8px; padding: 6px 10px; selection-background-color: {p.accent};
        selection-color: {p.accent_text}; }}
    QLineEdit:hover, QComboBox:hover {{ border-color: {p.accent}; }}
    QLineEdit:focus, QComboBox:focus {{ border: 1px solid {p.accent};
        background: {p.surface}; }}
    QLineEdit:disabled {{ color: {p.text_muted}; background: {p.surface_alt}; }}
    QLineEdit#HeaderUrl {{ font-family: {_MONO}; font-size: 9pt;
        background: {p.surface_alt}; }}
    QComboBox::drop-down {{ subcontrol-origin: padding;
        subcontrol-position: center right; width: 24px; border: none; }}
    QComboBox::down-arrow {{ image: url("{_chevron(p.text_muted)}");
        width: 12px; height: 12px; }}
    QComboBox::down-arrow:on {{ image: url("{_chevron(p.accent)}"); }}
    QComboBox QAbstractItemView {{ background: {p.surface};
        border: 1px solid {p.border};
        border-radius: 8px; padding: 4px; outline: none;
        selection-background-color: {p.selection}; selection-color: {p.text}; }}

    /* Tables and trees */
    QTableView, QTreeWidget {{ background: {p.surface}; alternate-background-color:
        {p.surface_alt}; border: 1px solid {p.border}; border-radius: 12px;
        gridline-color: {p.border}; selection-background-color: {p.selection};
        selection-color: {p.text}; outline: none; }}
    QTableView::item {{ padding: 0 10px; border: none; }}
    QTableView::item:hover, QTreeWidget::item:hover {{ background: {p.hover}; }}
    QTableView::item:selected, QTreeWidget::item:selected {{
        background: {p.selection}; color: {p.text}; }}
    QTreeWidget::item {{ padding: 4px 0; }}
    QHeaderView {{ background: transparent; border: none; }}
    QHeaderView::section {{ background: {p.surface_alt}; color: {p.text_muted};
        border: none; border-bottom: 1px solid {p.border}; padding: 8px 10px;
        font-weight: 700; font-size: 8pt; }}
    QHeaderView::section:hover {{ color: {p.text}; }}
    QTableCornerButton::section {{ background: {p.surface_alt}; border: none; }}
    QAbstractScrollArea::corner {{ background: transparent; border: none; }}

    /* Scroll bars */
    QScrollBar:vertical {{ background: transparent; width: 12px; margin: 4px 2px; }}
    QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 2px 4px; }}
    QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 4px;
        min-height: 36px; margin: 0 2px; }}
    QScrollBar::handle:horizontal {{ background: {p.border}; border-radius: 4px;
        min-width: 36px; margin: 2px 0; }}
    QScrollBar::handle:hover {{ background: {p.border_strong}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; border: none; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

    /* Bars */
    QProgressBar#BarMeter, QProgressBar#DirectionBar {{ background: {p.neutral_soft};
        border: none; border-radius: 4px; max-height: 8px; min-height: 8px; }}
    QProgressBar#BarMeter::chunk {{ background: {p.accent}; border-radius: 4px; }}
    QProgressBar#DirectionBar {{ background: {p.secondary}; }}
    QProgressBar#DirectionBar::chunk {{ background: {p.accent};
        border-top-left-radius: 4px; border-bottom-left-radius: 4px; }}
    QProgressBar {{ background: {p.neutral_soft}; border: none; border-radius: 4px;
        max-height: 8px; text-align: center; }}
    QProgressBar::chunk {{ background: {p.accent}; border-radius: 4px; }}
    QLabel#LegendA {{ color: {p.accent}; font-weight: 700; font-size: 8pt; }}
    QLabel#LegendB {{ color: {p.secondary}; font-weight: 700; font-size: 8pt; }}
    {_tone_rules(p)}

    /* Drop zone and empty states */
    QFrame#DropZone {{ background: {p.surface}; border: 2px dashed {p.border_strong};
        border-radius: 16px; }}
    QFrame#DropZone[active="true"] {{ border-color: {p.accent};
        background: {p.accent_soft}; }}
    QLabel#DropIcon {{ background: {p.accent_soft}; color: {p.accent};
        border: 2px solid {p.accent}; border-radius: 14px; font-size: 13pt;
        font-weight: 800; letter-spacing: 1px; }}
    QLabel#DropTitle {{ font-size: 17pt; font-weight: 800; }}
    QLabel#StepNumber {{ background: {p.accent}; color: {p.accent_text};
        border-radius: 11px; font-size: 8pt; font-weight: 800; }}
    QLabel#StepText {{ color: {p.text_muted}; }}
    QLabel#ShortcutHint {{ color: {p.text_muted}; font-size: 8pt; }}
    QFrame#EmptyState {{ background: {p.surface}; border: 1px solid {p.border};
        border-radius: 16px; }}

    QMenuBar {{ background: {p.surface}; border-bottom: 1px solid {p.border};
        padding: 2px 6px; }}
    QMenuBar::item {{ padding: 4px 10px; background: transparent; border-radius: 6px; }}
    QMenuBar::item:selected {{ background: {p.accent_soft}; color: {p.accent}; }}
    QMenu {{ background: {p.surface}; border: 1px solid {p.border}; padding: 6px;
        border-radius: 8px; }}
    QMenu::item {{ padding: 6px 24px 6px 14px; border-radius: 6px; }}
    QMenu::item:selected {{ background: {p.accent_soft}; color: {p.accent}; }}
    QMenu::item:disabled {{ color: {p.text_muted}; }}
    QMenu::separator {{ height: 1px; background: {p.border}; margin: 5px 8px; }}

    QStatusBar {{ background: {p.surface}; border-top: 1px solid {p.border};
        color: {p.text_muted}; padding-left: 8px; }}
    QStatusBar::item {{ border: none; }}
    QSplitter::handle {{ background: transparent; }}
    QSplitter::handle:horizontal {{ width: 10px; }}
    QScrollArea {{ border: none; background: transparent; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QMessageBox {{ background: {p.surface}; }}
    """


def _qt_palette(p: Palette) -> QPalette:
    """
    Build a QPalette so native-drawn parts of widgets match the stylesheet.

    Args:
        p: The colour tokens.

    Returns:
        The palette.

    """
    palette = QPalette()
    role = QPalette.ColorRole
    for color_role, value in (
        (role.Window, p.window),
        (role.WindowText, p.text),
        (role.Base, p.surface),
        (role.AlternateBase, p.surface_alt),
        (role.Text, p.text),
        (role.Button, p.surface),
        (role.ButtonText, p.text),
        (role.Highlight, p.accent),
        (role.HighlightedText, p.accent_text),
        (role.ToolTipBase, p.surface),
        (role.ToolTipText, p.text),
        (role.PlaceholderText, p.text_muted),
        (role.Link, p.accent),
        (role.Mid, p.border),
        (role.Dark, p.border_strong),
    ):
        palette.setColor(color_role, QColor(value))
    return palette


def resolve_theme(saved: object, app: QApplication) -> ThemeMode:
    """
    Choose the theme to start with.

    Args:
        saved: The value stored in the user's settings, if any.
        app: The running application, for the operating system's preference.

    Returns:
        The saved theme when valid, else the system colour scheme.

    """
    if saved in {mode.value for mode in ThemeMode}:
        return ThemeMode(str(saved))
    if app.styleHints().colorScheme() == Qt.ColorScheme.Dark:
        return ThemeMode.DARK
    return ThemeMode.LIGHT


def apply_theme(app: QApplication, mode: ThemeMode) -> Palette:
    """
    Apply a theme to the whole application.

    Args:
        app: The running application.
        mode: Which palette to use.

    Returns:
        The palette that was applied, for widgets that paint by hand.

    """
    palette = PALETTES[mode]
    _active[0] = palette
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setPalette(_qt_palette(palette))
    app.setStyleSheet(build_stylesheet(palette))
    return palette


def repolish(widget: QWidget) -> None:
    """
    Re-apply the stylesheet after a dynamic property changed.

    Qt only re-evaluates property selectors such as ``[state="ok"]`` when the
    widget is unpolished and polished again.

    Args:
        widget: The widget whose property changed.

    """
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
