"""
Design tokens and the application stylesheet.

Every colour the interface uses is a named token on `Palette`; the stylesheet
is generated from those tokens, so restyling the whole application means
editing one dataclass, and a dark theme is just a second instance of it.

Widgets opt into a style with ``setObjectName`` (``Card``, ``Sidebar``,
``PrimaryButton``...) or with a dynamic ``role`` property for small text
variants, never with inline ``setStyleSheet`` calls. That keeps the look in
this file and the layout in the widget code.
"""

from dataclasses import dataclass
from enum import StrEnum

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QStyleFactory, QWidget


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
    border: str
    text: str
    text_muted: str
    accent: str
    accent_hover: str
    accent_text: str
    selection: str
    success: str
    warning: str
    danger: str
    sidebar: str
    sidebar_text: str
    sidebar_active: str


LIGHT = Palette(
    window="#F4F6FA",
    surface="#FFFFFF",
    surface_alt="#F8FAFC",
    border="#E2E8F0",
    text="#0F172A",
    text_muted="#64748B",
    accent="#2563EB",
    accent_hover="#1D4ED8",
    accent_text="#FFFFFF",
    selection="#DBEAFE",
    success="#16A34A",
    warning="#D97706",
    danger="#DC2626",
    sidebar="#0F172A",
    sidebar_text="#CBD5E1",
    sidebar_active="#1E293B",
)

DARK = Palette(
    window="#0B1120",
    surface="#111827",
    surface_alt="#0F172A",
    border="#1F2A3D",
    text="#E5E7EB",
    text_muted="#94A3B8",
    accent="#3B82F6",
    accent_hover="#60A5FA",
    accent_text="#FFFFFF",
    selection="#1E3A8A",
    success="#22C55E",
    warning="#F59E0B",
    danger="#F87171",
    sidebar="#060A14",
    sidebar_text="#94A3B8",
    sidebar_active="#111827",
)

PALETTES: dict[ThemeMode, Palette] = {ThemeMode.LIGHT: LIGHT, ThemeMode.DARK: DARK}


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
    QWidget {{ color: {p.text}; font-size: 10pt; }}
    QToolTip {{ background: {p.surface}; color: {p.text};
        border: 1px solid {p.border}; padding: 4px; }}

    /* Sidebar */
    QFrame#Sidebar {{ background: {p.sidebar}; border: none; }}
    QLabel#Brand {{ color: #FFFFFF; font-size: 13pt; font-weight: 700; }}
    QLabel#BrandCaption {{ color: {p.sidebar_text}; font-size: 8pt; }}
    QPushButton#NavButton {{ background: transparent; color: {p.sidebar_text};
        border: none; border-left: 3px solid transparent; text-align: left;
        padding: 9px 14px; font-weight: 600; }}
    QPushButton#NavButton:hover {{ background: {p.sidebar_active}; color: #FFFFFF; }}
    QPushButton#NavButton:checked {{ background: {p.sidebar_active}; color: #FFFFFF;
        border-left: 3px solid {p.accent}; }}
    QLabel#SidebarFooter {{ color: {p.sidebar_text}; font-size: 8pt; }}

    /* Header */
    QFrame#HeaderBar {{ background: {p.surface};
        border-bottom: 1px solid {p.border}; }}
    QLabel#PageTitle {{ font-size: 15pt; font-weight: 700; }}
    QLabel#PageSubtitle {{ color: {p.text_muted}; }}

    /* Cards */
    QFrame#Card {{ background: {p.surface}; border: 1px solid {p.border};
        border-radius: 10px; }}
    QLabel#CardTitle {{ color: {p.text_muted}; font-size: 8pt; font-weight: 700;
        letter-spacing: 0.5px; }}
    QLabel#CardValue {{ font-size: 18pt; font-weight: 700; }}
    QLabel#CardCaption {{ color: {p.text_muted}; font-size: 8pt; }}
    QLabel#SectionTitle {{ font-size: 11pt; font-weight: 700; }}
    QLabel[role="muted"] {{ color: {p.text_muted}; }}
    QLabel[role="mono"] {{ font-family: "JetBrains Mono", "Cascadia Mono", "Consolas",
        "DejaVu Sans Mono", monospace; }}

    /* Status chips */
    QLabel#Chip {{ border-radius: 9px; padding: 2px 10px; font-size: 8pt;
        font-weight: 700; background: {p.surface_alt}; color: {p.text_muted};
        border: 1px solid {p.border}; }}
    QLabel#Chip[state="ok"] {{ color: {p.success}; border-color: {p.success}; }}
    QLabel#Chip[state="busy"] {{ color: {p.warning}; border-color: {p.warning}; }}
    QLabel#Chip[state="error"] {{ color: {p.danger}; border-color: {p.danger}; }}

    /* Buttons and inputs */
    QPushButton {{ background: {p.surface}; border: 1px solid {p.border};
        border-radius: 6px; padding: 6px 14px; font-weight: 600; }}
    QPushButton:hover {{ border-color: {p.accent}; }}
    QPushButton:disabled {{ color: {p.text_muted}; background: {p.surface_alt}; }}
    QPushButton#PrimaryButton {{ background: {p.accent}; color: {p.accent_text};
        border: 1px solid {p.accent}; }}
    QPushButton#PrimaryButton:hover {{ background: {p.accent_hover}; }}
    QPushButton#PrimaryButton:disabled {{ background: {p.border};
        border-color: {p.border}; color: {p.text_muted}; }}
    QLineEdit, QComboBox {{ background: {p.surface}; border: 1px solid {p.border};
        border-radius: 6px; padding: 5px 8px; selection-background-color: {p.accent}; }}
    QLineEdit:focus, QComboBox:focus {{ border-color: {p.accent}; }}
    QComboBox QAbstractItemView {{ background: {p.surface};
        selection-background-color: {p.selection}; selection-color: {p.text}; }}

    /* Tables and trees */
    QTableView, QTreeWidget {{ background: {p.surface}; alternate-background-color:
        {p.surface_alt}; border: 1px solid {p.border}; border-radius: 8px;
        gridline-color: {p.border}; selection-background-color: {p.selection};
        selection-color: {p.text}; }}
    QHeaderView::section {{ background: {p.surface_alt}; color: {p.text_muted};
        border: none; border-bottom: 1px solid {p.border}; padding: 6px 8px;
        font-weight: 700; font-size: 8pt; }}
    QTableView::item {{ padding: 0 10px; }}
    QTreeWidget::item {{ padding: 3px 0; }}

    /* Breakdown bars */
    QProgressBar#BarMeter {{ background: {p.surface_alt}; border: none;
        border-radius: 4px; max-height: 8px; }}
    QProgressBar#BarMeter::chunk {{ background: {p.accent}; border-radius: 4px; }}

    /* Drop zone */
    QFrame#DropZone {{ background: {p.surface}; border: 2px dashed {p.border};
        border-radius: 14px; }}
    QFrame#DropZone[active="true"] {{ border-color: {p.accent};
        background: {p.selection}; }}
    QLabel#DropTitle {{ font-size: 14pt; font-weight: 700; }}

    QMenuBar {{ background: {p.surface}; border-bottom: 1px solid {p.border}; }}
    QMenuBar::item {{ padding: 4px 10px; background: transparent; }}
    QMenuBar::item:selected {{ background: {p.selection}; }}
    QMenu {{ background: {p.surface}; border: 1px solid {p.border}; padding: 4px; }}
    QMenu::item {{ padding: 5px 22px; border-radius: 4px; }}
    QMenu::item:selected {{ background: {p.selection}; color: {p.text}; }}
    QMenu::separator {{ height: 1px; background: {p.border}; margin: 4px 8px; }}

    QStatusBar {{ background: {p.surface}; border-top: 1px solid {p.border};
        color: {p.text_muted}; }}
    QSplitter::handle {{ background: {p.window}; }}
    QScrollArea {{ border: none; background: transparent; }}
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
