"""Pills: short categorical values drawn as rounded, tone-coloured badges."""

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFontMetrics, QPainter
from PySide6.QtWidgets import (
    QLabel,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QWidget,
)

from ciara_pcap_gui.models import TONE_ROLE
from ciara_pcap_gui.theme import active_palette, repolish, tone_colors
from ciara_pcap_gui.tones import Tone

_PAD_X = 9
_PAD_Y = 3
_INSET = 10
_FONT_SCALE = 0.88


class Pill(QLabel):
    """A label drawn as a pill in the colours of a tone."""

    def __init__(
        self, text: str = "", tone: Tone = Tone.NEUTRAL, parent: QWidget | None = None
    ) -> None:
        """
        Create a pill.

        Args:
            text: The label.
            tone: The colour family.
            parent: Optional Qt parent.

        """
        super().__init__(text, parent)
        self.setObjectName("Pill")
        self.set_tone(tone)

    @property
    def tone(self) -> Tone:
        """
        The colour family currently shown.

        Returns:
            The tone.

        """
        return Tone(str(self.property("tone")))

    def set_tone(self, tone: Tone) -> None:
        """
        Change the colour family.

        Args:
            tone: The new tone.

        """
        self.setProperty("tone", str(tone))
        repolish(self)


class PillDelegate(QStyledItemDelegate):
    """Paints a cell as a pill in the tone the model publishes under `TONE_ROLE`."""

    def sizeHint(  # noqa: N802 - Qt API
        self,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> QSize:
        """
        Make room for the pill, so resize-to-contents does not clip it.

        Args:
            option: Geometry and state of the cell.
            index: The cell.

        Returns:
            The size of the plain text plus the pill's padding and inset.

        """
        size = super().sizeHint(option, index)
        if index.data(TONE_ROLE) is None:
            return size
        font = option.font  # pyright: ignore[reportAttributeAccessIssue] - Qt attribute
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() * _FONT_SCALE)
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        width = QFontMetrics(font).horizontalAdvance(text) + 2 * (_PAD_X + _INSET)
        return QSize(max(size.width(), width), size.height())

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> None:
        """
        Draw the row background, then the cell text inside a pill.

        Args:
            painter: The view's painter.
            option: Geometry and state of the cell.
            index: The cell.

        """
        tone = index.data(TONE_ROLE)
        if tone is None:
            super().paint(painter, option, index)
            return

        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        text = opt.text  # pyright: ignore[reportAttributeAccessIssue] - set by initStyleOption
        opt.text = ""  # pyright: ignore[reportAttributeAccessIssue] - same attribute
        # The view's own style, so the stylesheet's hover and selection
        # backgrounds are drawn exactly as in the other columns.
        view = opt.widget  # pyright: ignore[reportAttributeAccessIssue] - same
        view.style().drawControl(
            QStyle.ControlElement.CE_ItemViewItem, opt, painter, view
        )

        foreground, background = tone_colors(active_palette(), str(tone))
        font = opt.font  # pyright: ignore[reportAttributeAccessIssue] - same
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() * _FONT_SCALE)
        painter.save()
        painter.setFont(font)
        metrics = painter.fontMetrics()
        width = metrics.horizontalAdvance(text) + 2 * _PAD_X
        height = metrics.height() + 2 * _PAD_Y
        cell = opt.rect  # pyright: ignore[reportAttributeAccessIssue] - same
        pill = QRectF(
            cell.x() + _INSET,
            cell.y() + (cell.height() - height) / 2,
            min(width, cell.width() - 2 * _INSET),
            height,
        )
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(background))
        painter.drawRoundedRect(pill, height / 2, height / 2)
        painter.setPen(QColor(foreground))
        painter.drawText(pill, int(Qt.AlignmentFlag.AlignCenter), text)
        painter.restore()
