"""Card containers and the KPI stat card."""

from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from ciara_pcap_gui.tones import Tone

_STRIPE_WIDTH = 28
_STRIPE_HEIGHT = 4


class Card(QFrame):
    """A rounded surface that groups related content under an optional title."""

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        """
        Create an empty card.

        Args:
            title: Section title shown at the top; omitted when empty.
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(18, 16, 18, 16)
        self.body.setSpacing(10)
        if title:
            heading = QLabel(title)
            heading.setObjectName("SectionTitle")
            self.body.addWidget(heading)


class StatCard(QFrame):
    """A single headline number with a title and a caption."""

    def __init__(
        self, title: str, tone: Tone = Tone.ACCENT, parent: QWidget | None = None
    ) -> None:
        """
        Create a card showing a placeholder value.

        Args:
            title: What the number measures, shown above it.
            tone: Colour of the short stripe above the title.
            parent: Optional Qt parent.

        """
        super().__init__(parent)
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(3)

        stripe = QFrame()
        stripe.setObjectName("StatStripe")
        stripe.setProperty("tone", str(tone))
        stripe.setFixedSize(_STRIPE_WIDTH, _STRIPE_HEIGHT)
        layout.addWidget(stripe)
        layout.addSpacing(6)

        self._title = QLabel(title.upper())
        self._title.setObjectName("CardTitle")
        self._value = QLabel("—")
        self._value.setObjectName("CardValue")
        self._caption = QLabel("")
        self._caption.setObjectName("CardCaption")
        self._caption.setWordWrap(True)

        layout.addWidget(self._title)
        layout.addWidget(self._value)
        layout.addWidget(self._caption)
        layout.addStretch(1)

    @property
    def value(self) -> str:
        """
        The headline text currently shown.

        Returns:
            The value label's text.

        """
        return self._value.text()

    @property
    def caption(self) -> str:
        """
        The caption currently shown.

        Returns:
            The caption label's text.

        """
        return self._caption.text()

    def set_value(self, value: str, caption: str = "") -> None:
        """
        Update the headline number and its caption.

        Args:
            value: The headline text.
            caption: A short explanation shown under it.

        """
        self._value.setText(value)
        self._caption.setText(caption)
