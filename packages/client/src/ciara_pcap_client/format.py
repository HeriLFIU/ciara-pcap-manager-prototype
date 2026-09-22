"""
Value formatting shared by every Python client.

Byte counts, timestamps and nDPI labels were formatted identically in the CLI
and in the desktop client. Keeping one implementation here means a capture
renders the same in a terminal table and in a Qt cell, and the ``UNSET``
narrowing needed to read an optional SDK field happens in one place.
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ciara_pcap_sdk.types import Unset

from ciara_pcap_client.unset import value_or

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import Flow, FlowSummary

__all__ = [
    "application_label",
    "format_bytes",
    "format_clock",
    "format_timestamp",
    "ranked_applications",
]

_BYTE_UNITS = ("B", "KB", "MB", "GB", "TB")
_BYTE_STEP = 1024


def format_bytes(count: int) -> str:
    """
    Render a byte count in the largest unit that keeps it readable.

    Args:
        count: The number of bytes.

    Returns:
        A short human-readable string such as ``1.4 MB``.

    """
    size = float(count)
    for unit in _BYTE_UNITS[:-1]:
        if size < _BYTE_STEP:
            return f"{size:.{0 if unit == 'B' else 1}f} {unit}"
        size /= _BYTE_STEP
    return f"{size:.1f} {_BYTE_UNITS[-1]}"


def _utc(epoch_ms: int) -> datetime:
    """
    Convert epoch milliseconds into a timezone-aware UTC datetime.

    Args:
        epoch_ms: Milliseconds since the Unix epoch.

    Returns:
        The equivalent UTC datetime.

    """
    return datetime.fromtimestamp(epoch_ms / 1000, tz=UTC)


def format_timestamp(epoch_ms: int) -> str:
    """
    Render epoch milliseconds as a full UTC date and time.

    Args:
        epoch_ms: Milliseconds since the Unix epoch.

    Returns:
        A ``YYYY-MM-DD HH:MM:SS.mmm`` timestamp.

    """
    moment = _utc(epoch_ms)
    return moment.strftime("%Y-%m-%d %H:%M:%S.") + f"{moment.microsecond // 1000:03d}"


def format_clock(epoch_ms: int) -> str:
    """
    Render epoch milliseconds as a UTC wall-clock time.

    Every flow in one capture shares a date, so the flow table shows only the
    time of day.

    Args:
        epoch_ms: Milliseconds since the Unix epoch.

    Returns:
        A ``HH:MM:SS.mmm`` timestamp.

    """
    moment = _utc(epoch_ms)
    return moment.strftime("%H:%M:%S.") + f"{moment.microsecond // 1000:03d}"


def application_label(flow: "Flow") -> str:
    """
    Render a flow's application label, flagging values nDPI merely guessed.

    Args:
        flow: The flow to describe.

    Returns:
        The application name, suffixed with ``?`` when the label was a guess.

    """
    guessed = value_or(flow.application_is_guessed, default=False)
    return f"{flow.application_name}{'?' if guessed else ''}"


def ranked_applications(
    summary: "FlowSummary", *, top: int = 0
) -> list[tuple[str, int]]:
    """
    Read a summary's application histogram, most frequent first.

    The generated SDK models a free-form object as a class whose keys live in
    ``additional_properties``, and the whole field is ``UNSET`` when the backend
    omitted it.

    Args:
        summary: The capture summary.
        top: Keep only this many entries. Zero keeps all of them.

    Returns:
        ``(application, flow_count)`` pairs, empty when the backend sent none.

    """
    histogram = summary.top_applications
    if isinstance(histogram, Unset):
        return []
    ranked = sorted(
        histogram.additional_properties.items(), key=lambda item: (-item[1], item[0])
    )
    return ranked[:top] if top else ranked
