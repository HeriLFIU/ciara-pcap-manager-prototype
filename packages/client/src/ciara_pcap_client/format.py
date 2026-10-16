"""
Value formatting shared by every Python client.

A capture renders the same in a terminal table and in a Qt cell because both
call these functions. The ``UNSET`` narrowing needed to read an optional SDK
field also happens here, once.
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from ciara_pcap_sdk.types import Unset

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import FlowSummary

__all__ = [
    "Histogram",
    "endpoint",
    "format_bytes",
    "format_clock",
    "format_count",
    "format_duration",
    "format_nanoseconds",
    "format_percent",
    "format_timestamp",
    "int_coverage",
    "protocol_label",
    "ranked_counts",
]

_BYTE_UNITS = ("B", "KB", "MB", "GB", "TB")
_BYTE_STEP = 1024
_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 132: "SCTP"}
_MILLISECOND = 1e-3
_MICROSECOND = 1e-6
_NS_PER_US = 1_000
_NS_PER_MS = 1_000_000


class Histogram(Protocol):
    """The shape the SDK generates for a free-form ``{str: int}`` object."""

    additional_properties: dict[str, int]


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


def format_count(count: int) -> str:
    """
    Render an integer with thousands separators.

    Args:
        count: The number.

    Returns:
        For example ``15,458``.

    """
    return f"{count:,}"


def format_percent(fraction: float | None) -> str:
    """
    Render a fraction in [0, 1] as a percentage.

    Args:
        fraction: The fraction, or None when undefined.

    Returns:
        For example ``42.0%``, or an em dash when undefined.

    """
    return "—" if fraction is None else f"{fraction * 100:.1f}%"


def _utc(epoch_seconds: float) -> datetime:
    """
    Convert epoch seconds into a timezone-aware UTC datetime.

    Args:
        epoch_seconds: Seconds since the Unix epoch.

    Returns:
        The equivalent UTC datetime.

    """
    return datetime.fromtimestamp(epoch_seconds, tz=UTC)


def format_timestamp(epoch_seconds: float) -> str:
    """
    Render epoch seconds as a full UTC date and time.

    Args:
        epoch_seconds: Seconds since the Unix epoch.

    Returns:
        A ``YYYY-MM-DD HH:MM:SS.mmm`` timestamp.

    """
    moment = _utc(epoch_seconds)
    return moment.strftime("%Y-%m-%d %H:%M:%S.") + f"{moment.microsecond // 1000:03d}"


def format_clock(epoch_seconds: float) -> str:
    """
    Render epoch seconds as a UTC wall-clock time with microseconds.

    Every flow in one capture usually shares a date, so the flow table shows
    only the time of day.

    Args:
        epoch_seconds: Seconds since the Unix epoch.

    Returns:
        A ``HH:MM:SS.uuuuuu`` timestamp.

    """
    return _utc(epoch_seconds).strftime("%H:%M:%S.%f")


def format_duration(seconds: float) -> str:
    """
    Render a duration in the unit that keeps it readable.

    Args:
        seconds: The duration in seconds.

    Returns:
        For example ``0 s``, ``850 µs``, ``12.5 ms`` or ``3.200 s``.

    """
    if seconds == 0:
        return "0 s"
    if seconds < _MILLISECOND:
        return f"{seconds / _MICROSECOND:.0f} µs"
    if seconds < 1:
        return f"{seconds / _MILLISECOND:.1f} ms"
    return f"{seconds:.3f} s"


def format_nanoseconds(value: float | None) -> str:
    """
    Render a nanosecond quantity, such as an INT latency.

    Args:
        value: Nanoseconds, or None when not measured.

    Returns:
        For example ``1.54 µs``, or an em dash when not measured.

    """
    if value is None:
        return "—"
    if value < _NS_PER_US:
        return f"{value:.0f} ns"
    if value < _NS_PER_MS:
        return f"{value / _NS_PER_US:.2f} µs"
    return f"{value / _NS_PER_MS:.2f} ms"


def protocol_label(proto: int) -> str:
    """
    Name an IP protocol number.

    Args:
        proto: The IANA protocol number.

    Returns:
        ``TCP``, ``UDP`` and so on, or ``IP-<n>`` when unmapped.

    """
    return _PROTOCOLS.get(proto, f"IP-{proto}")


def endpoint(ip: str, port: int) -> str:
    """
    Join an address and a port.

    Args:
        ip: The IPv4 address.
        port: The transport port.

    Returns:
        ``ip:port``.

    """
    return f"{ip}:{port}"


def ranked_counts(histogram: "Histogram | Unset") -> list[tuple[str, int]]:
    """
    Read a ``{name: count}`` object from the SDK, largest count first.

    The generated SDK models a free-form object as a class whose keys live in
    ``additional_properties``, and the whole field is ``UNSET`` when the backend
    omitted it.

    Args:
        histogram: The SDK field.

    Returns:
        ``(name, count)`` pairs, empty when the backend sent none.

    """
    if isinstance(histogram, Unset):
        return []
    return sorted(
        histogram.additional_properties.items(), key=lambda item: (-item[1], item[0])
    )


def int_coverage(summary: "FlowSummary") -> float | None:
    """
    Compute the share of decoded inner packets that carried INT hops.

    Args:
        summary: The capture summary.

    Returns:
        A fraction in [0, 1], or None when no inner packet was decoded.

    """
    decode = summary.decode
    if not decode.inner_packets:
        return None
    return decode.packets_with_int_hops / decode.inner_packets
