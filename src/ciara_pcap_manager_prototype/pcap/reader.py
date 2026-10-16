"""
Streaming reader for classic libpcap and pcapng capture files.

The reader yields one :class:`Frame` per captured packet and never loads the
whole file into memory. It needs no native library: both formats are simple,
length-prefixed record streams, and parsing them with :mod:`struct` keeps the
platform free of libpcap/Npcap installation problems.

Formats:

* classic libpcap, in either byte order, with microsecond or nanosecond
  timestamps (https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/);
* pcapng Enhanced Packet Blocks and the obsolete Packet Block, with each
  interface's ``if_tsresol`` and ``if_tsoffset`` honoured
  (https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/). Simple Packet
  Blocks carry no timestamp and are skipped.
"""

import logging
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO, Final

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

logger = logging.getLogger(__name__)

#: DLT/LINKTYPE value for Ethernet, the only link type the decoder walks.
LINKTYPE_ETHERNET: Final = 1

_NS_PER_SECOND: Final = 1_000_000_000

_CLASSIC_HEADER_LEN: Final = 24
_CLASSIC_RECORD_LEN: Final = 16

#: Classic magic numbers as read in little-endian order, mapped to
#: ``(struct byte-order prefix, nanoseconds per timestamp fraction unit)``.
_CLASSIC_MAGICS: Final[dict[bytes, tuple[str, int]]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),  # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000),  # big endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),  # big endian, nanoseconds
}

_PCAPNG_SHB: Final = 0x0A0D0D0A
_PCAPNG_IDB: Final = 0x00000001
_PCAPNG_PB: Final = 0x00000002
_PCAPNG_SPB: Final = 0x00000003
_PCAPNG_EPB: Final = 0x00000006
_PCAPNG_BYTE_ORDER_MAGIC: Final = 0x1A2B3C4D
_PCAPNG_OPT_END: Final = 0
_PCAPNG_OPT_TSRESOL: Final = 9
_PCAPNG_OPT_TSOFFSET: Final = 14
_PCAPNG_MIN_BLOCK: Final = 12
_PCAPNG_MIN_SHB: Final = 28
#: Fixed fields each block body must hold before its variable part.
_PCAPNG_MIN_BODY: Final[dict[int, int]] = {
    _PCAPNG_IDB: 8,
    _PCAPNG_PB: 20,
    _PCAPNG_EPB: 20,
}
_PCAPNG_DEFAULT_TSRESOL: Final = 6
_TSRESOL_BASE2_FLAG: Final = 0x80
_TSRESOL_EXPONENT_MASK: Final = 0x7F

#: Bit mask for the link type in a classic header's LinkType field; the upper
#: bits may carry FCS information.
_LINKTYPE_MASK: Final = 0xFFFF


class CaptureFormatError(ValueError):
    """Raised when a file is not a readable libpcap or pcapng capture."""


@dataclass(frozen=True, slots=True)
class Frame:
    """One captured packet, exactly as stored in the capture file."""

    index: int
    """Zero-based position of the packet in the file."""

    timestamp_ns: int
    """Capture time in nanoseconds since the Unix epoch."""

    data: bytes
    """The captured bytes, which may be fewer than the packet's original size."""

    original_length: int
    """Length of the packet on the wire, before any snap-length truncation."""

    link_type: int
    """LINKTYPE of the interface that captured the packet."""


def iter_frames(path: "Path") -> "Iterator[Frame]":
    """
    Yield every packet stored in a capture file, in file order.

    Args:
        path: The capture file to read.

    Yields:
        One frame per captured packet.

    Raises:
        CaptureFormatError: If the file is not a libpcap or pcapng capture, or
            its headers are corrupt.

    """
    with path.open("rb") as handle:
        magic = handle.read(4)
        handle.seek(0)
        if magic in _CLASSIC_MAGICS:
            yield from _iter_classic(handle)
        elif len(magic) == 4 and struct.unpack("<I", magic)[0] == _PCAPNG_SHB:  # noqa: PLR2004 - magic length
            yield from _iter_pcapng(handle)
        else:
            msg = (
                f"{path.name} is not a libpcap or pcapng capture "
                f"(unexpected magic number {magic.hex() or 'empty'})."
            )
            raise CaptureFormatError(msg)


def _iter_classic(handle: BinaryIO) -> "Iterator[Frame]":
    """
    Read a classic libpcap stream.

    Args:
        handle: The open file, positioned at its first byte.

    Yields:
        One frame per record.

    Raises:
        CaptureFormatError: If the global header is incomplete.

    """
    header = handle.read(_CLASSIC_HEADER_LEN)
    if len(header) < _CLASSIC_HEADER_LEN:
        msg = "Capture ends inside the libpcap global header."
        raise CaptureFormatError(msg)

    order, fraction_ns = _CLASSIC_MAGICS[header[:4]]
    link_type = struct.unpack(f"{order}I", header[20:24])[0] & _LINKTYPE_MASK
    record = struct.Struct(f"{order}IIII")

    index = 0
    while True:
        raw = handle.read(_CLASSIC_RECORD_LEN)
        if not raw:
            return
        if len(raw) < _CLASSIC_RECORD_LEN:
            logger.warning("Capture ends inside the header of packet %d", index)
            return
        seconds, fraction, captured, original = record.unpack(raw)
        data = handle.read(captured)
        if len(data) < captured:
            logger.warning("Capture ends inside the data of packet %d", index)
            return
        yield Frame(
            index=index,
            timestamp_ns=seconds * _NS_PER_SECOND + fraction * fraction_ns,
            data=data,
            original_length=original,
            link_type=link_type,
        )
        index += 1


@dataclass(slots=True)
class _Interface:
    """What a pcapng Interface Description Block tells us about its packets."""

    link_type: int
    units_per_second: int
    offset_seconds: int

    def to_ns(self, ticks: int) -> int:
        """
        Convert a raw pcapng timestamp into epoch nanoseconds.

        Args:
            ticks: The 64-bit timestamp in this interface's resolution.

        Returns:
            Nanoseconds since the Unix epoch.

        """
        return (
            ticks * _NS_PER_SECOND // self.units_per_second
            + self.offset_seconds * _NS_PER_SECOND
        )


def _iter_pcapng(handle: BinaryIO) -> "Iterator[Frame]":
    """
    Read a pcapng stream block by block.

    Args:
        handle: The open file, positioned at its first byte.

    Yields:
        One frame per Enhanced Packet Block or Packet Block.

    Raises:
        CaptureFormatError: If a block is corrupt.

    """
    order = "<"
    interfaces: list[_Interface] = []
    index = 0

    while (block := _read_block(handle, order)) is not None:
        block_type, body, order = block
        if block_type in _PCAPNG_MIN_BODY and len(body) < _PCAPNG_MIN_BODY[block_type]:
            msg = f"pcapng block of type {block_type:#x} is too short ({len(body)} B)."
            raise CaptureFormatError(msg)

        if block_type == _PCAPNG_SHB:
            interfaces = []
        elif block_type == _PCAPNG_IDB:
            interfaces.append(_parse_interface(body, order))
        elif block_type in {_PCAPNG_EPB, _PCAPNG_PB}:
            frame = _parse_packet_block(block_type, body, order, interfaces, index)
            if frame is not None:
                yield frame
                index += 1
        elif block_type == _PCAPNG_SPB:
            logger.debug("Skipping a Simple Packet Block: it carries no timestamp")


def _read_block(handle: BinaryIO, order: str) -> tuple[int, bytes, str] | None:
    """
    Read one whole pcapng block.

    A Section Header Block sets the byte order for the blocks that follow it,
    so its own byte-order magic is read before its length is interpreted.

    Args:
        handle: The open file, positioned at a block boundary.
        order: The current section's struct byte-order prefix.

    Returns:
        ``(block_type, body, byte_order)`` where ``body`` is everything between
        the length field and the trailing length, or None at the end of the
        file or when the file ends inside the block.

    Raises:
        CaptureFormatError: If the block's length or byte-order magic is invalid.

    """
    head = handle.read(8)
    if len(head) < 8:  # noqa: PLR2004 - block type + length
        if head:
            logger.warning("Capture ends inside a pcapng block header")
        return None

    minimum = _PCAPNG_MIN_BLOCK
    prefix = b""
    if struct.unpack("<I", head[:4])[0] == _PCAPNG_SHB:
        prefix = handle.read(4)
        order = _section_byte_order(prefix)
        minimum = _PCAPNG_MIN_SHB

    block_type, total = struct.unpack(f"{order}II", head)
    if total < minimum or total % 4:
        msg = f"pcapng block of type {block_type:#x} has invalid length {total}."
        raise CaptureFormatError(msg)

    body = prefix + handle.read(total - 12 - len(prefix))
    trailer = handle.read(4)
    if len(body) < total - 12 or len(trailer) < 4:  # noqa: PLR2004 - trailer length
        logger.warning("Capture ends inside a pcapng block")
        return None
    return block_type, body, order


def _section_byte_order(magic: bytes) -> str:
    """
    Read a Section Header Block's byte-order magic.

    Args:
        magic: The four bytes following the block length.

    Returns:
        The struct byte-order prefix for the section.

    Raises:
        CaptureFormatError: If the magic is missing or matches neither order.

    """
    if len(magic) == 4:  # noqa: PLR2004 - magic length
        if struct.unpack("<I", magic)[0] == _PCAPNG_BYTE_ORDER_MAGIC:
            return "<"
        if struct.unpack(">I", magic)[0] == _PCAPNG_BYTE_ORDER_MAGIC:
            return ">"
    msg = "pcapng section header has a missing or invalid byte-order magic."
    raise CaptureFormatError(msg)


def _parse_interface(body: bytes, order: str) -> _Interface:
    """
    Read an Interface Description Block.

    Args:
        body: The block body, after the type and length fields.
        order: The section's struct byte-order prefix.

    Returns:
        The interface's link type and timestamp resolution.

    """
    link_type = struct.unpack(f"{order}H", body[:2])[0]
    tsresol = _PCAPNG_DEFAULT_TSRESOL
    offset_seconds = 0

    position = 8
    while position + 4 <= len(body):
        code, length = struct.unpack(f"{order}HH", body[position : position + 4])
        value = body[position + 4 : position + 4 + length]
        if code == _PCAPNG_OPT_END:
            break
        if code == _PCAPNG_OPT_TSRESOL and length >= 1:
            tsresol = value[0]
        elif code == _PCAPNG_OPT_TSOFFSET and length >= 8:  # noqa: PLR2004 - int64
            offset_seconds = struct.unpack(f"{order}q", value[:8])[0]
        position += 4 + length + (-length % 4)

    exponent = tsresol & _TSRESOL_EXPONENT_MASK
    units = 2**exponent if tsresol & _TSRESOL_BASE2_FLAG else 10**exponent
    return _Interface(
        link_type=link_type, units_per_second=units, offset_seconds=offset_seconds
    )


def _parse_packet_block(
    block_type: int,
    body: bytes,
    order: str,
    interfaces: list[_Interface],
    index: int,
) -> Frame | None:
    """
    Read an Enhanced Packet Block or an obsolete Packet Block.

    Args:
        block_type: Which of the two block types this is.
        body: The block body, after the type and length fields.
        order: The section's struct byte-order prefix.
        interfaces: Interfaces declared so far in this section.
        index: Position to assign to the frame.

    Returns:
        The frame, or None if it names an undeclared interface.

    """
    fields: tuple[int, ...]
    if block_type == _PCAPNG_EPB:
        fields = struct.unpack(f"{order}IIIII", body[:20])
    else:
        # The obsolete Packet Block has a 16-bit drop counter after the id.
        interface_id_and_drops = struct.unpack(f"{order}HHIIII", body[:20])
        fields = (interface_id_and_drops[0], *interface_id_and_drops[2:])
    interface_id, high, low, captured, original = fields
    if interface_id >= len(interfaces):
        logger.warning("Packet %d names undeclared interface %d", index, interface_id)
        return None
    interface = interfaces[interface_id]
    return Frame(
        index=index,
        timestamp_ns=interface.to_ns((high << 32) | low),
        data=body[20 : 20 + captured],
        original_length=original,
        link_type=interface.link_type,
    )
