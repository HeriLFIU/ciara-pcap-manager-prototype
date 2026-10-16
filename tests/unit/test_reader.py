"""Tests for the libpcap and pcapng reader."""

import struct
from pathlib import Path

import pytest

from ciara_pcap_manager_prototype.pcap.reader import (
    LINKTYPE_ETHERNET,
    CaptureFormatError,
    iter_frames,
)

FRAME_A = b"\x01" * 60
FRAME_B = b"\x02" * 42


def classic(order: str, magic: int, records: list[tuple[int, int, bytes]]) -> bytes:
    """Build a classic capture: records are (seconds, fraction, data)."""
    header = struct.pack(f"{order}IHHiIII", magic, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    body = b"".join(
        struct.pack(f"{order}IIII", seconds, fraction, len(data), len(data) + 10) + data
        for seconds, fraction, data in records
    )
    return header + body


def block(order: str, block_type: int, body: bytes) -> bytes:
    """Build one pcapng block, padding the body to 32 bits."""
    body += b"\x00" * (-len(body) % 4)
    total = len(body) + 12
    return (
        struct.pack(f"{order}II", block_type, total)
        + body
        + struct.pack(f"{order}I", total)
    )


def section(order: str) -> bytes:
    """A Section Header Block."""
    return block(order, 0x0A0D0D0A, struct.pack(f"{order}IHHq", 0x1A2B3C4D, 1, 0, -1))


def interface(order: str, tsresol: int | None = None) -> bytes:
    """An Ethernet Interface Description Block, optionally with if_tsresol."""
    options = b""
    if tsresol is not None:
        options = struct.pack(f"{order}HH", 9, 1) + bytes([tsresol, 0, 0, 0])
        options += struct.pack(f"{order}HH", 0, 0)
    return block(
        order, 1, struct.pack(f"{order}HHI", LINKTYPE_ETHERNET, 0, 65535) + options
    )


def enhanced(order: str, ticks: int, data: bytes, interface_id: int = 0) -> bytes:
    """An Enhanced Packet Block."""
    head = struct.pack(
        f"{order}IIIII",
        interface_id,
        ticks >> 32,
        ticks & 0xFFFFFFFF,
        len(data),
        len(data),
    )
    return block(order, 6, head + data)


def write(tmp_path: Path, content: bytes) -> Path:
    """Write bytes to a capture file."""
    path = tmp_path / "capture.bin"
    path.write_bytes(content)
    return path


@pytest.mark.parametrize(
    ("order", "magic", "fraction", "expected_ns"),
    [
        ("<", 0xA1B2C3D4, 250_000, 250_000_000),
        (">", 0xA1B2C3D4, 250_000, 250_000_000),
        ("<", 0xA1B23C4D, 250_000_123, 250_000_123),
        (">", 0xA1B23C4D, 250_000_123, 250_000_123),
    ],
)
def test_classic_captures_in_both_orders_and_resolutions(
    tmp_path: Path, order: str, magic: int, fraction: int, expected_ns: int
) -> None:
    path = write(
        tmp_path, classic(order, magic, [(10, fraction, FRAME_A), (11, 0, FRAME_B)])
    )

    frames = list(iter_frames(path))

    assert [frame.data for frame in frames] == [FRAME_A, FRAME_B]
    assert frames[0].timestamp_ns == 10 * 1_000_000_000 + expected_ns
    assert frames[0].original_length == len(FRAME_A) + 10
    assert [frame.index for frame in frames] == [0, 1]
    assert frames[0].link_type == LINKTYPE_ETHERNET


def test_a_truncated_last_record_ends_the_stream(tmp_path: Path) -> None:
    content = classic("<", 0xA1B2C3D4, [(1, 0, FRAME_A), (2, 0, FRAME_B)])

    assert len(list(iter_frames(write(tmp_path, content[:-5])))) == 1
    assert len(list(iter_frames(write(tmp_path, content[: -len(FRAME_B) - 8])))) == 1


@pytest.mark.parametrize("order", ["<", ">"])
def test_pcapng_enhanced_packets_with_nanosecond_resolution(
    tmp_path: Path, order: str
) -> None:
    content = (
        section(order)
        + interface(order, tsresol=9)
        + enhanced(order, 5_000_000_001, FRAME_A)
    )

    (frame,) = iter_frames(write(tmp_path, content))

    assert frame.data == FRAME_A
    assert frame.timestamp_ns == 5_000_000_001


def test_pcapng_defaults_to_microsecond_resolution(tmp_path: Path) -> None:
    content = section("<") + interface("<") + enhanced("<", 1_500_000, FRAME_B)

    (frame,) = iter_frames(write(tmp_path, content))

    assert frame.timestamp_ns == 1_500_000_000


def test_pcapng_skips_packets_of_undeclared_interfaces_and_simple_blocks(
    tmp_path: Path,
) -> None:
    simple = block("<", 3, struct.pack("<I", len(FRAME_A)) + FRAME_A)
    content = (
        section("<")
        + interface("<")
        + enhanced("<", 1, FRAME_A, interface_id=3)
        + simple
        + enhanced("<", 2, FRAME_B)
    )

    frames = list(iter_frames(write(tmp_path, content)))

    assert [frame.data for frame in frames] == [FRAME_B]
    assert frames[0].index == 0


def test_pcapng_obsolete_packet_block(tmp_path: Path) -> None:
    head = struct.pack("<HHIIII", 0, 0, 0, 7, len(FRAME_A), len(FRAME_A))
    content = section("<") + interface("<") + block("<", 2, head + FRAME_A)

    (frame,) = iter_frames(write(tmp_path, content))

    assert (frame.data, frame.timestamp_ns) == (FRAME_A, 7_000)


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not a capture at all",
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x00\x00\x00\x00"
        + b"\x00" * 16,
        section("<") + struct.pack("<II", 6, 13) + b"\x00" * 8,
        section("<") + block("<", 6, b"\x00" * 8),
    ],
    ids=["empty", "text", "bad-byte-order", "bad-length", "short-packet-block"],
)
def test_corrupt_files_are_rejected(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(CaptureFormatError):
        list(iter_frames(write(tmp_path, content)))
