"""
Build small, deterministic libpcap files without a capture library.

Committing binary fixtures makes a repository opaque and hard to review. These
helpers write the handful of bytes NFStream needs straight from ``struct``, so
every fixture in the suite is readable source.

Run it directly to regenerate the sample shipped for manual testing::

    uv run python tests/support/pcap_factory.py samples/synthetic.pcap
"""

import socket
import struct
import sys
from pathlib import Path

PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

ETH_TYPE_IPV4 = 0x0800
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PSH = 0x08
TH_ACK = 0x10

_SRC_MAC = b"\x00\x11\x22\x33\x44\x55"
_DST_MAC = b"\x66\x77\x88\x99\xaa\xbb"

#: Base capture timestamp: 2023-11-14 22:13:20 UTC, chosen only for stability.
BASE_EPOCH_SECONDS = 1_700_000_000


def _checksum(data: bytes) -> int:
    """
    Compute the 16-bit one's complement checksum used by IP headers.

    Args:
        data: The bytes to checksum. Padded to an even length internally.

    Returns:
        The checksum, ready to place in a header field.

    """
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    """
    Build an IPv4 packet.

    Args:
        src: Source address in dotted-quad form.
        dst: Destination address in dotted-quad form.
        protocol: IANA protocol number of the payload.
        payload: The transport-layer bytes.

    Returns:
        The encoded IPv4 packet.

    """
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0x4000,
        64,
        protocol,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def _ethernet(payload: bytes) -> bytes:
    """
    Wrap a payload in an Ethernet II frame.

    Args:
        payload: The network-layer bytes.

    Returns:
        The encoded frame.

    """
    return _DST_MAC + _SRC_MAC + struct.pack("!H", ETH_TYPE_IPV4) + payload


def tcp_segment(
    src_port: int,
    dst_port: int,
    *,
    flags: int,
    seq: int = 0,
    ack: int = 0,
    payload: bytes = b"",
) -> bytes:
    """
    Build a TCP segment with a zeroed checksum.

    NFStream reads the header fields and never validates the checksum, so
    leaving it at zero keeps these fixtures readable.

    Args:
        src_port: Source port.
        dst_port: Destination port.
        flags: TCP flag bits.
        seq: Sequence number.
        ack: Acknowledgement number.
        payload: Application bytes carried by the segment.

    Returns:
        The encoded segment.

    """
    header = struct.pack(
        "!HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 64240, 0, 0
    )
    return header + payload


def udp_datagram(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """
    Build a UDP datagram with a zeroed checksum.

    Args:
        src_port: Source port.
        dst_port: Destination port.
        payload: Application bytes carried by the datagram.

    Returns:
        The encoded datagram.

    """
    header = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return header + payload


def dns_query(name: str, *, transaction_id: int = 0x1234) -> bytes:
    """
    Build a minimal DNS A-record query.

    Args:
        name: The hostname to ask about.
        transaction_id: DNS transaction identifier.

    Returns:
        The encoded DNS message.

    """
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + question + b"\x00" + struct.pack("!HH", 1, 1)


def dns_response(name: str, address: str, *, transaction_id: int = 0x1234) -> bytes:
    """
    Build a minimal DNS response carrying one A record.

    Args:
        name: The hostname that was asked about.
        address: The answer, in dotted-quad form.
        transaction_id: DNS transaction identifier.

    Returns:
        The encoded DNS message.

    """
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    header = struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
    body = question + b"\x00" + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return header + body + answer


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> Path:
    """
    Write frames to a classic libpcap file.

    Args:
        path: Destination file.
        packets: ``(timestamp, frame)`` pairs in capture order.

    Returns:
        The path that was written.

    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(
            struct.pack(
                "!IHHiIII",
                PCAP_MAGIC_MICROSECONDS,
                2,
                4,
                0,
                0,
                SNAPLEN,
                LINKTYPE_ETHERNET,
            )
        )
        for timestamp, frame in packets:
            seconds = int(timestamp)
            microseconds = round((timestamp - seconds) * 1_000_000)
            handle.write(
                struct.pack("!IIII", seconds, microseconds, len(frame), len(frame))
            )
            handle.write(frame)
    return path


def build_sample_capture(path: Path) -> Path:
    """
    Write a capture holding one HTTP conversation and one DNS exchange.

    The HTTP flow carries a full TCP handshake and teardown so NFStream's
    state machine sees a well-formed, standard-compliant flow.

    Args:
        path: Destination file.

    Returns:
        The path that was written.

    """
    client, server, resolver = "10.0.0.1", "93.184.216.34", "8.8.8.8"
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

    exchanges: list[tuple[str, str, bytes]] = [
        (client, server, tcp_segment(5001, 80, flags=TH_SYN, seq=1000)),
        (
            server,
            client,
            tcp_segment(80, 5001, flags=TH_SYN | TH_ACK, seq=5000, ack=1001),
        ),
        (client, server, tcp_segment(5001, 80, flags=TH_ACK, seq=1001, ack=5001)),
        (
            client,
            server,
            tcp_segment(
                5001, 80, flags=TH_ACK | TH_PSH, seq=1001, ack=5001, payload=request
            ),
        ),
        (
            server,
            client,
            tcp_segment(
                80, 5001, flags=TH_ACK | TH_PSH, seq=5001, ack=1040, payload=response
            ),
        ),
        (
            client,
            server,
            tcp_segment(5001, 80, flags=TH_ACK | TH_FIN, seq=1040, ack=5040),
        ),
        (
            server,
            client,
            tcp_segment(80, 5001, flags=TH_ACK | TH_FIN, seq=5040, ack=1041),
        ),
        (client, server, tcp_segment(5001, 80, flags=TH_ACK, seq=1041, ack=5041)),
        (client, resolver, udp_datagram(40000, 53, dns_query("example.com"))),
        (
            resolver,
            client,
            udp_datagram(53, 40000, dns_response("example.com", server)),
        ),
    ]

    packets: list[tuple[float, bytes]] = []
    for index, (src, dst, transport) in enumerate(exchanges):
        protocol = (
            IP_PROTO_UDP if src in {resolver} or dst in {resolver} else IP_PROTO_TCP
        )
        frame = _ethernet(_ipv4(src, dst, protocol, transport))
        packets.append((BASE_EPOCH_SECONDS + index * 0.01, frame))

    return write_pcap(path, packets)


if __name__ == "__main__":
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/synthetic.pcap")
    print(build_sample_capture(destination))
