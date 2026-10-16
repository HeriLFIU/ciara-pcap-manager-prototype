"""
Packet rows: the per-packet fields the flow generator consumes.

`PacketRecord` holds the parser columns of the PIPELINE_V2 feature codebook
(section 1) for one decoded inner packet, plus three INT aggregates the
generator needs that the codebook's packet table does not list
(``int_hop_count``, ``int_path_latency`` and ``int_queue_observations``).

Conventions, from codebook section 0.1:

* TCP rows carry parsed TCP fields and zeros for UDP-only fields; UDP rows
  carry parsed UDP fields and zeros for TCP-only fields.
* INT fields are None when the packet carries no parseable INT hop.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ciara_pcap_manager_prototype.telemetry.decoder import IP_PROTO_TCP

if TYPE_CHECKING:
    from ciara_pcap_manager_prototype.pcap.reader import Frame
    from ciara_pcap_manager_prototype.telemetry.layers import DecodedPacket

TCP_FIN: Final = 0x01
TCP_SYN: Final = 0x02
TCP_RST: Final = 0x04
TCP_PSH: Final = 0x08
TCP_ACK: Final = 0x10
TCP_URG: Final = 0x20

_TCP_MIN_HEADER: Final = 20
_NS_PER_SECOND: Final = 1_000_000_000

#: The parser cannot tell which way a packet travels; the generator orients it.
UNKNOWN_DIRECTION: Final = "unknown"


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """One decoded inner packet, flattened into codebook packet columns."""

    packet_uid: str
    source_file: str
    packet_index: int
    packet_time: float
    packet_time_ns: int
    timeframe_id: str | None
    direction: str
    inner_ip_src: str
    inner_ip_dst: str
    inner_ip_proto: int
    l4_proto: str
    src_port: int
    dst_port: int
    tcp_dataofs: int
    tcp_header_len_bytes: int
    tcp_options_len: int
    inner_ip_len: int
    inner_ip_total_length_declared: int
    int_ingress_timestamp: int | None
    int_egress_timestamp: int | None
    int_queue_occupancy: int | None
    inner_ip_truncated_vs_declared: bool
    inner_udp_truncated_vs_declared: bool
    tcp_flag_syn: bool
    tcp_flag_ack: bool
    tcp_flag_fin: bool
    tcp_flag_rst: bool
    tcp_flag_psh: bool
    tcp_flag_urg: bool
    capture_start_utc: str | None
    capture_end_utc: str | None
    capture_start_epoch: float | None
    capture_end_epoch: float | None
    int_hop_count: int
    """INT hops decoded for this packet; 0 without INT."""
    int_path_latency: int | None
    """Sum of the decoded hops' latencies (ns), None if no hop had one."""
    int_queue_observations: tuple[int, ...]
    """Queue occupancy of every decoded hop that reported one."""

    @property
    def is_tcp(self) -> bool:
        """
        Report whether the inner packet is TCP.

        Returns:
            True for TCP, False for UDP.

        """
        return self.inner_ip_proto == IP_PROTO_TCP

    @property
    def int_timestamp(self) -> int | None:
        """
        Pick the INT timestamp used for inter-arrival times.

        Returns:
            The first hop's egress timestamp, falling back to its ingress
            timestamp, or None when neither was decoded.

        """
        if self.int_egress_timestamp is not None:
            return self.int_egress_timestamp
        return self.int_ingress_timestamp


def build_packet_record(
    frame: "Frame",
    decoded: "DecodedPacket",
    *,
    source_file: str,
    timeframe_id: str | None,
) -> PacketRecord:
    """
    Flatten a decoded packet into a packet row.

    The packet-level INT fields come from the first hop of the stack. The
    capture-window columns stay None: they are only defined for files named
    after a timestamp range, and no such naming scheme is configured.

    Args:
        frame: The captured frame the packet came from.
        decoded: The decoder's output for that frame.
        source_file: Name of the capture file, for provenance.
        timeframe_id: Timeframe label for the file.

    Returns:
        The packet row.

    """
    inner = decoded.inner
    is_tcp = inner.ip_proto == IP_PROTO_TCP
    flags = inner.tcp_flags
    header_len = inner.tcp_data_offset * 4 if is_tcp else 0

    hops = decoded.int_telemetry.hops if decoded.int_telemetry else ()
    first = hops[0] if hops else None
    latencies = [hop.hop_latency for hop in hops if hop.hop_latency is not None]

    return PacketRecord(
        packet_uid=f"{timeframe_id}|{source_file}|{frame.index}",
        source_file=source_file,
        packet_index=frame.index,
        packet_time=frame.timestamp_ns / _NS_PER_SECOND,
        packet_time_ns=frame.timestamp_ns,
        timeframe_id=timeframe_id,
        direction=UNKNOWN_DIRECTION,
        inner_ip_src=inner.src_ip,
        inner_ip_dst=inner.dst_ip,
        inner_ip_proto=inner.ip_proto,
        l4_proto="TCP" if is_tcp else "UDP",
        src_port=inner.src_port,
        dst_port=inner.dst_port,
        tcp_dataofs=inner.tcp_data_offset,
        tcp_header_len_bytes=header_len,
        tcp_options_len=max(header_len - _TCP_MIN_HEADER, 0),
        inner_ip_len=inner.ip_total_length,
        inner_ip_total_length_declared=inner.ip_total_length,
        int_ingress_timestamp=first.ingress_timestamp if first else None,
        int_egress_timestamp=first.egress_timestamp if first else None,
        int_queue_occupancy=first.queue_occupancy if first else None,
        inner_ip_truncated_vs_declared=inner.ip_captured_bytes != inner.ip_total_length,
        inner_udp_truncated_vs_declared=(
            not is_tcp and inner.udp_captured_bytes != inner.udp_length
        ),
        tcp_flag_syn=bool(flags & TCP_SYN),
        tcp_flag_ack=bool(flags & TCP_ACK),
        tcp_flag_fin=bool(flags & TCP_FIN),
        tcp_flag_rst=bool(flags & TCP_RST),
        tcp_flag_psh=bool(flags & TCP_PSH),
        tcp_flag_urg=bool(flags & TCP_URG),
        capture_start_utc=None,
        capture_end_utc=None,
        capture_start_epoch=None,
        capture_end_epoch=None,
        int_hop_count=len(hops),
        int_path_latency=sum(latencies) if latencies else None,
        int_queue_observations=tuple(
            hop.queue_occupancy for hop in hops if hop.queue_occupancy is not None
        ),
    )
