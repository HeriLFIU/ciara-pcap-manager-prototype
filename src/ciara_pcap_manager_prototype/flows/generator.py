"""
Group packet rows into bidirectional flow segments.

Packets with the same direction-independent key (``base_flow_key``) belong to
the same flow. A flow is cut into *segments*, each closed for one of the
codebook's termination reasons:

``inactive_timeout``
    No packet for longer than the idle timeout. Checked when the next packet
    of the flow arrives and, for every open segment, whenever capture time
    advances (so a segment that went quiet is not mislabelled at the end).
``active_timeout``
    The segment has lasted longer than the active timeout. Checked when the
    next packet arrives; that packet opens the next segment.
``tcp_rst``
    A TCP packet carried RST. The RST packet is the segment's last packet.
``tcp_fin_both``
    Both directions have sent FIN. The packet that completes the pair is the
    segment's last packet; a trailing ACK opens a new segment.
``end_of_input``
    The capture ended while the segment was still open.

A packet that arrives after its segment closed opens the next segment of the
same key, with ``flow_segment_id`` incremented.
"""

import socket
from typing import TYPE_CHECKING, Final

from ciara_pcap_manager_prototype.domain.flows import TerminationReason
from ciara_pcap_manager_prototype.flows.segment import FlowSegment

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ciara_pcap_manager_prototype.domain.flows import Flow
    from ciara_pcap_manager_prototype.flows.packet import PacketRecord

_NS_PER_SECOND: Final = 1_000_000_000

#: Default timeouts, in seconds; configurable through ``CoreSettings``.
DEFAULT_IDLE_TIMEOUT_SECONDS: Final = 120.0
DEFAULT_ACTIVE_TIMEOUT_SECONDS: Final = 1800.0

#: How far capture time must advance before open segments are swept for idleness.
_SWEEP_INTERVAL_NS: Final = _NS_PER_SECOND


def base_flow_key(packet: "PacketRecord") -> str:
    """
    Build the direction-independent identity of a packet's flow.

    The two endpoints are ordered by (address, port), comparing addresses
    numerically, so ``A:p -> B:q`` and ``B:q -> A:p`` give the same key. Each
    port stays paired with its own address.

    Args:
        packet: The packet.

    Returns:
        ``proto|ip_low|ip_high|port_low|port_high``.

    """
    src = (socket.inet_aton(packet.inner_ip_src), packet.src_port)
    dst = (socket.inet_aton(packet.inner_ip_dst), packet.dst_port)
    if src <= dst:
        low_ip, low_port, high_ip, high_port = (
            packet.inner_ip_src,
            packet.src_port,
            packet.inner_ip_dst,
            packet.dst_port,
        )
    else:
        low_ip, low_port, high_ip, high_port = (
            packet.inner_ip_dst,
            packet.dst_port,
            packet.inner_ip_src,
            packet.src_port,
        )
    return f"{packet.inner_ip_proto}|{low_ip}|{high_ip}|{low_port}|{high_port}"


class FlowGenerator:
    """Turns a stream of packet rows into finished flows."""

    def __init__(
        self,
        *,
        idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
        active_timeout_seconds: float = DEFAULT_ACTIVE_TIMEOUT_SECONDS,
        max_flows: int = 0,
    ) -> None:
        """
        Configure the generator.

        Args:
            idle_timeout_seconds: Close a segment idle for longer than this.
            active_timeout_seconds: Close a segment that lasted longer than this.
            max_flows: Stop opening segments after this many. Zero means no cap.

        """
        self._idle_ns = int(idle_timeout_seconds * _NS_PER_SECOND)
        self._active_ns = int(active_timeout_seconds * _NS_PER_SECOND)
        self._max_flows = max_flows
        self._open: dict[str, FlowSegment] = {}
        self._next_segment: dict[str, int] = {}
        self._finished: list[Flow] = []
        self._segments_opened = 0
        self._latest_ns: int | None = None
        self._last_sweep_ns: int | None = None
        self.packets_over_cap = 0

    def add(self, packet: "PacketRecord") -> None:
        """
        Assign one packet to its flow segment.

        Args:
            packet: The next packet, in capture order.

        """
        now = packet.packet_time_ns
        self._advance_clock(now)

        key = base_flow_key(packet)
        segment = self._open.get(key)
        if segment is not None:
            if now - segment.last_ns > self._idle_ns:
                self._close(key, TerminationReason.INACTIVE_TIMEOUT)
                segment = None
            elif now - segment.first_ns > self._active_ns:
                self._close(key, TerminationReason.ACTIVE_TIMEOUT)
                segment = None

        if segment is None:
            if self._max_flows and self._segments_opened >= self._max_flows:
                self.packets_over_cap += 1
                return
            segment = self._open_segment(key, packet)

        segment.add(packet)

        if packet.is_tcp:
            if packet.tcp_flag_rst:
                self._close(key, TerminationReason.TCP_RST)
            elif segment.fin_seen_both_ways:
                self._close(key, TerminationReason.TCP_FIN_BOTH)

    def add_all(self, packets: "Iterable[PacketRecord]") -> None:
        """
        Assign every packet of a stream.

        Args:
            packets: Packets in capture order.

        """
        for packet in packets:
            self.add(packet)

    def finish(self) -> list["Flow"]:
        """
        Close every open segment and return all flows.

        Segments that were already idle for longer than the idle timeout at
        the last packet of the capture close as ``inactive_timeout``; the rest
        close as ``end_of_input``.

        Returns:
            Every flow, ordered by start time, then by flow id.

        """
        if self._latest_ns is not None:
            self._sweep_idle(self._latest_ns)
        for key in list(self._open):
            self._close(key, TerminationReason.END_OF_INPUT)
        return sorted(
            self._finished, key=lambda flow: (flow.flow_start_time, flow.flow_id)
        )

    def _open_segment(self, key: str, packet: "PacketRecord") -> FlowSegment:
        """
        Start the next segment of a key, oriented by its first packet.

        Args:
            key: The flow's base key.
            packet: The segment's first packet.

        Returns:
            The new, empty segment.

        """
        segment_id = self._next_segment.get(key, 0)
        self._next_segment[key] = segment_id + 1
        segment = FlowSegment(base_flow_key=key, segment_id=segment_id, first=packet)
        self._open[key] = segment
        self._segments_opened += 1
        return segment

    def _close(self, key: str, reason: TerminationReason) -> None:
        """
        Finish an open segment.

        Args:
            key: The flow's base key.
            reason: Why it is being closed.

        """
        self._finished.append(self._open.pop(key).to_flow(reason))

    def _advance_clock(self, now: int) -> None:
        """
        Track capture time and sweep idle segments once per elapsed second.

        Args:
            now: The current packet's timestamp, in nanoseconds.

        """
        if self._latest_ns is None or now > self._latest_ns:
            self._latest_ns = now
        if self._last_sweep_ns is None:
            self._last_sweep_ns = now
        elif self._latest_ns - self._last_sweep_ns >= _SWEEP_INTERVAL_NS:
            self._sweep_idle(self._latest_ns)
            self._last_sweep_ns = self._latest_ns

    def _sweep_idle(self, now: int) -> None:
        """
        Close every open segment idle for longer than the idle timeout.

        Args:
            now: The latest capture time seen, in nanoseconds.

        """
        idle = [
            key
            for key, segment in self._open.items()
            if now - segment.last_ns > self._idle_ns
        ]
        for key in idle:
            self._close(key, TerminationReason.INACTIVE_TIMEOUT)
