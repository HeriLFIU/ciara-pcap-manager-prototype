"""
Restore capture-time order with a bounded buffer.

A collector capture interleaves several report streams (one per switch or
collector port). Each stream is in time order, but the streams lag each other,
so file order is not time order: in the bundled 50,000-packet sample, 22,220
frames carry a timestamp earlier than one already read, by up to 115 ms.

Flow features depend on order. The first packet orients a flow, its duration
spans first to last, and INT inter-arrival times are differences between
consecutive packets. Feeding packets out of order turns a small negative INT
delta into a ~4.29 s value once it is taken modulo 2**32.

`ReorderBuffer` holds packets for a fixed window of capture time and releases
them in timestamp order. Memory is bounded by the packets that arrive within
one window. A packet that lags by more than the window can no longer be put
in place; it is released at once and counted as late.
"""

import heapq
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ciara_pcap_manager_prototype.flows.packet import PacketRecord

_NS_PER_SECOND: Final = 1_000_000_000

#: Default window, in seconds: comfortably above the lag seen in practice.
DEFAULT_REORDER_WINDOW_SECONDS: Final = 1.0


class ReorderBuffer:
    """Releases packet rows in capture-time order within a sliding window."""

    def __init__(self, window_seconds: float = DEFAULT_REORDER_WINDOW_SECONDS) -> None:
        """
        Configure the buffer.

        Args:
            window_seconds: How long to hold a packet waiting for earlier ones.
                Zero disables reordering: packets pass through in file order.

        """
        self._window_ns = int(window_seconds * _NS_PER_SECOND)
        self._heap: list[tuple[int, int, PacketRecord]] = []
        self._latest_ns: int | None = None
        self._released_ns: int | None = None
        self.out_of_order = 0
        """Packets read with a timestamp earlier than one already read."""
        self.late = 0
        """Packets released after a later-stamped packet had already left."""

    def push(self, packet: "PacketRecord") -> "Iterator[PacketRecord]":
        """
        Accept one packet and release every packet that is now safe to emit.

        Args:
            packet: The next packet, in file order.

        Yields:
            Packets whose timestamp is at least one window older than the
            newest timestamp read so far, oldest first.

        """
        now = packet.packet_time_ns
        if self._latest_ns is not None and now < self._latest_ns:
            self.out_of_order += 1
        if self._latest_ns is None or now > self._latest_ns:
            self._latest_ns = now

        # The packet index breaks timestamp ties, keeping file order stable.
        heapq.heappush(self._heap, (now, packet.packet_index, packet))
        horizon = self._latest_ns - self._window_ns
        while self._heap and self._heap[0][0] <= horizon:
            yield self._release()

    def drain(self) -> "Iterator[PacketRecord]":
        """
        Release every packet still held, oldest first.

        Yields:
            The remaining packets.

        """
        while self._heap:
            yield self._release()

    def _release(self) -> "PacketRecord":
        """
        Pop the oldest held packet, counting it if it arrived too late.

        Returns:
            The packet.

        """
        timestamp, _, packet = heapq.heappop(self._heap)
        if self._released_ns is not None and timestamp < self._released_ns:
            self.late += 1
        else:
            self._released_ns = timestamp
        return packet
