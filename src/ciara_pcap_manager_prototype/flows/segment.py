"""
One open flow segment and the arithmetic that turns it into a `Flow`.

A segment accumulates running counters as packets arrive, so memory per flow
is constant no matter how many packets it holds. `FlowSegment.to_flow` then
applies the codebook's formulas and its rules for zero denominators
(sections 0.2 and 3).

Standard deviations are population standard deviations, computed with
Welford's online algorithm. That is the same quantity as the codebook's
``sqrt(sum_sq / n - mean^2)`` (clamped at zero) but without the catastrophic
cancellation the sum-of-squares form suffers on nanosecond-scale values.
"""

import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from ciara_pcap_manager_prototype.domain.flows import (
    FIRST_PACKET_DIRECTION,
    FLOW_INITIATOR,
    Flow,
    InitiatorConfidence,
    TerminationReason,
)

if TYPE_CHECKING:
    from ciara_pcap_manager_prototype.flows.packet import PacketRecord

#: Packets at most this many bytes count as small (codebook 3.7).
SMALL_PACKET_BYTES: Final = 100
#: Packets at most this many bytes count as tiny (codebook 3.7).
TINY_PACKET_BYTES: Final = 40

_NS_PER_SECOND: Final = 1_000_000_000
#: INT timestamps are 32-bit nanosecond counters that wrap every ~4.29 s.
_INT_TIMESTAMP_WRAP: Final = 1 << 32

_FLAGS: Final = ("syn", "ack", "fin", "rst", "psh", "urg")


@dataclass(slots=True)
class RunningStats:
    """Count, mean, population variance, minimum and maximum of a stream."""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf

    def add(self, value: float) -> None:
        """
        Fold one observation into the statistics.

        Args:
            value: The observation.

        """
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)

    @property
    def std(self) -> float:
        """
        Population standard deviation, 0.0 for fewer than two observations.

        Returns:
            The standard deviation.

        """
        if self.count < 2:  # noqa: PLR2004 - variance needs two points
            return 0.0
        return math.sqrt(max(self.m2 / self.count, 0.0))


def _ratio(numerator: float, denominator: float) -> float:
    """
    Divide, mapping a zero denominator to 0.0 (codebook 3.5 and 3.6).

    Args:
        numerator: The dividend.
        denominator: The divisor.

    Returns:
        The quotient, or 0.0 when the divisor is zero.

    """
    return numerator / denominator if denominator else 0.0


def _share(numerator: float, denominator: float) -> float | None:
    """
    Divide, mapping a zero denominator to None (codebook 3.6 shares).

    Args:
        numerator: The dividend.
        denominator: The divisor.

    Returns:
        The quotient, or None when the divisor is zero.

    """
    return numerator / denominator if denominator else None


def _rate(amount: float, duration: float) -> float:
    """
    Compute a per-second rate (codebook 3.2): 0.0 when the duration is zero.

    Args:
        amount: Packets or bytes.
        duration: Segment duration in seconds, never negative here.

    Returns:
        The rate.

    """
    return amount / duration if duration > 0 else 0.0


@dataclass(slots=True)
class FlowSegment:
    """Running state of one flow segment, oriented by its first packet."""

    base_flow_key: str
    segment_id: int
    first: "PacketRecord"
    first_ns: int = 0
    last_ns: int = 0
    pkts: list[int] = field(default_factory=lambda: [0, 0])
    bytes: list[int] = field(default_factory=lambda: [0, 0])
    small: int = 0
    tiny: int = 0
    flags: dict[str, list[int]] = field(
        default_factory=lambda: {name: [0, 0] for name in _FLAGS}
    )
    sizes: RunningStats = field(default_factory=RunningStats)
    hop_count_sum: int = 0
    hop_count_packets: int = 0
    latency: RunningStats = field(default_factory=RunningStats)
    queue: RunningStats = field(default_factory=RunningStats)
    iat: RunningStats = field(default_factory=RunningStats)
    last_int_timestamp: int | None = None
    truncated_ip: int = 0
    truncated_udp: int = 0
    last_source_file: str = ""
    source_file_count: int = 1
    last_timeframe_id: str | None = None

    def __post_init__(self) -> None:
        """Start the segment's clock and provenance at its first packet."""
        self.first_ns = self.last_ns = self.first.packet_time_ns
        self.last_source_file = self.first.source_file
        self.last_timeframe_id = self.first.timeframe_id

    def is_forward(self, packet: "PacketRecord") -> bool:
        """
        Report whether a packet travels A to B.

        Args:
            packet: A packet of this segment.

        Returns:
            True when it has the first packet's source address and port.

        """
        return (
            packet.inner_ip_src == self.first.inner_ip_src
            and packet.src_port == self.first.src_port
        )

    @property
    def fin_seen_both_ways(self) -> bool:
        """
        Report whether FIN has been seen in both directions.

        Returns:
            True once each side sent at least one FIN.

        """
        fwd, bwd = self.flags["fin"]
        return fwd > 0 and bwd > 0

    def add(self, packet: "PacketRecord") -> None:
        """
        Fold one packet into the segment.

        Args:
            packet: The packet, which must belong to this segment.

        """
        side = 0 if self.is_forward(packet) else 1
        size = packet.inner_ip_len

        self.first_ns = min(self.first_ns, packet.packet_time_ns)
        self.last_ns = max(self.last_ns, packet.packet_time_ns)
        self.pkts[side] += 1
        self.bytes[side] += size
        self.sizes.add(size)
        self.small += size <= SMALL_PACKET_BYTES
        self.tiny += size <= TINY_PACKET_BYTES

        for name in _FLAGS:
            if getattr(packet, f"tcp_flag_{name}"):
                self.flags[name][side] += 1

        if packet.int_hop_count:
            self.hop_count_sum += packet.int_hop_count
            self.hop_count_packets += 1
        if packet.int_path_latency is not None:
            self.latency.add(packet.int_path_latency)
        for occupancy in packet.int_queue_observations:
            self.queue.add(occupancy)

        timestamp = packet.int_timestamp
        if timestamp is not None:
            if self.last_int_timestamp is not None:
                # Wrap-aware: the counter is 32 bits wide.
                self.iat.add(
                    (timestamp - self.last_int_timestamp) % _INT_TIMESTAMP_WRAP
                )
            self.last_int_timestamp = timestamp

        self.truncated_ip += packet.inner_ip_truncated_vs_declared
        self.truncated_udp += packet.inner_udp_truncated_vs_declared

        if packet.source_file != self.last_source_file:
            self.source_file_count += 1
            self.last_source_file = packet.source_file
        self.last_timeframe_id = packet.timeframe_id

    def to_flow(self, reason: TerminationReason) -> Flow:
        """
        Close the segment and compute its codebook features.

        Args:
            reason: Why the segment is being closed.

        Returns:
            The finished flow.

        """
        first = self.first
        pkts_fwd, pkts_bwd = self.pkts
        bytes_fwd, bytes_bwd = self.bytes
        pkts_total = pkts_fwd + pkts_bwd
        bytes_total = bytes_fwd + bytes_bwd
        duration = (self.last_ns - self.first_ns) / _NS_PER_SECOND
        per_pkt_fwd = _ratio(bytes_fwd, pkts_fwd)
        per_pkt_bwd = _ratio(bytes_bwd, pkts_bwd)
        is_tcp = first.is_tcp
        syn, ack = first.tcp_flag_syn, first.tcp_flag_ack
        bare_syn = is_tcp and syn and not ack

        flag_columns: dict[str, int | float] = {}
        for name, (fwd, bwd) in self.flags.items():
            flag_columns[f"{name}_count_fwd"] = fwd
            flag_columns[f"{name}_count_bwd"] = bwd
            flag_columns[f"{name}_ratio_fwd"] = _ratio(fwd, pkts_fwd)
            flag_columns[f"{name}_ratio_bwd"] = _ratio(bwd, pkts_bwd)
            flag_columns[f"{name}_fraction"] = _ratio(fwd + bwd, pkts_total)

        latency, queue, iat, sizes = self.latency, self.queue, self.iat, self.sizes
        has_iat = iat.count > 0

        return Flow.model_validate(
            {
                "base_flow_key": self.base_flow_key,
                "flow_id": f"{self.base_flow_key}|{self.segment_id}",
                "flow_segment_id": self.segment_id,
                "timeframe_id": first.timeframe_id,
                "proto": first.inner_ip_proto,
                "ip_a": first.inner_ip_src,
                "ip_b": first.inner_ip_dst,
                "port_a": first.src_port,
                "port_b": first.dst_port,
                "first_observed_src_ip": first.inner_ip_src,
                "first_observed_dst_ip": first.inner_ip_dst,
                "first_observed_src_port": first.src_port,
                "first_observed_dst_port": first.dst_port,
                "first_packet_syn": int(syn),
                "first_packet_ack": int(ack),
                "first_packet_was_syn": int(bare_syn),
                "first_packet_was_syn_ack": int(is_tcp and syn and ack),
                "first_packet_direction": FIRST_PACKET_DIRECTION,
                "flow_initiator": FLOW_INITIATOR,
                "initiator_confidence": (
                    InitiatorConfidence.TCP_SYN_NOACK_OBSERVED
                    if bare_syn
                    else InitiatorConfidence.OBSERVED_FIRST_PACKET
                ),
                "pkts_fwd": pkts_fwd,
                "pkts_bwd": pkts_bwd,
                "bytes_fwd": bytes_fwd,
                "bytes_bwd": bytes_bwd,
                "pkts_total": pkts_total,
                "bytes_total": bytes_total,
                "duration": duration,
                "flow_start_time": self.first_ns / _NS_PER_SECOND,
                "flow_end_time": self.last_ns / _NS_PER_SECOND,
                "termination_reason": reason,
                "first_source_file": first.source_file,
                "last_source_file": self.last_source_file,
                "source_file_count": self.source_file_count,
                "first_timeframe_id": first.timeframe_id,
                "last_timeframe_id": self.last_timeframe_id,
                "crosses_file_boundary": int(self.source_file_count > 1),
                "fwd_pps": _rate(pkts_fwd, duration),
                "bwd_pps": _rate(pkts_bwd, duration),
                "total_pps": _rate(pkts_total, duration),
                "total_Bps": _rate(bytes_total, duration),
                "fwd_Bps": _rate(bytes_fwd, duration),
                "bwd_Bps": _rate(bytes_bwd, duration),
                "mean_pkt_size": sizes.mean if sizes.count else None,
                "pkt_size_std": sizes.std if sizes.count else None,
                "pkt_size_min": int(sizes.minimum) if sizes.count else None,
                "pkt_size_max": int(sizes.maximum) if sizes.count else None,
                "mean_hop_count": (
                    self.hop_count_sum / self.hop_count_packets
                    if self.hop_count_packets
                    else None
                ),
                "mean_hop_latency": latency.mean if latency.count else None,
                "iat_int_count": iat.count,
                "mean_iat_int_ns": iat.mean if has_iat else 0.0,
                "iat_std_int_ns": iat.std,
                "iat_min_int_ns": iat.minimum if has_iat else 0.0,
                "iat_max_int_ns": iat.maximum if has_iat else 0.0,
                "latency_min": int(latency.minimum) if latency.count else None,
                "latency_max": int(latency.maximum) if latency.count else None,
                "latency_std": latency.std if latency.count else None,
                **flag_columns,
                "bytes_per_pkt_fwd": per_pkt_fwd,
                "bytes_per_pkt_bwd": per_pkt_bwd,
                "bytes_per_pkt_gap": per_pkt_fwd - per_pkt_bwd,
                "small_pkt_fraction_total": _ratio(self.small, pkts_total),
                "tiny_pkt_fraction_total": _ratio(self.tiny, pkts_total),
                "syn_ack_gap": self.flags["syn"][0] - self.flags["ack"][1],
                "fwd_share_pkts": _share(pkts_fwd, pkts_total),
                "fwd_share_bytes": _share(bytes_fwd, bytes_total),
                "queue_occupancy_mean": queue.mean if queue.count else None,
                "queue_occupancy_std": queue.std if queue.count else None,
                "queue_occupancy_max": int(queue.maximum) if queue.count else None,
                "truncated_ip_fraction": _share(self.truncated_ip, pkts_total),
                "truncated_udp_fraction": _share(self.truncated_udp, pkts_total),
            }
        )
