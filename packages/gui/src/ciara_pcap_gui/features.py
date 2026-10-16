"""
How the flow detail panel groups and formats the codebook features.

The groups follow the sections of the feature codebook. Every column of
`ciara_pcap_client.FLOW_CSV_COLUMNS` belongs to exactly one group; a unit test
holds that invariant, so adding a codebook column without placing it here
fails the build instead of silently hiding the column.
"""

from collections.abc import Mapping
from datetime import UTC, datetime

from ciara_pcap_client import format_count

_FLAGS = ("syn", "ack", "fin", "rst", "psh", "urg")

#: ``(group title, columns)`` in display order.
FEATURE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Identity",
        ("base_flow_key", "flow_id", "flow_segment_id", "timeframe_id", "proto"),
    ),
    (
        "Orientation",
        (
            "ip_a",
            "port_a",
            "ip_b",
            "port_b",
            "first_observed_src_ip",
            "first_observed_dst_ip",
            "first_observed_src_port",
            "first_observed_dst_port",
            "first_packet_syn",
            "first_packet_ack",
            "first_packet_was_syn",
            "first_packet_was_syn_ack",
            "first_packet_direction",
            "flow_initiator",
            "initiator_confidence",
        ),
    ),
    (
        "Counts and lifecycle",
        (
            "pkts_fwd",
            "pkts_bwd",
            "pkts_total",
            "bytes_fwd",
            "bytes_bwd",
            "bytes_total",
            "duration",
            "flow_start_time",
            "flow_end_time",
            "termination_reason",
        ),
    ),
    (
        "Provenance",
        (
            "first_source_file",
            "last_source_file",
            "source_file_count",
            "first_timeframe_id",
            "last_timeframe_id",
            "crosses_file_boundary",
        ),
    ),
    ("Rates", ("fwd_pps", "bwd_pps", "total_pps", "fwd_Bps", "bwd_Bps", "total_Bps")),
    ("Packet sizes", ("mean_pkt_size", "pkt_size_std", "pkt_size_min", "pkt_size_max")),
    (
        "INT telemetry",
        (
            "mean_hop_count",
            "mean_hop_latency",
            "latency_min",
            "latency_max",
            "latency_std",
            "iat_int_count",
            "mean_iat_int_ns",
            "iat_std_int_ns",
            "iat_min_int_ns",
            "iat_max_int_ns",
            "queue_occupancy_mean",
            "queue_occupancy_std",
            "queue_occupancy_max",
        ),
    ),
    (
        "TCP flags",
        tuple(
            f"{flag}_{suffix}"
            for flag in _FLAGS
            for suffix in (
                "count_fwd",
                "count_bwd",
                "ratio_fwd",
                "ratio_bwd",
                "fraction",
            )
        ),
    ),
    (
        "Directionality and quality",
        (
            "bytes_per_pkt_fwd",
            "bytes_per_pkt_bwd",
            "bytes_per_pkt_gap",
            "fwd_share_pkts",
            "fwd_share_bytes",
            "small_pkt_fraction_total",
            "tiny_pkt_fraction_total",
            "syn_ack_gap",
            "truncated_ip_fraction",
            "truncated_udp_fraction",
        ),
    ),
)

_TIMESTAMPS = frozenset({"flow_start_time", "flow_end_time"})
_LARGE_FLOAT = 1e6
#: Integers that are identifiers, not quantities: no thousands separators.
_PLAIN_INTEGERS = frozenset(
    {
        "proto",
        "port_a",
        "port_b",
        "first_observed_src_port",
        "first_observed_dst_port",
        "flow_segment_id",
    }
)


def format_feature(column: str, value: object) -> str:
    """
    Render one feature value for the detail panel.

    The exact value is always available too: the panel puts ``str(value)`` in
    the tooltip, which is what the CSV export writes.

    Args:
        column: The codebook column name.
        value: The value from the flow's JSON form.

    Returns:
        A readable rendering, with an em dash for a blank.

    """
    if value is None:
        return "—"
    if column in _TIMESTAMPS and isinstance(value, float):
        moment = datetime.fromtimestamp(value, tz=UTC)
        return moment.strftime("%Y-%m-%d %H:%M:%S.%f UTC")
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        return str(value) if column in _PLAIN_INTEGERS else format_count(value)
    if isinstance(value, float):
        return f"{value:,.1f}" if abs(value) >= _LARGE_FLOAT else f"{value:.6g}"
    return str(value)


def feature_rows(
    values: Mapping[str, object],
) -> list[tuple[str, list[tuple[str, object]]]]:
    """
    Arrange a flow's values into the detail panel's groups.

    Args:
        values: The flow's JSON form, keyed by codebook column.

    Returns:
        ``(group title, [(column, value), ...])`` in display order.

    """
    return [
        (title, [(column, values.get(column)) for column in columns])
        for title, columns in FEATURE_GROUPS
    ]
