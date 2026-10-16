"""
CSV export of SDK flows, in the feature codebook's column order.

The CLI and the desktop client both export through this module, so a CSV
written from either is byte-identical to one written by the core package's
``ciara-pcap-inspect --csv``. ``tests/unit/test_client_export.py`` asserts that
the column list below matches the backend's `Flow` model field for field.
"""

import csv
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import TextIO

    from ciara_pcap_sdk.models import Flow

__all__ = ["FLOW_CSV_COLUMNS", "write_flows_csv"]

_FLAGS = ("syn", "ack", "fin", "rst", "psh", "urg")

#: The generator columns of PIPELINE_V2_FEATURE_CODEBOOK.md, section 6.
FLOW_CSV_COLUMNS: tuple[str, ...] = (
    "base_flow_key",
    "flow_id",
    "flow_segment_id",
    "timeframe_id",
    "proto",
    "ip_a",
    "ip_b",
    "port_a",
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
    "pkts_fwd",
    "pkts_bwd",
    "bytes_fwd",
    "bytes_bwd",
    "pkts_total",
    "bytes_total",
    "duration",
    "flow_start_time",
    "flow_end_time",
    "termination_reason",
    "first_source_file",
    "last_source_file",
    "source_file_count",
    "first_timeframe_id",
    "last_timeframe_id",
    "crosses_file_boundary",
    "fwd_pps",
    "bwd_pps",
    "total_pps",
    "total_Bps",
    "fwd_Bps",
    "bwd_Bps",
    "mean_pkt_size",
    "pkt_size_std",
    "pkt_size_min",
    "pkt_size_max",
    "mean_hop_count",
    "mean_hop_latency",
    "iat_int_count",
    "mean_iat_int_ns",
    "iat_std_int_ns",
    "iat_min_int_ns",
    "iat_max_int_ns",
    "latency_min",
    "latency_max",
    "latency_std",
    *(
        f"{flag}_{suffix}"
        for flag in _FLAGS
        for suffix in ("count_fwd", "count_bwd", "ratio_fwd", "ratio_bwd", "fraction")
    ),
    "bytes_per_pkt_fwd",
    "bytes_per_pkt_bwd",
    "bytes_per_pkt_gap",
    "small_pkt_fraction_total",
    "tiny_pkt_fraction_total",
    "syn_ack_gap",
    "fwd_share_pkts",
    "fwd_share_bytes",
    "queue_occupancy_mean",
    "queue_occupancy_std",
    "queue_occupancy_max",
    "truncated_ip_fraction",
    "truncated_udp_fraction",
)


def write_flows_csv(flows: "Iterable[Flow]", stream: "TextIO") -> int:
    """
    Write SDK flows to a text stream as CSV with a header row.

    Missing values become empty cells, the codebook's rendering of a blank.

    Args:
        flows: The flows to write.
        stream: An open text stream. Open files with ``newline=""``.

    Returns:
        The number of flow rows written.

    """
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(FLOW_CSV_COLUMNS)
    rows = 0
    for flow in flows:
        values = flow.to_dict()
        writer.writerow(
            "" if values.get(column) is None else values[column]
            for column in FLOW_CSV_COLUMNS
        )
        rows += 1
    return rows
