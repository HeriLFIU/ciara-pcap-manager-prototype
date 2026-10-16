"""Rich table rendering for flows, jobs and capture summaries."""

from typing import TYPE_CHECKING

from ciara_pcap_client import (
    Histogram,
    endpoint,
    format_bytes,
    format_count,
    format_duration,
    format_nanoseconds,
    format_percent,
    format_timestamp,
    int_coverage,
    protocol_label,
    ranked_counts,
    value_or,
)
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import AnalysisJob, Flow, FlowSummary
    from ciara_pcap_sdk.types import Unset

_STATUS_STYLES = {
    "pending": "yellow",
    "running": "cyan",
    "succeeded": "green",
    "failed": "bold red",
}


def status_text(status: str) -> Text:
    """
    Render a job status with a status-appropriate colour.

    Args:
        status: The job status.

    Returns:
        The styled text.

    """
    return Text(status, style=_STATUS_STYLES.get(status, "white"))


def flows_table(flows: "list[Flow]", *, title: str | None = None) -> Table:
    """
    Build a table of flow segments.

    Args:
        flows: The flows to render.
        title: Optional table title.

    Returns:
        The populated table.

    """
    table = Table(title=title, header_style="bold", expand=False)
    table.add_column("Endpoint A")
    table.add_column("Endpoint B")
    table.add_column("Proto")
    table.add_column("Seg", justify="right", style="dim")
    table.add_column("Pkts A→B", justify="right")
    table.add_column("Pkts B→A", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("INT latency", justify="right")
    table.add_column("Ended by")

    for flow in flows:
        table.add_row(
            endpoint(flow.ip_a, flow.port_a),
            endpoint(flow.ip_b, flow.port_b),
            protocol_label(flow.proto),
            str(flow.flow_segment_id),
            format_count(flow.pkts_fwd),
            format_count(flow.pkts_bwd),
            format_bytes(flow.bytes_total),
            format_duration(flow.duration),
            format_nanoseconds(flow.mean_hop_latency),
            flow.termination_reason,
        )
    return table


def _counts(summary_field: "Histogram | Unset") -> str:
    """
    Render a ``{name: count}`` summary field on one line.

    Args:
        summary_field: The SDK field.

    Returns:
        For example ``TCP 10,383 · UDP 5,075``.

    """
    pairs = ranked_counts(summary_field)
    return " · ".join(f"{name} {format_count(count)}" for name, count in pairs)


def summary_table(summary: "FlowSummary") -> Table:
    """
    Build a two-column table describing an analysed capture.

    Args:
        summary: The capture summary.

    Returns:
        The populated table.

    """
    decode = summary.decode
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Frames read", format_count(decode.frames_read))
    table.add_row("Inner packets", format_count(decode.inner_packets))
    table.add_row("INT coverage", format_percent(int_coverage(summary)))
    table.add_row("Flows", format_count(summary.flow_count))
    table.add_row("Bytes", format_bytes(summary.byte_count))
    first, last = value_or(summary.first_seen, None), value_or(summary.last_seen, None)
    if first is not None and last is not None:
        table.add_row("First packet", format_timestamp(first))
        table.add_row("Last packet", format_timestamp(last))
    table.add_row("Protocols", _counts(summary.flows_by_protocol))
    table.add_row("Ended by", _counts(summary.flows_by_termination))
    if decode.packets_out_of_order:
        table.add_row(
            "Reordered",
            f"{format_count(decode.packets_out_of_order)} out of order, "
            f"{format_count(decode.packets_late)} beyond the window",
        )
    skipped = _counts(decode.skipped)
    if skipped:
        table.add_row("Skipped frames", skipped)
    return table


def jobs_table(jobs: "list[AnalysisJob]") -> Table:
    """
    Build a table of analysis jobs.

    Args:
        jobs: The jobs to render.

    Returns:
        The populated table.

    """
    table = Table(header_style="bold")
    table.add_column("Job")
    table.add_column("Capture")
    table.add_column("Status")
    table.add_column("Size", justify="right")
    table.add_column("Flows", justify="right")
    table.add_column("Created")

    for job in jobs:
        summary = value_or(job.summary, None)
        created = value_or(job.created_at, None)
        table.add_row(
            str(job.job_id),
            job.filename,
            status_text(str(job.status)),
            format_bytes(job.size_bytes),
            "" if summary is None else format_count(summary.flow_count),
            "" if created is None else created.strftime("%Y-%m-%d %H:%M:%S"),
        )
    return table
