"""Rich table rendering for flows and jobs. Value formatting is shared."""

from typing import TYPE_CHECKING

from ciara_pcap_client import (
    application_label,
    format_bytes,
    format_timestamp,
    is_set,
    ranked_applications,
    value_or,
)
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from ciara_pcap_sdk.models import AnalysisJob, Flow, FlowSummary

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
    Build a table of bidirectional flows.

    Args:
        flows: The flows to render.
        title: Optional table title.

    Returns:
        The populated table.

    """
    table = Table(title=title, header_style="bold", expand=False)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Proto")
    table.add_column("Application")
    table.add_column("Pkts", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("Server name")

    for flow in flows:
        table.add_row(
            str(flow.flow_id),
            f"{flow.src_ip}:{flow.src_port}",
            f"{flow.dst_ip}:{flow.dst_port}",
            flow.protocol_name,
            application_label(flow),
            str(flow.bidirectional_packets),
            format_bytes(flow.bidirectional_bytes),
            f"{flow.duration_ms} ms",
            value_or(flow.requested_server_name, ""),
        )
    return table


def summary_table(summary: "FlowSummary") -> Table:
    """
    Build a two-column table describing an analysed capture.

    Args:
        summary: The capture summary.

    Returns:
        The populated table.

    """
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Flows", str(summary.flow_count))
    table.add_row("Packets", str(summary.packet_count))
    table.add_row("Bytes", format_bytes(summary.byte_count))
    if is_set(summary.first_seen_ms) and is_set(summary.last_seen_ms):
        table.add_row(
            "First packet", format_timestamp(value_or(summary.first_seen_ms, 0))
        )
        table.add_row(
            "Last packet", format_timestamp(value_or(summary.last_seen_ms, 0))
        )
    applications = ranked_applications(summary)
    if applications:
        table.add_row(
            "Top applications",
            ", ".join(f"{name} ({count})" for name, count in applications),
        )
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
            "" if summary is None else str(summary.flow_count),
            "" if created is None else created.strftime("%Y-%m-%d %H:%M:%S"),
        )
    return table
