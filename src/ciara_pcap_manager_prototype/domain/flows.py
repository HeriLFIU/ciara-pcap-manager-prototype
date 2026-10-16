"""
Bidirectional flow models.

These Pydantic models are the single source of truth for the platform. FastAPI
renders them into the OpenAPI 3.1 schema, and ``openapi-python-client``
regenerates the shared SDK from that schema, so the CLI and the GUI can never
drift from the backend contract.

`Flow` carries exactly the generator columns of the PIPELINE_V2 feature
codebook (``docs/reference/feature_codebook.md``), declared in the codebook's
export order and under the codebook's names. Do not rename or reorder a field
without changing the codebook: the CSV export writes the fields in this order.
"""

from enum import StrEnum

from pydantic import BaseModel, Field

# IANA protocol numbers worth naming in a table cell.
_PROTOCOL_NAMES: dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    132: "SCTP",
}


def protocol_name(number: int) -> str:
    """
    Translate an IANA protocol number into a display name.

    Args:
        number: The IP protocol number.

    Returns:
        The well-known protocol name, or ``IP-<number>`` when unmapped.

    """
    return _PROTOCOL_NAMES.get(number, f"IP-{number}")


class TerminationReason(StrEnum):
    """Why a flow segment was closed."""

    INACTIVE_TIMEOUT = "inactive_timeout"
    ACTIVE_TIMEOUT = "active_timeout"
    TCP_RST = "tcp_rst"
    TCP_FIN_BOTH = "tcp_fin_both"
    END_OF_INPUT = "end_of_input"


class InitiatorConfidence(StrEnum):
    """How much the first packet says about who opened the flow."""

    TCP_SYN_NOACK_OBSERVED = "tcp_syn_noack_observed"
    OBSERVED_FIRST_PACKET = "observed_first_packet"
    UNKNOWN = "unknown"


#: The only orientation the canonical export produces: A/B come from the
#: first packet, so the first packet is forward by construction.
FIRST_PACKET_DIRECTION = "fwd"

#: The canonical export's constant initiator label.
FLOW_INITIATOR = "observed_first_packet_src"


class Flow(BaseModel):
    """One flow segment built from the inner packets of INT telemetry reports."""

    # -- Identity -----------------------------------------------------------
    base_flow_key: str = Field(
        description="Direction-independent identity: "
        "`proto|ip_low|ip_high|port_low|port_high`."
    )
    flow_id: str = Field(description="Segment identifier: `base_flow_key|segment`.")
    flow_segment_id: int = Field(
        ge=0, description="Segment counter per `base_flow_key`, starting at 0."
    )
    timeframe_id: str | None = Field(
        description="Timeframe of the segment's first packet (the capture's file "
        "name without its extension)."
    )
    proto: int = Field(description="IP protocol number: 6 for TCP, 17 for UDP.")

    # -- Orientation ----------------------------------------------------------
    ip_a: str = Field(description="Source address of the segment's first packet.")
    ip_b: str = Field(description="Destination address of the segment's first packet.")
    port_a: int = Field(description="Port paired with `ip_a`.")
    port_b: int = Field(description="Port paired with `ip_b`.")
    first_observed_src_ip: str = Field(description="Equals `ip_a`.")
    first_observed_dst_ip: str = Field(description="Equals `ip_b`.")
    first_observed_src_port: int = Field(description="Equals `port_a`.")
    first_observed_dst_port: int = Field(description="Equals `port_b`.")
    first_packet_syn: int = Field(
        ge=0, le=1, description="1 if the first packet had SYN."
    )
    first_packet_ack: int = Field(
        ge=0, le=1, description="1 if the first packet had ACK."
    )
    first_packet_was_syn: int = Field(
        ge=0, le=1, description="1 for TCP with SYN=1 and ACK=0 on the first packet."
    )
    first_packet_was_syn_ack: int = Field(
        ge=0, le=1, description="1 for TCP with SYN=1 and ACK=1 on the first packet."
    )
    first_packet_direction: str = Field(
        description="Always `fwd`: A/B are taken from the first packet."
    )
    flow_initiator: str = Field(description="Always `observed_first_packet_src`.")
    initiator_confidence: InitiatorConfidence = Field(
        description="`tcp_syn_noack_observed` when the first packet was a bare "
        "SYN, otherwise `observed_first_packet`."
    )

    # -- Counts and lifecycle -------------------------------------------------
    pkts_fwd: int = Field(ge=0, description="Packets from A to B.")
    pkts_bwd: int = Field(ge=0, description="Packets from B to A.")
    bytes_fwd: int = Field(ge=0, description="Inner IPv4 Total Length summed, A to B.")
    bytes_bwd: int = Field(ge=0, description="Inner IPv4 Total Length summed, B to A.")
    pkts_total: int = Field(ge=0, description="`pkts_fwd + pkts_bwd`.")
    bytes_total: int = Field(ge=0, description="`bytes_fwd + bytes_bwd`.")
    duration: float = Field(
        ge=0.0, description="Seconds from the first to the last packet."
    )
    flow_start_time: float = Field(description="Epoch seconds of the first packet.")
    flow_end_time: float = Field(description="Epoch seconds of the last packet.")
    termination_reason: TerminationReason = Field(
        description="Why the segment was closed."
    )

    # -- Provenance -----------------------------------------------------------
    first_source_file: str = Field(description="First capture file of the segment.")
    last_source_file: str = Field(description="Last capture file of the segment.")
    source_file_count: int = Field(
        ge=1, description="1 plus the number of source-file changes in the segment."
    )
    first_timeframe_id: str | None = Field(description="First timeframe observed.")
    last_timeframe_id: str | None = Field(description="Last timeframe observed.")
    crosses_file_boundary: int = Field(
        ge=0, le=1, description="1 if the segment took packets from several files."
    )

    # -- Rates (0.0 when duration is 0) --------------------------------------
    fwd_pps: float | None = Field(description="`pkts_fwd / duration`.")
    bwd_pps: float | None = Field(description="`pkts_bwd / duration`.")
    total_pps: float | None = Field(description="`pkts_total / duration`.")
    total_Bps: float | None = Field(  # noqa: N815 - codebook column name
        description="`bytes_total / duration`."
    )
    fwd_Bps: float | None = Field(  # noqa: N815 - codebook column name
        description="`bytes_fwd / duration`."
    )
    bwd_Bps: float | None = Field(  # noqa: N815 - codebook column name
        description="`bytes_bwd / duration`."
    )

    # -- Packet sizes (inner IPv4 Total Length) -------------------------------
    mean_pkt_size: float | None = Field(description="Mean packet size in bytes.")
    pkt_size_std: float | None = Field(description="Population std dev of sizes.")
    pkt_size_min: int | None = Field(description="Smallest packet size in bytes.")
    pkt_size_max: int | None = Field(description="Largest packet size in bytes.")

    # -- INT hops, inter-arrival and latency ----------------------------------
    mean_hop_count: float | None = Field(
        description="Mean INT hops per packet, over packets carrying INT hops."
    )
    mean_hop_latency: float | None = Field(
        description="Mean per-packet INT latency (ns, summed over hops)."
    )
    iat_int_count: int = Field(
        ge=0, description="INT-timestamp inter-arrival observations in the segment."
    )
    mean_iat_int_ns: float = Field(
        description="Mean INT inter-arrival (ns); 0.0 if none."
    )
    iat_std_int_ns: float = Field(
        description="Population std dev of INT inter-arrival (ns); 0.0 if <= 1."
    )
    iat_min_int_ns: float = Field(
        description="Smallest INT inter-arrival (ns); 0.0 if none."
    )
    iat_max_int_ns: float = Field(
        description="Largest INT inter-arrival (ns); 0.0 if none."
    )
    latency_min: int | None = Field(description="Smallest per-packet INT latency (ns).")
    latency_max: int | None = Field(description="Largest per-packet INT latency (ns).")
    latency_std: float | None = Field(
        description="Population std dev of per-packet INT latency (ns)."
    )

    # -- TCP flags: counts per direction, ratios per direction, fraction ------
    syn_count_fwd: int = Field(ge=0, description="SYN packets, A to B.")
    syn_count_bwd: int = Field(ge=0, description="SYN packets, B to A.")
    syn_ratio_fwd: float = Field(ge=0, le=1, description="`syn_count_fwd / pkts_fwd`.")
    syn_ratio_bwd: float = Field(ge=0, le=1, description="`syn_count_bwd / pkts_bwd`.")
    syn_fraction: float = Field(ge=0, le=1, description="SYN packets / `pkts_total`.")
    ack_count_fwd: int = Field(ge=0, description="ACK packets, A to B.")
    ack_count_bwd: int = Field(ge=0, description="ACK packets, B to A.")
    ack_ratio_fwd: float = Field(ge=0, le=1, description="`ack_count_fwd / pkts_fwd`.")
    ack_ratio_bwd: float = Field(ge=0, le=1, description="`ack_count_bwd / pkts_bwd`.")
    ack_fraction: float = Field(ge=0, le=1, description="ACK packets / `pkts_total`.")
    fin_count_fwd: int = Field(ge=0, description="FIN packets, A to B.")
    fin_count_bwd: int = Field(ge=0, description="FIN packets, B to A.")
    fin_ratio_fwd: float = Field(ge=0, le=1, description="`fin_count_fwd / pkts_fwd`.")
    fin_ratio_bwd: float = Field(ge=0, le=1, description="`fin_count_bwd / pkts_bwd`.")
    fin_fraction: float = Field(ge=0, le=1, description="FIN packets / `pkts_total`.")
    rst_count_fwd: int = Field(ge=0, description="RST packets, A to B.")
    rst_count_bwd: int = Field(ge=0, description="RST packets, B to A.")
    rst_ratio_fwd: float = Field(ge=0, le=1, description="`rst_count_fwd / pkts_fwd`.")
    rst_ratio_bwd: float = Field(ge=0, le=1, description="`rst_count_bwd / pkts_bwd`.")
    rst_fraction: float = Field(ge=0, le=1, description="RST packets / `pkts_total`.")
    psh_count_fwd: int = Field(ge=0, description="PSH packets, A to B.")
    psh_count_bwd: int = Field(ge=0, description="PSH packets, B to A.")
    psh_ratio_fwd: float = Field(ge=0, le=1, description="`psh_count_fwd / pkts_fwd`.")
    psh_ratio_bwd: float = Field(ge=0, le=1, description="`psh_count_bwd / pkts_bwd`.")
    psh_fraction: float = Field(ge=0, le=1, description="PSH packets / `pkts_total`.")
    urg_count_fwd: int = Field(ge=0, description="URG packets, A to B.")
    urg_count_bwd: int = Field(ge=0, description="URG packets, B to A.")
    urg_ratio_fwd: float = Field(ge=0, le=1, description="`urg_count_fwd / pkts_fwd`.")
    urg_ratio_bwd: float = Field(ge=0, le=1, description="`urg_count_bwd / pkts_bwd`.")
    urg_fraction: float = Field(ge=0, le=1, description="URG packets / `pkts_total`.")

    # -- Directionality, quality and queue ------------------------------------
    bytes_per_pkt_fwd: float = Field(description="`bytes_fwd / pkts_fwd`, else 0.0.")
    bytes_per_pkt_bwd: float = Field(description="`bytes_bwd / pkts_bwd`, else 0.0.")
    bytes_per_pkt_gap: float = Field(
        description="`bytes_per_pkt_fwd - bytes_per_pkt_bwd`."
    )
    small_pkt_fraction_total: float = Field(
        ge=0, le=1, description="Share of packets of at most 100 bytes."
    )
    tiny_pkt_fraction_total: float = Field(
        ge=0, le=1, description="Share of packets of at most 40 bytes."
    )
    syn_ack_gap: int = Field(description="`syn_count_fwd - ack_count_bwd`.")
    fwd_share_pkts: float | None = Field(description="`pkts_fwd / pkts_total`.")
    fwd_share_bytes: float | None = Field(description="`bytes_fwd / bytes_total`.")
    queue_occupancy_mean: float | None = Field(
        description="Mean INT queue occupancy over every hop observation."
    )
    queue_occupancy_std: float | None = Field(
        description="Population std dev of INT queue occupancy."
    )
    queue_occupancy_max: int | None = Field(description="Largest INT queue occupancy.")
    truncated_ip_fraction: float | None = Field(
        description="Share of packets whose captured inner IPv4 bytes differ from "
        "its declared Total Length."
    )
    truncated_udp_fraction: float | None = Field(
        description="Share of packets whose captured inner UDP bytes differ from "
        "its declared Length."
    )


#: Column order of the generator CSV export: the codebook's section 6 list.
FLOW_EXPORT_COLUMNS: tuple[str, ...] = tuple(Flow.model_fields)


class DecodeReport(BaseModel):
    """What the decoder made of every frame in a capture."""

    frames_read: int = Field(ge=0, description="Frames read from the capture file.")
    inner_packets: int = Field(
        ge=0, description="Frames whose inner TCP/UDP packet was decoded."
    )
    packets_with_int: int = Field(
        ge=0, description="Decoded packets that also carried an INT header."
    )
    packets_with_int_hops: int = Field(
        ge=0, description="Decoded packets with at least one INT hop decoded."
    )
    packets_out_of_order: int = Field(
        ge=0,
        description="Decoded packets read with a timestamp earlier than one "
        "already read; the reorder buffer puts them back in time order.",
    )
    packets_late: int = Field(
        ge=0,
        description="Out-of-order packets that lagged by more than the reorder "
        "window and were processed out of time order.",
    )
    packets_over_flow_cap: int = Field(
        ge=0,
        description="Decoded packets dropped because they would have opened a "
        "flow beyond the configured cap.",
    )
    skipped: dict[str, int] = Field(
        default_factory=dict,
        description="Frames that yielded no inner packet, per reason.",
    )


class FlowSummary(BaseModel):
    """Aggregate statistics describing an analysed capture."""

    flow_count: int = Field(description="Number of flow segments.")
    packet_count: int = Field(description="Inner packets across every flow.")
    byte_count: int = Field(description="Inner bytes across every flow.")
    first_seen: float | None = Field(
        default=None, description="Epoch seconds of the earliest flow start."
    )
    last_seen: float | None = Field(
        default=None, description="Epoch seconds of the latest flow end."
    )
    flows_by_protocol: dict[str, int] = Field(
        default_factory=dict, description="Flow count per protocol name."
    )
    flows_by_termination: dict[str, int] = Field(
        default_factory=dict, description="Flow count per termination reason."
    )
    decode: DecodeReport = Field(description="How the capture's frames were decoded.")

    @classmethod
    def from_flows(cls, flows: list[Flow], decode: DecodeReport) -> "FlowSummary":
        """
        Aggregate a list of flows into a summary.

        Args:
            flows: The extracted flows to summarise.
            decode: The decoder's report for the same capture.

        Returns:
            The aggregated summary.

        """
        by_protocol: dict[str, int] = {}
        by_termination: dict[str, int] = {}
        for flow in flows:
            name = protocol_name(flow.proto)
            by_protocol[name] = by_protocol.get(name, 0) + 1
            reason = flow.termination_reason.value
            by_termination[reason] = by_termination.get(reason, 0) + 1

        return cls(
            flow_count=len(flows),
            packet_count=sum(flow.pkts_total for flow in flows),
            byte_count=sum(flow.bytes_total for flow in flows),
            first_seen=min((flow.flow_start_time for flow in flows), default=None),
            last_seen=max((flow.flow_end_time for flow in flows), default=None),
            flows_by_protocol=dict(sorted(by_protocol.items(), key=_by_count)),
            flows_by_termination=dict(sorted(by_termination.items(), key=_by_count)),
            decode=decode,
        )


def _by_count(item: tuple[str, int]) -> tuple[int, str]:
    """
    Sort key placing the largest count first and breaking ties by name.

    Args:
        item: A ``(name, count)`` pair.

    Returns:
        The sort key.

    """
    return (-item[1], item[0])


class FlowPage(BaseModel):
    """One page of flows, as returned by the flows endpoint."""

    items: list[Flow] = Field(description="The flows in this page.")
    total: int = Field(description="Total flows available for the capture.")
    offset: int = Field(description="Index of the first item in this page.")
    limit: int = Field(description="Maximum page size that was applied.")
