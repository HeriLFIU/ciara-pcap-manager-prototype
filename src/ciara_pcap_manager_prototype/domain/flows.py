"""
Bidirectional flow models.

These Pydantic models are the single source of truth for the platform. FastAPI
renders them into the OpenAPI 3.1 schema, and ``openapi-python-client``
regenerates the shared SDK from that schema, so the CLI and the GUI can never
drift from the backend contract.
"""

from collections import Counter
from enum import StrEnum

from pydantic import BaseModel, Field

# IANA protocol numbers worth naming. NFStream reports the raw number; the
# clients want something a human can read in a table cell.
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
        number: The IP protocol number reported by NFStream.

    Returns:
        The well-known protocol name, or ``IP-<number>`` when unmapped.

    """
    return _PROTOCOL_NAMES.get(number, f"IP-{number}")


class ExpirationReason(StrEnum):
    """
    Why NFStream closed a flow.

    NFStream encodes this as ``expiration_id``: ``0`` for the idle timeout,
    ``1`` for the active timeout and ``-1`` when an ``NFPlugin`` forced a
    custom expiration.
    """

    IDLE_TIMEOUT = "idle_timeout"
    ACTIVE_TIMEOUT = "active_timeout"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

    @classmethod
    def from_expiration_id(cls, expiration_id: int) -> "ExpirationReason":
        """
        Map an NFStream ``expiration_id`` onto a named reason.

        Args:
            expiration_id: The raw identifier taken from the NFStream flow.

        Returns:
            The matching expiration reason.

        """
        match expiration_id:
            case 0:
                return cls.IDLE_TIMEOUT
            case 1:
                return cls.ACTIVE_TIMEOUT
            case -1:
                return cls.CUSTOM
            case _:
                return cls.UNKNOWN


class Flow(BaseModel):
    """A single bidirectional flow extracted from a packet capture."""

    flow_id: int = Field(description="Per-capture index assigned by NFStream.")
    expiration_reason: ExpirationReason = Field(
        description="Why the flow was closed by the metering engine."
    )

    src_ip: str = Field(description="Source IP address of the first packet seen.")
    src_port: int = Field(
        description="Source transport port, or 0 when not applicable."
    )
    dst_ip: str = Field(description="Destination IP address of the first packet seen.")
    dst_port: int = Field(
        description="Destination transport port, or 0 when not applicable."
    )
    protocol: int = Field(description="IANA IP protocol number.")
    protocol_name: str = Field(description="Human-readable form of `protocol`.")
    ip_version: int = Field(description="IP version, 4 or 6.")
    vlan_id: int = Field(description="VLAN identifier, 0 when untagged.")

    first_seen_ms: int = Field(
        description="Unix epoch milliseconds of the first packet in either direction."
    )
    last_seen_ms: int = Field(
        description="Unix epoch milliseconds of the last packet in either direction."
    )
    duration_ms: int = Field(description="Wall-clock lifetime of the flow.")

    bidirectional_packets: int = Field(description="Total packets in both directions.")
    bidirectional_bytes: int = Field(description="Total bytes in both directions.")
    src2dst_packets: int = Field(description="Packets sent from source to destination.")
    src2dst_bytes: int = Field(description="Bytes sent from source to destination.")
    dst2src_packets: int = Field(description="Packets sent from destination to source.")
    dst2src_bytes: int = Field(description="Bytes sent from destination to source.")

    application_name: str = Field(
        description="nDPI application label, for example `DNS` or `TLS.Google`."
    )
    application_category_name: str = Field(description="nDPI application category.")
    application_is_guessed: bool = Field(
        description="True when nDPI inferred the label instead of dissecting it."
    )
    application_confidence: int = Field(description="nDPI confidence identifier.")

    requested_server_name: str | None = Field(
        default=None, description="TLS SNI or DNS query name, when one was observed."
    )
    client_fingerprint: str | None = Field(
        default=None, description="JA3/JA4-style client fingerprint, when available."
    )
    server_fingerprint: str | None = Field(
        default=None, description="Server-side handshake fingerprint, when available."
    )
    user_agent: str | None = Field(
        default=None, description="Cleartext HTTP user agent, when observed."
    )
    content_type: str | None = Field(
        default=None, description="Cleartext HTTP content type, when observed."
    )


class FlowSummary(BaseModel):
    """Aggregate statistics describing an analysed capture."""

    flow_count: int = Field(description="Number of bidirectional flows extracted.")
    packet_count: int = Field(description="Total packets across every flow.")
    byte_count: int = Field(description="Total bytes across every flow.")
    first_seen_ms: int | None = Field(
        default=None, description="Earliest packet timestamp across every flow."
    )
    last_seen_ms: int | None = Field(
        default=None, description="Latest packet timestamp across every flow."
    )
    top_applications: dict[str, int] = Field(
        default_factory=dict,
        description="Flow count per nDPI application, highest first.",
    )

    @classmethod
    def from_flows(cls, flows: list[Flow], *, top_n: int = 10) -> "FlowSummary":
        """
        Aggregate a list of flows into a summary.

        Args:
            flows: The extracted flows to summarise.
            top_n: How many applications to keep in `top_applications`.

        Returns:
            The aggregated summary.

        """
        if not flows:
            return cls(flow_count=0, packet_count=0, byte_count=0)

        counts = Counter(flow.application_name for flow in flows)
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))

        return cls(
            flow_count=len(flows),
            packet_count=sum(flow.bidirectional_packets for flow in flows),
            byte_count=sum(flow.bidirectional_bytes for flow in flows),
            first_seen_ms=min(flow.first_seen_ms for flow in flows),
            last_seen_ms=max(flow.last_seen_ms for flow in flows),
            top_applications=dict(ranked[:top_n]),
        )


class FlowPage(BaseModel):
    """One page of flows, as returned by the flows endpoint."""

    items: list[Flow] = Field(description="The flows in this page.")
    total: int = Field(description="Total flows available for the capture.")
    offset: int = Field(description="Index of the first item in this page.")
    limit: int = Field(description="Maximum page size that was applied.")
