"""
NFStream-backed extraction of bidirectional flows from an offline capture.

Everything in this module is synchronous and CPU-bound by design. It is meant
to be called from a worker process, never from an event loop; see
:mod:`ciara_pcap_manager_prototype.pcap.runner`.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ciara_pcap_manager_prototype.domain.flows import (
    ExpirationReason,
    Flow,
    protocol_name,
)
from ciara_pcap_manager_prototype.pcap.compat import ensure_capture_backend

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

#: NFStream reports "no value" as an empty string rather than ``None``.
_EMPTY: Final = ""

#: Stand-in label when nDPI dissection was switched off.
_UNKNOWN_APPLICATION: Final = "Unknown"


class PcapExtractionError(RuntimeError):
    """Raised when a capture cannot be parsed into flows."""


def _optional(value: object) -> str | None:
    """
    Normalise an NFStream string field into an optional value.

    Args:
        value: The raw attribute read from the NFStream flow.

    Returns:
        The stripped string, or None when NFStream reported no value.

    """
    if not isinstance(value, str) or value == _EMPTY:
        return None
    return value


def _to_flow(raw: Any) -> Flow:  # noqa: ANN401 - NFStream's NFlow is untyped
    """
    Convert one NFStream ``NFlow`` into the platform's `Flow` model.

    The application fields are read defensively: with ``n_dissections=0``
    NFStream omits the entire nDPI attribute group from the flow object rather
    than leaving it empty, so a direct attribute access would raise.

    Args:
        raw: An NFStream flow object.

    Returns:
        The equivalent domain model.

    """
    protocol = int(raw.protocol)
    return Flow(
        flow_id=int(raw.id),
        expiration_reason=ExpirationReason.from_expiration_id(int(raw.expiration_id)),
        src_ip=str(raw.src_ip),
        src_port=int(raw.src_port),
        dst_ip=str(raw.dst_ip),
        dst_port=int(raw.dst_port),
        protocol=protocol,
        protocol_name=protocol_name(protocol),
        ip_version=int(raw.ip_version),
        vlan_id=int(raw.vlan_id),
        first_seen_ms=int(raw.bidirectional_first_seen_ms),
        last_seen_ms=int(raw.bidirectional_last_seen_ms),
        duration_ms=int(raw.bidirectional_duration_ms),
        bidirectional_packets=int(raw.bidirectional_packets),
        bidirectional_bytes=int(raw.bidirectional_bytes),
        src2dst_packets=int(raw.src2dst_packets),
        src2dst_bytes=int(raw.src2dst_bytes),
        dst2src_packets=int(raw.dst2src_packets),
        dst2src_bytes=int(raw.dst2src_bytes),
        application_name=str(getattr(raw, "application_name", _UNKNOWN_APPLICATION)),
        application_category_name=str(
            getattr(raw, "application_category_name", _UNKNOWN_APPLICATION)
        ),
        application_is_guessed=bool(getattr(raw, "application_is_guessed", False)),
        application_confidence=int(getattr(raw, "application_confidence", 0)),
        requested_server_name=_optional(getattr(raw, "requested_server_name", _EMPTY)),
        client_fingerprint=_optional(getattr(raw, "client_fingerprint", _EMPTY)),
        server_fingerprint=_optional(getattr(raw, "server_fingerprint", _EMPTY)),
        user_agent=_optional(getattr(raw, "user_agent", _EMPTY)),
        content_type=_optional(getattr(raw, "content_type", _EMPTY)),
    )


def extract_flows(
    pcap_path: Path,
    *,
    n_dissections: int = 20,
    max_flows: int = 0,
) -> list[Flow]:
    """
    Parse an offline capture into bidirectional flows.

    This blocks for the whole duration of the parse and spawns NFStream's own
    metering processes, so it must run in a worker process rather than on an
    event loop.

    Args:
        pcap_path: Path to the capture file to parse.
        n_dissections: Packets per flow handed to nDPI for protocol dissection.
            Zero disables application identification entirely.
        max_flows: Stop after this many flows. Zero means no limit.

    Returns:
        Every flow extracted from the capture, in NFStream's emission order.

    Raises:
        PcapExtractionError: If the file is missing or NFStream rejects it.

    """
    if not pcap_path.is_file():
        msg = f"Capture file does not exist: {pcap_path}"
        raise PcapExtractionError(msg)

    ensure_capture_backend()

    # Imported lazily: the engine loads a large native library, and the DLL
    # search path above must already be in place on Windows.
    from nfstream import (  # noqa: PLC0415  # pyright: ignore[reportMissingTypeStubs]
        NFStreamer,
    )

    logger.info("Extracting flows from %s", pcap_path)
    try:
        streamer = NFStreamer(
            source=str(pcap_path),
            decode_tunnels=True,
            n_dissections=n_dissections,
            statistical_analysis=False,
            splt_analysis=0,
            max_nflows=max_flows,
        )
        flows: Iterator[Any] = iter(streamer)
        extracted = [_to_flow(raw) for raw in flows]
    except Exception as exc:
        msg = f"NFStream failed to parse {pcap_path.name}: {exc}"
        raise PcapExtractionError(msg) from exc

    logger.info("Extracted %d flows from %s", len(extracted), pcap_path)
    return extracted
