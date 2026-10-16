"""
Extract flows from the inner packets of an INT telemetry capture.

The pipeline is five small, pure stages, each in its own module::

    pcap.reader.iter_frames      file    -> Frame          (bytes + timestamp)
    telemetry.decoder            Frame   -> DecodedPacket  (outer, report, inner, INT)
    flows.packet                 decoded -> PacketRecord   (codebook packet columns)
    flows.reorder                records -> records        (capture-time order)
    flows.generator              records -> Flow           (codebook flow columns)

Only the *inner* packet of each report reaches the flow generator. The outer
envelope (switch to collector, UDP port 5900) is decoded so it can be checked
and counted, and then discarded.

Everything here is synchronous and CPU-bound. It is meant to run in a worker
process, never on an event loop; see :mod:`ciara_pcap_manager_prototype.pcap.runner`.
"""

import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePath

from ciara_pcap_manager_prototype.domain.flows import DecodeReport, Flow
from ciara_pcap_manager_prototype.flows.generator import (
    DEFAULT_ACTIVE_TIMEOUT_SECONDS,
    DEFAULT_IDLE_TIMEOUT_SECONDS,
    FlowGenerator,
)
from ciara_pcap_manager_prototype.flows.packet import build_packet_record
from ciara_pcap_manager_prototype.flows.reorder import (
    DEFAULT_REORDER_WINDOW_SECONDS,
    ReorderBuffer,
)
from ciara_pcap_manager_prototype.pcap.reader import (
    LINKTYPE_ETHERNET,
    CaptureFormatError,
    iter_frames,
)
from ciara_pcap_manager_prototype.telemetry.decoder import (
    DEFAULT_TELEMETRY_PORT,
    SkipReason,
    decode_frame,
)

logger = logging.getLogger(__name__)


class PcapExtractionError(RuntimeError):
    """Raised when a capture cannot be parsed into flows."""


@dataclass(frozen=True, slots=True)
class ExtractionOptions:
    """Knobs that change how a capture is decoded and segmented."""

    telemetry_port: int = DEFAULT_TELEMETRY_PORT
    idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS
    active_timeout_seconds: float = DEFAULT_ACTIVE_TIMEOUT_SECONDS
    reorder_window_seconds: float = DEFAULT_REORDER_WINDOW_SECONDS
    max_flows: int = 0


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """The flows of one capture and the decoder's account of its frames."""

    flows: list[Flow]
    report: DecodeReport


def extract_flows(
    pcap_path: Path,
    *,
    source_name: str | None = None,
    options: ExtractionOptions | None = None,
) -> ExtractionResult:
    """
    Parse a capture of INT telemetry reports into flows of the inner packets.

    Args:
        pcap_path: Path to the capture file to parse.
        source_name: Name recorded as the packets' source file. Defaults to the
            file's own name; the API passes the uploaded file's original name.
        options: Decoding and segmentation knobs. Defaults apply when omitted.

    Returns:
        Every flow, ordered by start time, and the decode report.

    Raises:
        PcapExtractionError: If the file is missing or is not a capture.

    """
    if not pcap_path.is_file():
        msg = f"Capture file does not exist: {pcap_path}"
        raise PcapExtractionError(msg)

    resolved = options or ExtractionOptions()
    source_file = source_name or pcap_path.name
    timeframe_id = PurePath(source_file).stem or None
    generator = FlowGenerator(
        idle_timeout_seconds=resolved.idle_timeout_seconds,
        active_timeout_seconds=resolved.active_timeout_seconds,
        max_flows=resolved.max_flows,
    )
    reorder = ReorderBuffer(resolved.reorder_window_seconds)
    skipped: Counter[str] = Counter()
    frames = decoded_count = with_int = with_hops = 0

    logger.info("Extracting flows from %s", pcap_path)
    try:
        for frame in iter_frames(pcap_path):
            frames += 1
            if frame.link_type != LINKTYPE_ETHERNET:
                skipped[SkipReason.UNSUPPORTED_LINK_TYPE.value] += 1
                continue
            decoded = decode_frame(frame.data, telemetry_port=resolved.telemetry_port)
            if isinstance(decoded, SkipReason):
                skipped[decoded.value] += 1
                continue
            decoded_count += 1
            if decoded.int_telemetry is not None:
                with_int += 1
                with_hops += bool(decoded.int_telemetry.hops)
            record = build_packet_record(
                frame, decoded, source_file=source_file, timeframe_id=timeframe_id
            )
            generator.add_all(reorder.push(record))
    except CaptureFormatError as exc:
        raise PcapExtractionError(str(exc)) from exc

    generator.add_all(reorder.drain())
    flows = generator.finish()
    report = DecodeReport(
        frames_read=frames,
        inner_packets=decoded_count,
        packets_with_int=with_int,
        packets_with_int_hops=with_hops,
        packets_out_of_order=reorder.out_of_order,
        packets_late=reorder.late,
        packets_over_flow_cap=generator.packets_over_cap,
        skipped=dict(skipped.most_common()),
    )
    logger.info(
        "Extracted %d flows from %d of %d frames in %s",
        len(flows),
        decoded_count,
        frames,
        pcap_path,
    )
    return ExtractionResult(flows=flows, report=report)
