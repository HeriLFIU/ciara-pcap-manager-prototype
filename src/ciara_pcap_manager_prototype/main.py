"""
Offline command line for the core package: ``ciara-pcap-inspect``.

It runs the extraction pipeline in-process, with no backend, which makes it
the quickest way to look inside a capture while developing:

    uv run ciara-pcap-inspect samples/student_sample_50000.pcap
    uv run ciara-pcap-inspect samples/student_sample_50000.pcap --inspect 2
    uv run ciara-pcap-inspect samples/student_sample_50000.pcap --csv flows.csv

Without arguments it parses the bundled synthetic sample, which is also what
the profiler measures (``make profile``).
"""

import argparse
import logging
import sys
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING

from ciara_pcap_manager_prototype.flows.export import write_flows_csv
from ciara_pcap_manager_prototype.pcap.extractor import (
    ExtractionOptions,
    PcapExtractionError,
    extract_flows,
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
from ciara_pcap_manager_prototype.telemetry.describe import describe_packet

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

_SAMPLE = Path("samples/synthetic.pcap")


def _default_capture() -> Path | None:
    """
    Locate the bundled synthetic sample.

    Returns:
        The sample's path, from the working directory or the repository root,
        or None when neither has it.

    """
    if _SAMPLE.is_file():
        return _SAMPLE
    candidate = Path(__file__).resolve().parents[2] / _SAMPLE
    return candidate if candidate.is_file() else None


def build_parser() -> argparse.ArgumentParser:
    """
    Construct the command line argument parser.

    Returns:
        The configured parser.

    """
    parser = argparse.ArgumentParser(
        prog="ciara-pcap-inspect",
        description="Decode INT telemetry reports and build flows of the inner "
        "packets, offline.",
    )
    parser.add_argument(
        "pcap",
        type=Path,
        nargs="?",
        default=_default_capture(),
        help="Capture file (defaults to samples/synthetic.pcap).",
    )
    parser.add_argument(
        "--inspect",
        type=int,
        default=0,
        metavar="N",
        help="Print the first N frames layer by layer instead of building flows.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        metavar="PATH",
        help="Write the flows to PATH as CSV, in codebook column order.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_TELEMETRY_PORT,
        help="Outer UDP destination port of the telemetry reports.",
    )
    return parser


def _write(line: str = "") -> None:
    """
    Write one line of program output to standard output.

    Args:
        line: The text to write.

    """
    sys.stdout.write(f"{line}\n")


def _inspect(capture: Path, count: int, port: int) -> None:
    """
    Print the first frames of a capture, decoded layer by layer.

    Args:
        capture: The capture to read.
        count: How many frames to print.
        port: Outer UDP destination port of the telemetry reports.

    """
    for frame in islice(iter_frames(capture), count):
        _write(
            f"frame {frame.index}  t={frame.timestamp_ns / 1e9:.9f}  "
            f"{len(frame.data)} bytes captured"
        )
        if frame.link_type != LINKTYPE_ETHERNET:
            _write(f"  skipped: {SkipReason.UNSUPPORTED_LINK_TYPE}")
            continue
        decoded = decode_frame(frame.data, telemetry_port=port)
        if isinstance(decoded, SkipReason):
            _write(f"  skipped: {decoded}")
            continue
        for line in describe_packet(decoded):
            _write(line)
        _write()


def _summarise(capture: Path, port: int, csv_path: Path | None) -> None:
    """
    Build the flows of a capture and print what was found.

    Args:
        capture: The capture to read.
        port: Outer UDP destination port of the telemetry reports.
        csv_path: Where to write the flows as CSV, if anywhere.

    """
    result = extract_flows(capture, options=ExtractionOptions(telemetry_port=port))
    report = result.report
    _write(f"{capture.name}")
    _write(f"  frames read            {report.frames_read}")
    _write(f"  inner packets decoded  {report.inner_packets}")
    _write(f"  packets with INT       {report.packets_with_int}")
    _write(f"  out of order           {report.packets_out_of_order}")
    _write(f"  late beyond window     {report.packets_late}")
    for reason, count in report.skipped.items():
        _write(f"  skipped frames         {count} ({reason})")
    _write(f"  flows                  {len(result.flows)}")

    if csv_path is not None:
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            rows = write_flows_csv(result.flows, handle)
        _write(f"  wrote {rows} flows to {csv_path}")


def main(argv: "Sequence[str] | None" = None) -> int:
    """
    Run the offline command line.

    Args:
        argv: Arguments to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        The process exit code: 0 on success, 1 when the capture is unusable.

    """
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    capture: Path | None = args.pcap
    if capture is None or not capture.is_file():
        logger.error("No capture file found: %s", capture)
        return 1

    try:
        if args.inspect > 0:
            _inspect(capture, args.inspect, args.port)
        else:
            _summarise(capture, args.port, args.csv)
    except (PcapExtractionError, CaptureFormatError, OSError) as exc:
        logger.error("%s", exc)  # noqa: TRY400 - the message is the whole story
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
