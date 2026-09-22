"""Application entry point for profiling and testing of the core package."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ciara_pcap_manager_prototype.pcap.extractor import (
    PcapExtractionError,
    extract_flows,
)

# Core is for PCAP parsing and management.
# See packages/ for the backend and frontend implementations.

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """
    Construct the command line argument parser.

    Returns:
        Configured ArgumentParser instance.

    """
    default_pcap = Path("samples/synthetic.pcap")
    if not default_pcap.is_file():
        candidate = (
            Path(__file__).resolve().parent.parent.parent / "samples" / "synthetic.pcap"
        )
        if candidate.is_file():
            default_pcap = candidate

    parser = argparse.ArgumentParser(
        description="CIARA PCAP Prototype entry point and flow extractor."
    )
    parser.add_argument(
        "pcap",
        type=Path,
        nargs="?",
        default=default_pcap if default_pcap.is_file() else None,
        help="Path to capture file (defaults to samples/synthetic.pcap).",
    )
    parser.add_argument(
        "--n-dissections",
        type=int,
        default=20,
        help="Packets per flow handed to nDPI (0 disables application identification).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """
    Execute the primary entry point for ciara_pcap_manager_prototype.

    When invoked without arguments, it defaults to flow extraction against
    the bundled synthetic PCAP sample (used by the profiler in CI).

    Args:
        argv: Optional command-line argument list. If None, sys.argv[1:] is used.

    Returns:
        Process exit code (0 on success).

    """
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    capture_path: Path | None = args.pcap
    if capture_path is None or not capture_path.is_file():
        logger.info(
            "Initializing ciara_pcap_manager_prototype (no capture file specified)..."
        )
        return 0

    logger.info("Extracting flows from %s...", capture_path)
    try:
        flows = extract_flows(
            capture_path,
            n_dissections=args.n_dissections,
        )
        logger.info(
            "Extracted %d flows, %d packets.",
            len(flows),
            sum(f.bidirectional_packets for f in flows),
        )
    except (PcapExtractionError, OSError, ValueError) as exc:
        logger.warning("Flow extraction failed: %s", exc)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
