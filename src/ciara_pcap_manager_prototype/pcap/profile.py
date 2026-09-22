"""
Profiling entry point for the extraction pipeline.

Flow extraction is the only CPU-bound stage of the platform, so it is the only
thing worth handing to a profiler. This module exists so ``make profile`` has a
single synchronous call to measure, with no server, no event loop and no worker
process in the way.

    uv run scalene -m ciara_pcap_manager_prototype.pcap.profile \
        -- samples/synthetic.pcap
"""

import argparse
import logging
from pathlib import Path

from ciara_pcap_manager_prototype.pcap.extractor import extract_flows


def main() -> None:
    """Extract flows from one capture and report what was produced."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="The capture to parse.")
    parser.add_argument(
        "--n-dissections",
        type=int,
        default=20,
        help="Packets per flow handed to nDPI. Zero disables it.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    flows = extract_flows(args.pcap, n_dissections=args.n_dissections)
    logging.getLogger(__name__).info(
        "%d flows, %d packets", len(flows), sum(f.bidirectional_packets for f in flows)
    )


if __name__ == "__main__":
    main()
