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
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    result = extract_flows(args.pcap)
    logging.getLogger(__name__).info(
        "%d flows, %d packets",
        len(result.flows),
        sum(flow.pkts_total for flow in result.flows),
    )


if __name__ == "__main__":
    main()
