"""
Write flows as CSV in the codebook's generator export order.

Missing values are written as empty cells, which is how the codebook renders
``None``/blank. Every other value is written with Python's ``str``.
"""

import csv
from typing import TYPE_CHECKING

from ciara_pcap_manager_prototype.domain.flows import FLOW_EXPORT_COLUMNS

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import TextIO

    from ciara_pcap_manager_prototype.domain.flows import Flow


def write_flows_csv(flows: "Iterable[Flow]", stream: "TextIO") -> int:
    """
    Write flows to a text stream as CSV with a header row.

    Args:
        flows: The flows to write.
        stream: An open text stream. Open files with ``newline=""``.

    Returns:
        The number of flow rows written.

    """
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(FLOW_EXPORT_COLUMNS)
    rows = 0
    for flow in flows:
        values = flow.model_dump(mode="json")
        writer.writerow(
            "" if values[column] is None else values[column]
            for column in FLOW_EXPORT_COLUMNS
        )
        rows += 1
    return rows
