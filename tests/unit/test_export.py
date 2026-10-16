"""
The CSV export must match the feature codebook, column for column.

Three lists have to agree: the codebook's section 6 (the document the team
works from), the core `Flow` model, and the clients' column list. These tests
read the codebook itself, so editing one without the others fails the build.
"""

import csv
import io
import json
import re
from pathlib import Path

from ciara_pcap_client import FLOW_CSV_COLUMNS
from ciara_pcap_client import write_flows_csv as write_sdk_csv
from ciara_pcap_sdk.models import Flow as SdkFlow

from ciara_pcap_manager_prototype.domain.flows import FLOW_EXPORT_COLUMNS
from ciara_pcap_manager_prototype.flows.export import write_flows_csv
from tests.support.factories import make_flow

CODEBOOK = (
    Path(__file__).resolve().parents[2] / "docs" / "reference" / "feature_codebook.md"
)


def codebook_columns() -> tuple[str, ...]:
    """Read the export-order list from section 6 of the codebook."""
    text = CODEBOOK.read_text(encoding="utf-8")
    section = text[text.index("## 6") :]
    match = re.search(r"`([^`]+)`", section)
    assert match is not None, "section 6 has no backticked column list"
    return tuple(column.strip() for column in match.group(1).split(","))


def test_the_flow_model_follows_the_codebook_export_order() -> None:
    assert codebook_columns() == FLOW_EXPORT_COLUMNS
    assert len(FLOW_EXPORT_COLUMNS) == 99


def test_the_client_columns_match_the_core_columns() -> None:
    assert FLOW_CSV_COLUMNS == FLOW_EXPORT_COLUMNS


def test_core_csv_writes_a_header_and_blank_cells_for_none() -> None:
    flow = make_flow(queue_occupancy_mean=None, latency_min=None)
    stream = io.StringIO()

    rows = write_flows_csv([flow], stream)

    stream.seek(0)
    header, row = list(csv.reader(stream))
    assert rows == 1
    assert tuple(header) == FLOW_EXPORT_COLUMNS
    values = dict(zip(header, row, strict=True))
    assert values["queue_occupancy_mean"] == ""
    assert values["latency_min"] == ""
    assert values["proto"] == "6"
    assert values["termination_reason"] == "end_of_input"


def test_client_csv_is_byte_identical_to_core_csv() -> None:
    flows = [make_flow(), make_flow(flow_segment_id=1, mean_hop_latency=None)]
    sdk_flows = [
        SdkFlow.from_dict(json.loads(flow.model_dump_json())) for flow in flows
    ]
    core, client = io.StringIO(), io.StringIO()

    write_flows_csv(flows, core)
    write_sdk_csv(sdk_flows, client)

    assert client.getvalue() == core.getvalue()
