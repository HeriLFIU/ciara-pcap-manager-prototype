"""
Tests for the HTTP surface.

The application is exercised through an in-process ASGI transport with a stub
extractor, so these tests never open a socket and never parse a capture.
"""

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from ciara_pcap_api.core.config import ApiSettings
from ciara_pcap_api.core.storage import CaptureStorage
from ciara_pcap_api.main import create_app
from ciara_pcap_api.services.analysis import AnalysisService

from ciara_pcap_manager_prototype.domain.flows import DecodeReport, Flow
from ciara_pcap_manager_prototype.jobs.memory import InMemoryJobStore
from ciara_pcap_manager_prototype.pcap.extractor import ExtractionResult
from tests.support.factories import make_flow

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
CAPTURE_BYTES = PCAP_MAGIC + b"synthetic capture body"
OK = 200
ACCEPTED = 202
NO_CONTENT = 204
NOT_FOUND = 404
UNSUPPORTED_MEDIA_TYPE = 415
UNPROCESSABLE = 422


REPORT = DecodeReport(
    frames_read=12,
    inner_packets=10,
    packets_with_int=10,
    packets_with_int_hops=9,
    packets_out_of_order=1,
    packets_late=0,
    packets_over_flow_cap=0,
    skipped={"not_telemetry_port": 2},
)


class StubExtractor:
    """Returns canned flows, or raises, without parsing anything."""

    def __init__(
        self, flows: list[Flow] | None = None, error: str | None = None
    ) -> None:
        self.flows = flows if flows is not None else []
        self.error = error
        self.calls: list[tuple[Path, str | None]] = []

    async def extract(
        self, pcap_path: Path, *, source_name: str | None = None
    ) -> ExtractionResult:
        """Record the call and return the canned outcome."""
        self.calls.append((pcap_path, source_name))
        if self.error is not None:
            raise RuntimeError(self.error)
        return ExtractionResult(flows=list(self.flows), report=REPORT)

    def shutdown(self, *, wait: bool = True) -> None:
        """Accept the shutdown call; there is nothing to release."""


@pytest.fixture
def extractor() -> StubExtractor:
    """A stub extractor returning two flows."""
    return StubExtractor([make_flow(), make_flow(flow_segment_id=1, proto=17)])


@pytest.fixture
async def client(
    tmp_path: Path, extractor: StubExtractor
) -> AsyncIterator[httpx.AsyncClient]:
    """An HTTP client bound to the app in-process, with storage in tmp_path."""
    settings = ApiSettings(storage_dir=tmp_path, cors_origins=[])
    app = create_app(settings)
    app.state.analysis_service = AnalysisService(
        store=InMemoryJobStore(),
        storage=CaptureStorage(
            settings.ensure_storage_dir(), max_bytes=1_000_000, chunk_bytes=64
        ),
        runner=extractor,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api") as http:
        yield http


async def submit(
    http: httpx.AsyncClient, payload: bytes = CAPTURE_BYTES
) -> httpx.Response:
    """Upload a capture body and return the raw response."""
    return await http.post(
        "/api/v1/captures",
        files={"file": ("sample.pcap", payload, "application/octet-stream")},
    )


async def await_terminal(http: httpx.AsyncClient, job_id: str) -> dict[str, Any]:
    """Poll a job until it leaves the pending or running states."""
    for _ in range(200):
        body = (await http.get(f"/api/v1/captures/{job_id}")).json()
        if body["status"] in {"succeeded", "failed"}:
            return body
        await asyncio.sleep(0.01)
    pytest.fail(f"Job {job_id} never reached a terminal state")


async def test_health_reports_ok(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health")

    assert response.status_code == OK
    assert response.json() == {"status": "ok", "service": "ciara-pcap-api"}


async def test_upload_is_accepted_without_waiting_for_the_parse(
    client: httpx.AsyncClient,
) -> None:
    response = await submit(client)

    assert response.status_code == ACCEPTED
    body = response.json()
    assert body["status"] in {"pending", "running", "succeeded"}
    assert body["filename"] == "sample.pcap"
    assert body["size_bytes"] == len(CAPTURE_BYTES)


async def test_a_successful_job_gains_a_summary(client: httpx.AsyncClient) -> None:
    job_id = (await submit(client)).json()["job_id"]

    body = await await_terminal(client, job_id)

    assert body["status"] == "succeeded"
    assert body["summary"]["flow_count"] == 2
    assert body["summary"]["flows_by_protocol"] == {"TCP": 1, "UDP": 1}
    assert body["summary"]["decode"] == REPORT.model_dump()
    assert body["error"] is None


async def test_flows_are_paginated(client: httpx.AsyncClient) -> None:
    job_id = (await submit(client)).json()["job_id"]
    await await_terminal(client, job_id)

    page = (
        await client.get(
            f"/api/v1/captures/{job_id}/flows", params={"offset": 1, "limit": 1}
        )
    ).json()

    assert page["total"] == 2
    assert page["offset"] == 1
    assert page["limit"] == 1
    assert [flow["flow_segment_id"] for flow in page["items"]] == [1]
    assert len(page["items"][0]) == 99


async def test_upload_is_passed_to_the_extractor_as_a_real_file(
    client: httpx.AsyncClient, extractor: StubExtractor
) -> None:
    job_id = (await submit(client)).json()["job_id"]
    await await_terminal(client, job_id)

    assert len(extractor.calls) == 1
    stored, source_name = extractor.calls[0]
    assert stored.read_bytes() == CAPTURE_BYTES
    assert source_name == "sample.pcap"


async def test_a_non_capture_upload_is_refused(client: httpx.AsyncClient) -> None:
    response = await submit(client, payload=b"PK\x03\x04definitely a zip")

    assert response.status_code == UNSUPPORTED_MEDIA_TYPE


async def test_a_request_without_a_file_is_a_validation_error(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post("/api/v1/captures")

    assert response.status_code == UNPROCESSABLE


@pytest.mark.parametrize("extractor", [StubExtractor(error="engine exploded")])
async def test_an_extraction_failure_is_recorded_on_the_job(
    client: httpx.AsyncClient,
) -> None:
    job_id = (await submit(client)).json()["job_id"]

    body = await await_terminal(client, job_id)

    assert body["status"] == "failed"
    assert "engine exploded" in str(body["error"])
    assert body["summary"] is None


async def test_jobs_are_listed(client: httpx.AsyncClient) -> None:
    await submit(client)
    await submit(client)

    listed = (await client.get("/api/v1/captures")).json()

    assert len(listed) == 2


async def test_unknown_job_ids_are_not_found(client: httpx.AsyncClient) -> None:
    missing = uuid4()

    assert (await client.get(f"/api/v1/captures/{missing}")).status_code == NOT_FOUND
    assert (
        await client.get(f"/api/v1/captures/{missing}/flows")
    ).status_code == NOT_FOUND
    assert (await client.delete(f"/api/v1/captures/{missing}")).status_code == NOT_FOUND


async def test_deleting_a_job_removes_its_capture_file(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    job_id = (await submit(client)).json()["job_id"]
    await await_terminal(client, job_id)
    stored = tmp_path / f"{job_id}.pcap"
    assert stored.exists()

    response = await client.delete(f"/api/v1/captures/{job_id}")

    assert response.status_code == NO_CONTENT
    assert not stored.exists()


async def test_the_openapi_document_is_3_1_with_readable_operation_ids(
    client: httpx.AsyncClient,
) -> None:
    document = (await client.get("/api/v1/openapi.json")).json()

    assert document["openapi"].startswith("3.1")
    operations = {
        operation["operationId"]
        for methods in document["paths"].values()
        for operation in methods.values()
    }
    assert {"upload_capture", "read_capture", "read_capture_flows"} <= operations
