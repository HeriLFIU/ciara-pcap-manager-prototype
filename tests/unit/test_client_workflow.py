"""
Tests for the shared client workflow.

A stubbed httpx transport stands in for the backend, so the upload, polling and
pagination logic is exercised without a server and without a socket.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from ciara_pcap_client import (
    ApiError,
    analyze_capture,
    build_client,
    check_health,
    fetch_all_flows,
    get_job,
    list_jobs,
    submit_capture,
    value_or,
    wait_for_job,
)
from ciara_pcap_sdk import Client

from tests.support.factories import make_flow

JOB_ID = UUID("11111111-2222-3333-4444-555555555555")
PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
BAD_REQUEST = 400


def job_payload(status: str = "pending", **extra: Any) -> dict[str, Any]:  # noqa: ANN401 - JSON
    """Build the JSON body the backend would return for a job."""
    return {
        "job_id": str(JOB_ID),
        "status": status,
        "filename": "sample.pcap",
        "size_bytes": 851,
        "created_at": "2026-09-10T12:00:00Z",
        "started_at": None,
        "finished_at": None,
        "summary": None,
        "error": None,
    } | extra


def flow_payload(flow_id: int) -> dict[str, Any]:
    """Build the JSON body of a single flow."""
    return json.loads(make_flow(flow_id=flow_id).model_dump_json())


def stub_client(handler: Callable[[httpx.Request], httpx.Response]) -> Client:
    """Build an SDK client whose transport is driven by `handler`."""
    client = build_client("http://backend")
    client.set_async_httpx_client(
        httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://backend"
        )
    )
    return client


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    """A file on disk that looks enough like a capture to be uploaded."""
    path = tmp_path / "sample.pcap"
    path.write_bytes(PCAP_MAGIC + b"body")
    return path


async def test_health_is_parsed() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "service": "ciara-pcap-api"})

    async with stub_client(handler) as client:
        assert (await check_health(client)).status == "ok"


async def test_upload_sends_the_file_bytes_as_multipart(capture: Path) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["content_type"] = request.headers["content-type"]
        seen["body"] = request.content
        return httpx.Response(202, json=job_payload())

    async with stub_client(handler) as client:
        job = await submit_capture(client, capture)

    assert job.job_id == JOB_ID
    assert seen["content_type"].startswith("multipart/form-data")
    assert PCAP_MAGIC + b"body" in seen["body"]
    assert b'filename="sample.pcap"' in seen["body"]


async def test_an_error_status_becomes_a_readable_api_error(capture: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(415, json={"detail": "Upload is not a capture."})

    async with stub_client(handler) as client:
        with pytest.raises(ApiError, match=r"Upload is not a capture\."):
            await submit_capture(client, capture)


async def test_a_non_json_error_still_produces_a_message(capture: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="upstream exploded")

    async with stub_client(handler) as client:
        with pytest.raises(ApiError, match="upstream exploded"):
            await submit_capture(client, capture)


async def test_waiting_polls_until_the_job_is_terminal() -> None:
    statuses = iter(["pending", "running", "succeeded"])
    seen: list[str] = []

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=job_payload(next(statuses)))

    async with stub_client(handler) as client:
        job = await wait_for_job(
            client,
            JOB_ID,
            poll_interval=0,
            on_update=lambda j: seen.append(str(j.status)),
        )

    assert job.status == "succeeded"
    assert seen == ["pending", "running", "succeeded"]


async def test_waiting_gives_up_after_the_timeout() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=job_payload("running"))

    async with stub_client(handler) as client:
        with pytest.raises(ApiError, match="did not finish"):
            await wait_for_job(client, JOB_ID, poll_interval=0, timeout=0)


async def test_flows_are_fetched_page_by_page() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        limit = int(request.url.params["limit"])
        everything = [flow_payload(i) for i in range(5)]
        return httpx.Response(
            200,
            json={
                "items": everything[offset : offset + limit],
                "total": len(everything),
                "offset": offset,
                "limit": limit,
            },
        )

    progress: list[tuple[int, int]] = []
    async with stub_client(handler) as client:
        flows = await fetch_all_flows(
            client, JOB_ID, page_size=2, on_page=lambda a, b: progress.append((a, b))
        )

    assert [flow.flow_id for flow in flows] == [0, 1, 2, 3, 4]
    assert progress == [(2, 5), (4, 5), (5, 5)]


async def test_pagination_stops_when_the_backend_returns_nothing() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"items": [], "total": 99, "offset": 0, "limit": 10}
        )

    async with stub_client(handler) as client:
        assert await fetch_all_flows(client, JOB_ID) == []


async def test_the_whole_workflow_runs_end_to_end(capture: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json=job_payload())
        if request.url.path.endswith("/flows"):
            return httpx.Response(
                200,
                json={
                    "items": [flow_payload(0)],
                    "total": 1,
                    "offset": 0,
                    "limit": 500,
                },
            )
        return httpx.Response(
            200,
            json=job_payload(
                "succeeded",
                summary={
                    "flow_count": 1,
                    "packet_count": 8,
                    "byte_count": 509,
                    "top_applications": {"HTTP": 1},
                },
            ),
        )

    async with stub_client(handler) as client:
        job, flows = await analyze_capture(client, capture, poll_interval=0)

    assert job.status == "succeeded"
    assert len(flows) == 1
    summary = value_or(job.summary, None)
    assert summary is not None
    applications = value_or(summary.top_applications, None)
    assert applications is not None
    assert applications.additional_properties == {"HTTP": 1}


async def test_a_failed_job_short_circuits_the_flow_fetch(capture: Path) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        if request.method == "POST":
            return httpx.Response(202, json=job_payload())
        return httpx.Response(200, json=job_payload("failed", error="engine exploded"))

    async with stub_client(handler) as client:
        job, flows = await analyze_capture(client, capture, poll_interval=0)

    assert job.status == "failed"
    assert flows == []
    assert not any(path.endswith("/flows") for path in requested)


async def test_listing_jobs_returns_every_entry() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[job_payload(), job_payload("succeeded")])

    async with stub_client(handler) as client:
        assert len(await list_jobs(client)) == 2


async def test_an_unparsable_body_is_reported_rather_than_returned() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(BAD_REQUEST, json={"unexpected": "shape"})

    async with stub_client(handler) as client:
        with pytest.raises(ApiError):
            await get_job(client, uuid4())
