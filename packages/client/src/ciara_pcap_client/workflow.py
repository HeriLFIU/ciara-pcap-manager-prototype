"""
The capture analysis workflow, expressed once for every Python client.

The generated SDK knows how to call each endpoint; it does not know that
uploading a capture starts a job you then have to poll. That sequence lives
here so the CLI and the desktop GUI cannot drift apart, and so a future worker
or notebook gets it for free.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

import httpx
from ciara_pcap_sdk import Client
from ciara_pcap_sdk.api.captures import (
    list_captures,
    read_capture,
    read_capture_flows,
    upload_capture,
)
from ciara_pcap_sdk.api.health import read_health
from ciara_pcap_sdk.errors import UnexpectedStatus
from ciara_pcap_sdk.models import (
    AnalysisJob,
    BodyUploadCapture,
    Flow,
    FlowPage,
    HealthResponse,
)
from ciara_pcap_sdk.types import File, Response, Unset

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

#: Job states from which no further transition happens.
TERMINAL_STATUSES: frozenset[str] = frozenset({"succeeded", "failed"})

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_PAGE_SIZE = 500


class ApiError(RuntimeError):
    """Raised when the backend answers with something the client cannot use."""


def build_client(base_url: str = DEFAULT_BASE_URL, *, timeout: float = 60.0) -> Client:
    """
    Create an SDK client pointed at a backend.

    Args:
        base_url: Root URL of the API, without the version prefix.
        timeout: Per-request timeout in seconds.

    Returns:
        A configured SDK client. Use it as an async context manager.

    """
    return Client(
        base_url=base_url.rstrip("/"),
        timeout=httpx.Timeout(timeout),
        raise_on_unexpected_status=True,
    )


async def _send[T](call: "Awaitable[Response[T]]") -> Response[T]:
    """
    Await one SDK call, reporting a refused request as an `ApiError`.

    Args:
        call: The ``asyncio_detailed`` coroutine to await.

    Returns:
        The detailed response, with its payload type preserved.

    Raises:
        ApiError: If the backend answered with an unexpected status.

    """
    try:
        return await call
    except UnexpectedStatus as exc:
        raise ApiError(_describe(exc)) from exc


async def _request[T](call: "Awaitable[Response[Any]]", expected: type[T]) -> T:
    """
    Await one SDK call and narrow its payload to the model the caller needs.

    Every endpoint needs the same two guards -- an unexpected status, and a body
    of the wrong shape (a validation error, say) -- so they live here instead of
    in each wrapper below.

    Args:
        call: The ``asyncio_detailed`` coroutine to await.
        expected: The model the caller needs.

    Returns:
        The parsed payload.

    Raises:
        ApiError: If the backend refused the call or answered with a different
            shape than the contract promises.

    """
    response = await _send(call)
    if isinstance(response.parsed, expected):
        return response.parsed
    detail = response.content.decode("utf-8", errors="replace")[:500]
    msg = f"Unexpected response (HTTP {response.status_code}): {detail}"
    raise ApiError(msg)


async def check_health(client: Client) -> HealthResponse:
    """
    Confirm the backend is reachable.

    Args:
        client: The SDK client.

    Returns:
        The health payload.

    Raises:
        ApiError: If the backend is unreachable or answers unexpectedly.

    """
    return await _request(read_health.asyncio_detailed(client=client), HealthResponse)


async def submit_capture(client: Client, pcap_path: Path) -> AnalysisJob:
    """
    Upload a capture and return the job the backend created for it.

    Args:
        client: The SDK client.
        pcap_path: The capture file to upload.

    Returns:
        The accepted job, in its pending state.

    Raises:
        ApiError: If the backend rejected the upload.

    """
    with pcap_path.open("rb") as handle:
        body = BodyUploadCapture(
            file=File(
                payload=handle,
                file_name=pcap_path.name,
                mime_type="application/octet-stream",
            )
        )
        # Awaited inside the `with`: the SDK streams the handle, so the file
        # must stay open until the upload completes.
        return await _request(
            upload_capture.asyncio_detailed(client=client, body=body), AnalysisJob
        )


async def get_job(client: Client, job_id: UUID) -> AnalysisJob:
    """
    Read the current state of a job.

    Args:
        client: The SDK client.
        job_id: The job to read.

    Returns:
        The job.

    Raises:
        ApiError: If the job does not exist.

    """
    return await _request(
        read_capture.asyncio_detailed(job_id, client=client), AnalysisJob
    )


async def list_jobs(client: Client) -> list[AnalysisJob]:
    """
    List every job the backend knows about, newest first.

    Args:
        client: The SDK client.

    Returns:
        The jobs.

    Raises:
        ApiError: If the backend answers unexpectedly.

    """
    response = await _send(list_captures.asyncio_detailed(client=client))
    if response.parsed is None:
        msg = f"Unexpected response (HTTP {response.status_code}) listing jobs."
        raise ApiError(msg)
    return response.parsed


async def wait_for_job(
    client: Client,
    job_id: UUID,
    *,
    poll_interval: float = 0.5,
    timeout: float = 600.0,
    on_update: "Callable[[AnalysisJob], None] | None" = None,
) -> AnalysisJob:
    """
    Poll a job until it reaches a terminal state.

    Args:
        client: The SDK client.
        job_id: The job to wait for.
        poll_interval: Seconds between polls.
        timeout: Give up after this many seconds.
        on_update: Called with every polled state, for progress reporting.

    Returns:
        The job in its terminal state.

    Raises:
        ApiError: If the job does not finish within the timeout.

    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    while True:
        job = await get_job(client, job_id)
        if on_update is not None:
            on_update(job)
        if job.status in TERMINAL_STATUSES:
            return job
        if loop.time() >= deadline:
            msg = f"Job {job_id} did not finish within {timeout:.0f}s."
            raise ApiError(msg)
        await asyncio.sleep(poll_interval)


async def fetch_flow_page(
    client: Client, job_id: UUID, *, offset: int = 0, limit: int = DEFAULT_PAGE_SIZE
) -> FlowPage:
    """
    Read a single page of a job's flows.

    Args:
        client: The SDK client.
        job_id: The job to read.
        offset: Index of the first flow.
        limit: Maximum flows to return.

    Returns:
        The page of flows.

    Raises:
        ApiError: If the backend answers unexpectedly.

    """
    return await _request(
        read_capture_flows.asyncio_detailed(
            job_id, client=client, offset=offset, limit=limit
        ),
        FlowPage,
    )


async def fetch_all_flows(
    client: Client,
    job_id: UUID,
    *,
    page_size: int = DEFAULT_PAGE_SIZE,
    on_page: "Callable[[int, int], None] | None" = None,
) -> list[Flow]:
    """
    Page through every flow a job produced.

    Args:
        client: The SDK client.
        job_id: The job to read.
        page_size: Flows requested per round trip.
        on_page: Called with ``(loaded, total)`` after each page.

    Returns:
        Every flow, in backend order.

    Raises:
        ApiError: If the backend answers unexpectedly.

    """
    flows: list[Flow] = []
    while True:
        page = await fetch_flow_page(client, job_id, offset=len(flows), limit=page_size)
        flows.extend(page.items)
        if on_page is not None:
            on_page(len(flows), page.total)
        if not page.items or len(flows) >= page.total:
            return flows


async def analyze_capture(  # noqa: PLR0913 - keyword-only progress and paging knobs
    client: Client,
    pcap_path: Path,
    *,
    poll_interval: float = 0.5,
    timeout: float = 600.0,
    page_size: int = DEFAULT_PAGE_SIZE,
    on_update: "Callable[[AnalysisJob], None] | None" = None,
    on_page: "Callable[[int, int], None] | None" = None,
) -> tuple[AnalysisJob, list[Flow]]:
    """
    Run the whole workflow: upload, wait, then collect the flows.

    Args:
        client: The SDK client.
        pcap_path: The capture file to analyse.
        poll_interval: Seconds between job polls.
        timeout: Give up waiting after this many seconds.
        page_size: Flows requested per round trip.
        on_update: Called with every polled job state.
        on_page: Called with ``(loaded, total)`` after each page of flows.

    Returns:
        The terminal job and its flows. The flow list is empty if the job
        failed.

    Raises:
        ApiError: If the upload was rejected or the job never finished.

    """
    job = await submit_capture(client, pcap_path)
    if on_update is not None:
        on_update(job)
    job_id = _require_job_id(job)

    job = await wait_for_job(
        client,
        job_id,
        poll_interval=poll_interval,
        timeout=timeout,
        on_update=on_update,
    )
    if job.status != "succeeded":
        return job, []

    flows = await fetch_all_flows(client, job_id, page_size=page_size, on_page=on_page)
    return job, flows


def _require_job_id(job: AnalysisJob) -> UUID:
    """
    Read the identifier the backend assigned to a job.

    Args:
        job: A job returned by the backend.

    Returns:
        The job identifier.

    Raises:
        ApiError: If the backend omitted it, which the contract forbids.

    """
    if isinstance(job.job_id, Unset):
        msg = "The backend accepted the upload but returned no job id."
        raise ApiError(msg)
    return job.job_id


def _describe(exc: UnexpectedStatus) -> str:
    """
    Turn an unexpected HTTP status into a message worth showing a user.

    Args:
        exc: The error raised by the SDK.

    Returns:
        A one-line description including the backend's own detail, if any.

    """
    body = exc.content.decode("utf-8", errors="replace")
    detail = body
    try:
        parsed: object = json.loads(body)
    except ValueError:
        pass
    else:
        if isinstance(parsed, dict) and "detail" in parsed:
            detail = str(parsed["detail"])  # pyright: ignore[reportUnknownArgumentType]
    return f"Backend returned HTTP {exc.status_code}: {detail[:500]}"
