"""
Capture upload and analysis result endpoints.

Uploading a capture returns ``202 Accepted`` with a job identifier rather than
blocking until the parse completes. Clients poll the job and then page through
its flows, which keeps the contract identical whether the work runs in a local
process pool or on a remote worker fleet.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status

from ciara_pcap_api.api.deps import AnalysisServiceDep
from ciara_pcap_api.core.storage import CaptureTooLargeError, NotACaptureError
from ciara_pcap_manager_prototype.domain.flows import FlowPage
from ciara_pcap_manager_prototype.domain.jobs import AnalysisJob
from ciara_pcap_manager_prototype.jobs.store import JobNotFoundError

router = APIRouter(prefix="/captures", tags=["captures"])

MAX_PAGE_SIZE = 1000


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload a capture for analysis",
)
async def upload_capture(
    service: AnalysisServiceDep,
    file: Annotated[UploadFile, File(description="A libpcap or pcapng capture.")],
) -> AnalysisJob:
    """
    Accept a capture upload and schedule flow extraction.

    Args:
        service: The analysis service.
        file: The uploaded capture, streamed to disk in chunks.

    Returns:
        The accepted job. Poll it to learn when extraction finished.

    Raises:
        HTTPException: If the upload is too large or is not a capture file.

    """
    try:
        return await service.submit(
            filename=file.filename or "capture.pcap",
            read_chunk=file.read,
        )
    except CaptureTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
        ) from exc
    except NotACaptureError as exc:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(exc)
        ) from exc


@router.get("", summary="List analysis jobs")
async def list_captures(service: AnalysisServiceDep) -> list[AnalysisJob]:
    """
    List every analysis job, newest first.

    Args:
        service: The analysis service.

    Returns:
        All known jobs.

    """
    return await service.list_jobs()


@router.get("/{job_id}", summary="Read one analysis job")
async def read_capture(service: AnalysisServiceDep, job_id: UUID) -> AnalysisJob:
    """
    Read the current state of an analysis job.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.

    Returns:
        The job, including its summary once extraction succeeded.

    Raises:
        HTTPException: If the job does not exist.

    """
    try:
        return await service.get(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@router.get("/{job_id}/flows", summary="Page through extracted flows")
async def read_capture_flows(
    service: AnalysisServiceDep,
    job_id: UUID,
    offset: Annotated[int, Query(ge=0, description="Index of the first flow.")] = 0,
    limit: Annotated[
        int,
        Query(ge=1, le=MAX_PAGE_SIZE, description="Maximum flows to return."),
    ] = 100,
) -> FlowPage:
    """
    Read one page of the flows extracted from a capture.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.
        offset: Index of the first flow to return.
        limit: Maximum number of flows to return.

    Returns:
        The requested page of flows.

    Raises:
        HTTPException: If the job does not exist.

    """
    try:
        items, total = await service.get_flows(job_id, offset=offset, limit=limit)
    except JobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return FlowPage(items=items, total=total, offset=offset, limit=limit)


@router.delete(
    "/{job_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a stored capture file",
)
async def delete_capture(service: AnalysisServiceDep, job_id: UUID) -> None:
    """
    Delete the capture file backing a job, keeping the job record.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.

    Raises:
        HTTPException: If the job does not exist.

    """
    try:
        await service.delete(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
