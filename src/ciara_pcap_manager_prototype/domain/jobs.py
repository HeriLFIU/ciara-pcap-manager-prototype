"""
Analysis job models.

A capture upload creates a job. Parsing then happens outside the request, so
every client polls the same job resource regardless of whether the work is done
by a local process pool today or by a distributed worker fleet later.
"""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from ciara_pcap_manager_prototype.domain.flows import FlowSummary


class JobStatus(StrEnum):
    """Lifecycle state of an analysis job."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        """
        Report whether no further state transition can occur.

        Returns:
            True when the job has finished, successfully or not.

        """
        return self in {JobStatus.SUCCEEDED, JobStatus.FAILED}


def _utc_now() -> datetime:
    """
    Produce the current time as a timezone-aware UTC datetime.

    Returns:
        The current UTC time.

    """
    return datetime.now(UTC)


class AnalysisJob(BaseModel):
    """The public view of a capture analysis job."""

    job_id: UUID = Field(default_factory=uuid4, description="Unique job identifier.")
    status: JobStatus = Field(
        default=JobStatus.PENDING, description="Current lifecycle state."
    )
    filename: str = Field(description="Original name of the uploaded capture.")
    size_bytes: int = Field(description="Size of the uploaded capture on disk.")
    created_at: datetime = Field(
        default_factory=_utc_now, description="When the upload was accepted."
    )
    started_at: datetime | None = Field(
        default=None, description="When extraction began."
    )
    finished_at: datetime | None = Field(
        default=None, description="When extraction reached a terminal state."
    )
    summary: FlowSummary | None = Field(
        default=None, description="Aggregate statistics, present once succeeded."
    )
    error: str | None = Field(
        default=None, description="Failure detail, present only when failed."
    )
