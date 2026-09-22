"""The job store contract."""

from typing import Protocol
from uuid import UUID

from ciara_pcap_manager_prototype.domain.flows import Flow
from ciara_pcap_manager_prototype.domain.jobs import AnalysisJob


class JobNotFoundError(LookupError):
    """Raised when a job identifier does not resolve to a known job."""

    def __init__(self, job_id: UUID) -> None:
        """
        Record which job was missing.

        Args:
            job_id: The identifier that could not be resolved.

        """
        self.job_id = job_id
        super().__init__(f"No analysis job with id {job_id}")


class JobStore(Protocol):
    """Persistence for analysis jobs and the flows they produced."""

    async def create(self, job: AnalysisJob) -> AnalysisJob:
        """
        Persist a newly accepted job.

        Args:
            job: The job to store.

        Returns:
            The stored job.

        """
        ...

    async def get(self, job_id: UUID) -> AnalysisJob:
        """
        Fetch a single job.

        Args:
            job_id: Identifier of the job to fetch.

        Returns:
            The stored job.

        Raises:
            JobNotFoundError: If no such job exists.

        """
        ...

    async def list_jobs(self) -> list[AnalysisJob]:
        """
        List every known job, newest first.

        Returns:
            All stored jobs.

        """
        ...

    async def save(self, job: AnalysisJob) -> AnalysisJob:
        """
        Overwrite a stored job with a new state.

        Args:
            job: The job state to persist.

        Returns:
            The persisted job.

        Raises:
            JobNotFoundError: If no such job exists.

        """
        ...

    async def set_flows(self, job_id: UUID, flows: list[Flow]) -> None:
        """
        Attach extraction results to a job.

        Args:
            job_id: Identifier of the job the flows belong to.
            flows: The extracted flows.

        Raises:
            JobNotFoundError: If no such job exists.

        """
        ...

    async def get_flows(
        self, job_id: UUID, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[Flow], int]:
        """
        Read one page of a job's flows.

        Args:
            job_id: Identifier of the job to read.
            offset: Index of the first flow to return.
            limit: Maximum number of flows to return.

        Returns:
            The requested page and the total number of flows available.

        Raises:
            JobNotFoundError: If no such job exists.

        """
        ...
