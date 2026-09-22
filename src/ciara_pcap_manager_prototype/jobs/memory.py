"""
In-process job store.

Suitable for a single-process prototype. It is deliberately the smallest thing
that satisfies :class:`~ciara_pcap_manager_prototype.jobs.store.JobStore`, so the cost
of replacing it with Redis is a new file rather than a refactor.
"""

import asyncio
from uuid import UUID

from ciara_pcap_manager_prototype.domain.flows import Flow
from ciara_pcap_manager_prototype.domain.jobs import AnalysisJob
from ciara_pcap_manager_prototype.jobs.store import JobNotFoundError


class InMemoryJobStore:
    """Keeps jobs and their flows in memory, guarded by a single lock."""

    def __init__(self) -> None:
        """Create an empty store."""
        self._jobs: dict[UUID, AnalysisJob] = {}
        self._flows: dict[UUID, list[Flow]] = {}
        self._lock = asyncio.Lock()

    async def create(self, job: AnalysisJob) -> AnalysisJob:
        """
        Persist a newly accepted job.

        Args:
            job: The job to store.

        Returns:
            The stored job.

        """
        async with self._lock:
            self._jobs[job.job_id] = job
        return job

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
        async with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise JobNotFoundError(job_id)
        return job

    async def list_jobs(self) -> list[AnalysisJob]:
        """
        List every known job, newest first.

        Returns:
            All stored jobs.

        """
        async with self._lock:
            jobs = list(self._jobs.values())
        return sorted(jobs, key=lambda job: job.created_at, reverse=True)

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
        async with self._lock:
            if job.job_id not in self._jobs:
                raise JobNotFoundError(job.job_id)
            self._jobs[job.job_id] = job
        return job

    async def set_flows(self, job_id: UUID, flows: list[Flow]) -> None:
        """
        Attach extraction results to a job.

        Args:
            job_id: Identifier of the job the flows belong to.
            flows: The extracted flows.

        Raises:
            JobNotFoundError: If no such job exists.

        """
        async with self._lock:
            if job_id not in self._jobs:
                raise JobNotFoundError(job_id)
            self._flows[job_id] = flows

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
        async with self._lock:
            if job_id not in self._jobs:
                raise JobNotFoundError(job_id)
            flows = self._flows.get(job_id, [])
            return flows[offset : offset + limit], len(flows)
