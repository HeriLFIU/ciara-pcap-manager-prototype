"""
Capture analysis orchestration.

The service owns the job lifecycle: accept an upload, hand the parse to a
worker process, and record the outcome. Routes stay thin, and the day this is
replaced by a Celery task the routes do not change at all.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from ciara_pcap_manager_prototype.domain.flows import Flow, FlowSummary
from ciara_pcap_manager_prototype.domain.jobs import AnalysisJob, JobStatus
from ciara_pcap_manager_prototype.jobs.store import JobStore
from ciara_pcap_manager_prototype.pcap.runner import FlowExtractor

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ciara_pcap_api.core.storage import CaptureStorage

logger = logging.getLogger(__name__)


class AnalysisService:
    """Coordinates capture storage, the job store and the extraction runner."""

    def __init__(
        self,
        *,
        store: JobStore,
        storage: "CaptureStorage",
        runner: FlowExtractor,
    ) -> None:
        """
        Wire the service to its collaborators.

        Args:
            store: Persistence for jobs and their flows.
            storage: On-disk capture storage.
            runner: Executor that parses captures off the event loop.

        """
        self._store = store
        self._storage = storage
        self._runner = runner
        # Strong references: a task that only the event loop knows about can be
        # garbage collected mid-flight.
        self._tasks: set[asyncio.Task[None]] = set()

    async def submit(
        self,
        *,
        filename: str,
        read_chunk: "Callable[[int], Awaitable[bytes]]",
    ) -> AnalysisJob:
        """
        Accept a capture upload and schedule its analysis.

        Args:
            filename: Client-supplied name, retained for display only.
            read_chunk: Awaitable returning the next chunk of the upload.

        Returns:
            The accepted job, in its pending state.

        """
        job = AnalysisJob(filename=filename, size_bytes=0)
        _, size = await self._storage.save(job.job_id, read_chunk)
        job.size_bytes = size
        await self._store.create(job)

        task = asyncio.create_task(self._run(job.job_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        return job

    async def get(self, job_id: UUID) -> AnalysisJob:
        """
        Fetch a job by identifier.

        Args:
            job_id: The job to fetch.

        Returns:
            The stored job.

        """
        return await self._store.get(job_id)

    async def list_jobs(self) -> list[AnalysisJob]:
        """
        List every job, newest first.

        Returns:
            All stored jobs.

        """
        return await self._store.list_jobs()

    async def get_flows(
        self, job_id: UUID, *, offset: int, limit: int
    ) -> tuple[list[Flow], int]:
        """
        Read one page of a job's flows.

        Args:
            job_id: The job to read.
            offset: Index of the first flow to return.
            limit: Maximum number of flows to return.

        Returns:
            The page of flows and the total flow count.

        """
        return await self._store.get_flows(job_id, offset=offset, limit=limit)

    async def delete(self, job_id: UUID) -> None:
        """
        Delete a job's capture file from disk.

        The job record is kept so clients polling a deleted job still get a
        meaningful answer.

        Args:
            job_id: The job whose capture should be removed.

        """
        await self._store.get(job_id)
        self._storage.delete(job_id)

    async def _run(self, job_id: UUID) -> None:
        """
        Execute one analysis job to completion.

        Args:
            job_id: The job to execute.

        """
        job = await self._store.get(job_id)
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(UTC)
        await self._store.save(job)

        try:
            flows = await self._runner.extract(self._storage.path_for(job_id))
        except Exception as exc:
            logger.exception("Analysis failed for job %s", job_id)
            job.status = JobStatus.FAILED
            job.error = str(exc)
        else:
            await self._store.set_flows(job_id, flows)
            job.status = JobStatus.SUCCEEDED
            job.summary = FlowSummary.from_flows(flows)

        job.finished_at = datetime.now(UTC)
        await self._store.save(job)

    async def aclose(self) -> None:
        """Cancel outstanding analyses and release the worker pool."""
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._runner.shutdown(wait=False)
