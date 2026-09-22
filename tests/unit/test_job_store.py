"""Tests for the in-memory job store."""

from uuid import uuid4

import pytest

from ciara_pcap_manager_prototype.domain.jobs import AnalysisJob, JobStatus
from ciara_pcap_manager_prototype.jobs import InMemoryJobStore, JobNotFoundError
from tests.support.factories import make_flow


async def test_created_job_can_be_read_back() -> None:
    store = InMemoryJobStore()
    job = AnalysisJob(filename="a.pcap", size_bytes=10)

    await store.create(job)

    assert (await store.get(job.job_id)).filename == "a.pcap"


async def test_reading_an_unknown_job_raises() -> None:
    store = InMemoryJobStore()
    missing = uuid4()

    with pytest.raises(JobNotFoundError) as caught:
        await store.get(missing)

    assert caught.value.job_id == missing


async def test_saving_an_unknown_job_raises() -> None:
    store = InMemoryJobStore()

    with pytest.raises(JobNotFoundError):
        await store.save(AnalysisJob(filename="ghost.pcap", size_bytes=0))


async def test_save_replaces_the_stored_state() -> None:
    store = InMemoryJobStore()
    job = await store.create(AnalysisJob(filename="a.pcap", size_bytes=10))

    job.status = JobStatus.SUCCEEDED
    await store.save(job)

    assert (await store.get(job.job_id)).status is JobStatus.SUCCEEDED


async def test_jobs_are_listed_newest_first() -> None:
    store = InMemoryJobStore()
    first = await store.create(AnalysisJob(filename="first.pcap", size_bytes=1))
    second = AnalysisJob(filename="second.pcap", size_bytes=2)
    second.created_at = first.created_at.replace(year=first.created_at.year + 1)
    await store.create(second)

    listed = await store.list_jobs()

    assert [job.filename for job in listed] == ["second.pcap", "first.pcap"]


async def test_flows_are_paged_and_report_the_full_total() -> None:
    store = InMemoryJobStore()
    job = await store.create(AnalysisJob(filename="a.pcap", size_bytes=10))
    await store.set_flows(job.job_id, [make_flow(flow_id=i) for i in range(5)])

    page, total = await store.get_flows(job.job_id, offset=1, limit=2)

    assert total == 5
    assert [flow.flow_id for flow in page] == [1, 2]


async def test_flows_of_a_job_that_never_ran_are_empty() -> None:
    store = InMemoryJobStore()
    job = await store.create(AnalysisJob(filename="a.pcap", size_bytes=10))

    page, total = await store.get_flows(job.job_id)

    assert page == []
    assert total == 0


async def test_attaching_flows_to_an_unknown_job_raises() -> None:
    store = InMemoryJobStore()

    with pytest.raises(JobNotFoundError):
        await store.set_flows(uuid4(), [])
