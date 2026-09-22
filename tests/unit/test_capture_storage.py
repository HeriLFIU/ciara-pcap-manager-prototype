"""Tests for the streaming capture storage."""

from collections.abc import Awaitable, Callable
from pathlib import Path
from uuid import uuid4

import pytest
from ciara_pcap_api.core.storage import (
    CaptureStorage,
    CaptureTooLargeError,
    NotACaptureError,
)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def reader(payload: bytes) -> Callable[[int], Awaitable[bytes]]:
    """Build an async chunk reader over a bytes payload, like UploadFile.read."""
    state = {"offset": 0}

    async def read(size: int) -> bytes:
        start = state["offset"]
        chunk = payload[start : start + size]
        state["offset"] = start + len(chunk)
        return chunk

    return read


def make_storage(
    tmp_path: Path, *, max_bytes: int = 1024, chunk: int = 8
) -> CaptureStorage:
    """Build storage rooted at a temporary directory."""
    return CaptureStorage(tmp_path, max_bytes=max_bytes, chunk_bytes=chunk)


@pytest.mark.parametrize("magic", [PCAP_MAGIC, PCAPNG_MAGIC])
async def test_accepts_known_capture_formats(tmp_path: Path, magic: bytes) -> None:
    storage = make_storage(tmp_path)
    job_id = uuid4()

    path, size = await storage.save(job_id, reader(magic + b"payload"))

    assert path.read_bytes() == magic + b"payload"
    assert size == len(magic) + len(b"payload")


async def test_streams_across_many_chunks(tmp_path: Path) -> None:
    storage = make_storage(tmp_path, max_bytes=10_000, chunk=4)
    payload = PCAP_MAGIC + bytes(range(256)) * 3

    _, size = await storage.save(uuid4(), reader(payload))

    assert size == len(payload)


async def test_file_is_named_after_the_job_not_the_upload(tmp_path: Path) -> None:
    storage = make_storage(tmp_path)
    job_id = uuid4()

    path, _ = await storage.save(job_id, reader(PCAP_MAGIC))

    assert path == storage.path_for(job_id)
    assert path.parent == tmp_path


async def test_rejects_a_payload_that_is_not_a_capture(tmp_path: Path) -> None:
    storage = make_storage(tmp_path)
    job_id = uuid4()

    with pytest.raises(NotACaptureError):
        await storage.save(job_id, reader(b"PK\x03\x04not a capture"))

    assert not storage.path_for(job_id).exists()


async def test_rejects_an_empty_upload(tmp_path: Path) -> None:
    storage = make_storage(tmp_path)
    job_id = uuid4()

    with pytest.raises(NotACaptureError):
        await storage.save(job_id, reader(b""))

    assert not storage.path_for(job_id).exists()


async def test_rejects_and_removes_an_oversized_upload(tmp_path: Path) -> None:
    storage = make_storage(tmp_path, max_bytes=16, chunk=4)
    job_id = uuid4()

    with pytest.raises(CaptureTooLargeError):
        await storage.save(job_id, reader(PCAP_MAGIC + b"x" * 64))

    assert not storage.path_for(job_id).exists()


async def test_delete_removes_the_file_and_tolerates_a_missing_one(
    tmp_path: Path,
) -> None:
    storage = make_storage(tmp_path)
    job_id = uuid4()
    await storage.save(job_id, reader(PCAP_MAGIC))

    storage.delete(job_id)
    storage.delete(job_id)

    assert not storage.path_for(job_id).exists()
