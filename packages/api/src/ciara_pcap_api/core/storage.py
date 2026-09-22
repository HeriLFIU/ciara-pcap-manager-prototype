"""
Streaming capture storage.

An uploaded capture is written to disk in bounded chunks and never held in
memory in full: a multi-gigabyte PCAP would otherwise take the API process
down. Files are named after the job that owns them, so a hostile
``filename`` can never influence a path on disk.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Final
from uuid import UUID

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

#: Magic numbers identifying a capture file, in the order they appear on disk.
#: Classic libpcap uses four byte orders (second and nanosecond resolution);
#: pcapng always begins with a Section Header Block.
_CAPTURE_MAGICS: Final[tuple[bytes, ...]] = (
    b"\xa1\xb2\xc3\xd4",  # libpcap, big endian, microseconds
    b"\xd4\xc3\xb2\xa1",  # libpcap, little endian, microseconds
    b"\xa1\xb2\x3c\x4d",  # libpcap, big endian, nanoseconds
    b"\x4d\x3c\xb2\xa1",  # libpcap, little endian, nanoseconds
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
)

_MAGIC_LENGTH: Final = 4


class CaptureTooLargeError(ValueError):
    """Raised when an upload exceeds the configured size limit."""


class NotACaptureError(ValueError):
    """Raised when an upload does not begin with a known capture magic number."""


class CaptureStorage:
    """Writes uploaded captures into a flat, job-addressed directory."""

    def __init__(
        self,
        directory: Path,
        *,
        max_bytes: int,
        chunk_bytes: int,
    ) -> None:
        """
        Configure capture storage.

        Args:
            directory: Directory that captures are written into.
            max_bytes: Largest upload accepted, in bytes.
            chunk_bytes: Read granularity while streaming an upload.

        """
        self._directory = directory
        self._max_bytes = max_bytes
        self._chunk_bytes = chunk_bytes

    def path_for(self, job_id: UUID) -> Path:
        """
        Return the on-disk location of a job's capture.

        Args:
            job_id: Identifier of the owning job.

        Returns:
            The capture path. The file may not exist yet.

        """
        return self._directory / f"{job_id}.pcap"

    async def save(
        self,
        job_id: UUID,
        read_chunk: "Callable[[int], Awaitable[bytes]]",
    ) -> tuple[Path, int]:
        """
        Stream an upload to disk, validating it as the first chunk arrives.

        Args:
            job_id: Identifier of the job the capture belongs to.
            read_chunk: Awaitable returning up to ``n`` bytes, or ``b""`` at EOF.
                This is :meth:`starlette.datastructures.UploadFile.read`.

        Returns:
            The path written and the number of bytes it holds.

        Raises:
            CaptureTooLargeError: If the upload exceeds the configured limit.
            NotACaptureError: If the leading bytes are not a capture magic number.

        """
        destination = self.path_for(job_id)
        written = 0
        checked = False

        try:
            with destination.open("wb") as handle:
                while chunk := await read_chunk(self._chunk_bytes):
                    if not checked:
                        self._reject_non_capture(chunk)
                        checked = True

                    written += len(chunk)
                    self._reject_oversized(written)
                    handle.write(chunk)
        except (CaptureTooLargeError, NotACaptureError):
            destination.unlink(missing_ok=True)
            raise

        if not checked:
            destination.unlink(missing_ok=True)
            msg = "Capture file is empty."
            raise NotACaptureError(msg)

        logger.info("Stored %d bytes for job %s at %s", written, job_id, destination)
        return destination, written

    def delete(self, job_id: UUID) -> None:
        """
        Remove a job's capture from disk if it is still present.

        Args:
            job_id: Identifier of the owning job.

        """
        self.path_for(job_id).unlink(missing_ok=True)

    def _reject_oversized(self, written: int) -> None:
        """
        Stop an upload that has grown past the configured limit.

        Args:
            written: Bytes accepted so far.

        Raises:
            CaptureTooLargeError: If the limit has been exceeded.

        """
        if written <= self._max_bytes:
            return
        msg = f"Capture exceeds the {self._max_bytes} byte upload limit."
        raise CaptureTooLargeError(msg)

    @staticmethod
    def _reject_non_capture(first_chunk: bytes) -> None:
        """
        Validate the leading bytes of an upload.

        Args:
            first_chunk: The first chunk read from the upload.

        Raises:
            NotACaptureError: If no known capture magic number is present.

        """
        header = first_chunk[:_MAGIC_LENGTH]
        if header in _CAPTURE_MAGICS:
            return
        msg = (
            "Upload is not a libpcap or pcapng capture "
            f"(unexpected magic number {header.hex()})."
        )
        raise NotACaptureError(msg)
