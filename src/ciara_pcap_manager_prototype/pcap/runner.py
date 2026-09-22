"""
Bridge between the asyncio world and CPU-bound NFStream extraction.

Extraction runs in a dedicated worker process per capture, which keeps four
promises:

* the ASGI event loop never blocks while a capture is parsed;
* a crash inside the native nDPI engine is reported, not inherited;
* a capture that makes NFStream hang is killed rather than pinning a job in
  ``running`` for ever;
* the call site is already shaped like a task queue, so replacing this runner
  with Celery or arq later is a change of implementation, not of contract.

``concurrent.futures.ProcessPoolExecutor`` cannot provide the third promise --
it offers no way to time out or terminate an individual worker -- so the
worker process is managed directly.
"""

import asyncio
import logging
import multiprocessing
import queue
import time
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from ciara_pcap_manager_prototype.pcap.compat import ensure_capture_backend
from ciara_pcap_manager_prototype.pcap.extractor import (
    PcapExtractionError,
    extract_flows,
)

if TYPE_CHECKING:
    from multiprocessing.context import SpawnProcess
    from multiprocessing.queues import Queue

    from ciara_pcap_manager_prototype.domain.flows import Flow

logger = logging.getLogger(__name__)

#: How often the parent checks on a worker while waiting for its result.
_POLL_SECONDS = 0.2

#: Grace period for draining the result queue after a worker exits.
_DRAIN_SECONDS = 1.0


def _worker(
    result_queue: "Queue[tuple[str, object]]",
    pcap_path: Path,
    n_dissections: int,
    max_flows: int,
) -> None:
    """
    Extract flows in a worker process and post the outcome back.

    Args:
        result_queue: Channel used to return the outcome to the parent.
        pcap_path: Capture to parse.
        n_dissections: Packets per flow handed to nDPI.
        max_flows: Cap on flows produced. Zero means no limit.

    """
    ensure_capture_backend()
    try:
        flows = extract_flows(
            pcap_path, n_dissections=n_dissections, max_flows=max_flows
        )
    except Exception as exc:  # noqa: BLE001 - the parent turns this into a job error
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))
    else:
        result_queue.put(("ok", flows))


class FlowExtractor(Protocol):
    """
    What a caller needs from an extraction backend.

    The API depends on this rather than on :class:`FlowExtractionRunner`, so a
    Celery-backed or arq-backed implementation is a drop-in replacement and a
    test can supply a stub without touching NFStream.
    """

    async def extract(self, pcap_path: Path) -> list["Flow"]:
        """
        Extract the flows of a capture.

        Args:
            pcap_path: Path to the capture file to parse.

        Returns:
            Every flow the capture produced.

        """
        ...

    def shutdown(self, *, wait: bool = True) -> None:
        """
        Release any resources the extractor holds.

        Args:
            wait: Block until in-flight work finishes.

        """
        ...


class FlowExtractionRunner:
    """Runs capture extraction in isolated, time-limited worker processes."""

    def __init__(
        self,
        *,
        max_workers: int = 2,
        n_dissections: int = 20,
        max_flows: int = 0,
        timeout_seconds: float = 300.0,
    ) -> None:
        """
        Configure the runner.

        Args:
            max_workers: Number of extractions allowed to run concurrently.
            n_dissections: Packets per flow handed to nDPI.
            max_flows: Cap on flows per capture. Zero means no limit.
            timeout_seconds: Kill a worker that has not finished in this long.

        """
        self._n_dissections = n_dissections
        self._max_flows = max_flows
        self._timeout = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_workers)
        # "spawn" everywhere rather than the platform default: forking a process
        # that already owns an event loop and native threads is unsafe, and
        # NFStream starts metering processes of its own on top of this one.
        self._context = multiprocessing.get_context("spawn")

    async def extract(self, pcap_path: Path) -> list["Flow"]:
        """
        Extract the flows of a capture without blocking the event loop.

        Args:
            pcap_path: Path to the capture file to parse.

        Returns:
            Every flow NFStream produced for the capture.

        Raises:
            PcapExtractionError: If the worker failed, timed out or died.

        """
        async with self._semaphore:
            return await asyncio.to_thread(self._extract_blocking, pcap_path)

    def _extract_blocking(self, pcap_path: Path) -> list["Flow"]:
        """
        Run one extraction in a worker process and wait for its result.

        Args:
            pcap_path: Path to the capture file to parse.

        Returns:
            Every flow NFStream produced for the capture.

        Raises:
            PcapExtractionError: If the worker failed, timed out or died.

        """
        result_queue: Queue[tuple[str, object]] = self._context.Queue()
        process: SpawnProcess = self._context.Process(
            target=_worker,
            args=(result_queue, pcap_path, self._n_dissections, self._max_flows),
            daemon=False,
        )
        process.start()
        logger.debug("Worker %s parsing %s", process.pid, pcap_path.name)

        try:
            kind, payload = self._await_outcome(process, result_queue, pcap_path)
        finally:
            self._reap(process)
            result_queue.close()

        if kind == "error":
            msg = str(payload)
            raise PcapExtractionError(msg)
        if not isinstance(payload, list):
            msg = f"Extraction worker returned {type(payload).__name__}, not a list."
            raise PcapExtractionError(msg)
        return cast("list[Flow]", payload)

    def _await_outcome(
        self,
        process: "SpawnProcess",
        result_queue: "Queue[tuple[str, object]]",
        pcap_path: Path,
    ) -> tuple[str, object]:
        """
        Wait for a worker to post its outcome, enforcing the timeout.

        Args:
            process: The running worker.
            result_queue: Channel the worker posts its outcome on.
            pcap_path: Capture being parsed, used for error messages.

        Returns:
            The outcome pair the worker produced.

        Raises:
            PcapExtractionError: If the worker timed out or died silently.

        """
        deadline = time.monotonic() + self._timeout

        while True:
            try:
                return result_queue.get(timeout=_POLL_SECONDS)
            except queue.Empty:
                pass

            if not process.is_alive():
                # The worker may have exited immediately after posting; give the
                # feeder thread of the queue a moment to flush before giving up.
                try:
                    return result_queue.get(timeout=_DRAIN_SECONDS)
                except queue.Empty:
                    msg = (
                        f"Extraction worker for {pcap_path.name} exited with code "
                        f"{process.exitcode} without returning a result. On Windows "
                        "this usually means the Npcap runtime could not be loaded."
                    )
                    raise PcapExtractionError(msg) from None

            if time.monotonic() >= deadline:
                msg = (
                    f"Extraction of {pcap_path.name} exceeded the "
                    f"{self._timeout:.0f}s limit and was cancelled."
                )
                raise PcapExtractionError(msg)

    @staticmethod
    def _reap(process: "SpawnProcess") -> None:
        """
        Ensure a worker process is gone before returning.

        Args:
            process: The worker to reap.

        """
        if process.is_alive():
            process.terminate()
        process.join(timeout=_DRAIN_SECONDS)
        if process.is_alive():
            process.kill()
            process.join(timeout=_DRAIN_SECONDS)
        process.close()

    def shutdown(self, *, wait: bool = True) -> None:
        """
        Release runner resources.

        Workers are owned by individual extractions, so there is no pool to
        drain; the method exists so callers need not know that.

        Args:
            wait: Accepted for interface compatibility; ignored.

        """
        logger.debug("Extraction runner shut down (wait=%s)", wait)
