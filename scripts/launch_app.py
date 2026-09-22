"""
Supervisor script to launch both the backend API and the desktop GUI.

Monitors the backend until /api/v1/health responds, then launches the
PySide6 GUI. When the user closes the GUI, tears down the backend process
and all descendant processes.
"""

from __future__ import annotations

import logging
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import FrameType

HEALTH_URL = "http://127.0.0.1:8000/api/v1/health"
STARTUP_TIMEOUT_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.25

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ciara_pcap.launcher")


def _terminate_process_tree(proc: subprocess.Popen[bytes] | None) -> None:
    """Terminate the process and all of its descendants."""
    if proc is None or proc.poll() is not None:
        return

    logger.info("Stopping backend process (PID %d)...", proc.pid)
    if sys.platform == "win32":
        taskkill_bin = shutil.which("taskkill") or r"C:\Windows\System32\taskkill.exe"
        try:
            subprocess.run(  # noqa: S603
                [taskkill_bin, "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            logger.warning("taskkill failed: %s", exc)
    else:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    logger.info("Backend stopped.")


def _wait_for_backend(
    proc: subprocess.Popen[bytes],
    timeout: float = STARTUP_TIMEOUT_SECONDS,
) -> bool:
    """Poll the backend health endpoint until it answers or times out."""
    start_time = time.monotonic()
    if not HEALTH_URL.startswith(("http://", "https://")):
        msg = f"Invalid health URL scheme: {HEALTH_URL}"
        raise ValueError(msg)

    while time.monotonic() - start_time < timeout:
        if proc.poll() is not None:
            logger.error(
                "Backend process exited prematurely with code %d.", proc.returncode
            )
            return False

        try:
            req = urllib.request.Request(
                HEALTH_URL, headers={"User-Agent": "CIARA-Launcher"}
            )
            with urllib.request.urlopen(req, timeout=1.0) as resp:  # noqa: S310
                if resp.status == HTTPStatus.OK:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

        time.sleep(POLL_INTERVAL_SECONDS)

    logger.error(
        "Timed out after %.1f seconds waiting for backend at %s.", timeout, HEALTH_URL
    )
    return False


def main() -> int:
    """Run the supervisor lifecycle."""
    repo_root = Path(__file__).resolve().parent.parent
    backend_proc: subprocess.Popen[bytes] | None = None

    def handle_signal(_signum: int, _frame: FrameType | None) -> None:
        _terminate_process_tree(backend_proc)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    sigbreak: object = getattr(signal, "SIGBREAK", None)
    if isinstance(sigbreak, int):
        signal.signal(sigbreak, handle_signal)

    try:
        logger.info("Starting CIARA PCAP Backend API...")
        backend_proc = subprocess.Popen(
            [sys.executable, "-m", "ciara_pcap_api"],
            cwd=str(repo_root),
        )

        logger.info("Waiting for backend to be ready...")
        if not _wait_for_backend(backend_proc):
            logger.error("Backend failed to initialize.")
            return 1

        logger.info("Backend is ready. Launching CIARA PCAP Analyzer GUI...")
        gui_result = subprocess.run(
            [sys.executable, "-m", "ciara_pcap_gui"],
            cwd=str(repo_root),
            check=False,
        )

        logger.info("GUI closed (exit code %d).", gui_result.returncode)
        return gui_result.returncode

    finally:
        _terminate_process_tree(backend_proc)
        logger.info("All processes cleaned up.")


if __name__ == "__main__":
    sys.exit(main())
