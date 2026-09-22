"""
Desktop application entry point.

Qt and asyncio each want to own the thread's event loop. ``qasync.QEventLoop``
is an asyncio loop implemented on top of Qt's, so installing it as *the* loop
lets one thread run both: a coroutine can await an HTTP response while Qt keeps
delivering paint and input events. That is what makes the window stay
responsive during an upload without a single worker thread.

On Python 3.11 and newer the loop is installed by passing it to
``asyncio.run`` as ``loop_factory``; ``qasync.run`` is the equivalent for older
interpreters and is not needed here.
"""

import asyncio
import logging
import os
import sys

from ciara_pcap_client import DEFAULT_BASE_URL
from PySide6.QtWidgets import QApplication

# qasync ships no type stubs; pyright uses its inline types instead.
from qasync import QEventLoop  # pyright: ignore[reportMissingTypeStubs]

from ciara_pcap_gui.main_window import MainWindow

API_URL_ENV_VAR = "CIARA_PCAP_API_URL"


async def _run(app: QApplication, api_url: str) -> None:
    """
    Show the main window and keep the loop alive until Qt quits.

    Args:
        app: The Qt application.
        api_url: Backend URL pre-filled in the window.

    """
    # There is no Qt exec() call to block on -- the loop is already running --
    # so the coroutine has to be kept alive by hand until Qt decides to quit.
    closed = asyncio.Event()
    app.aboutToQuit.connect(closed.set)

    # The local reference matters: a top-level window with no Python owner is
    # garbage collected and vanishes the moment this frame drops it.
    window = MainWindow(api_url)
    window.show()

    await closed.wait()


def main() -> None:
    """Start the desktop client."""
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s"
    )
    app = QApplication(sys.argv)
    app.setApplicationName("CIARA PCAP Analyzer")

    api_url = os.environ.get(API_URL_ENV_VAR, DEFAULT_BASE_URL)
    asyncio.run(_run(app, api_url), loop_factory=QEventLoop)


if __name__ == "__main__":
    main()
