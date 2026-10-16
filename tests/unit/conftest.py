"""Fixtures shared by the unit tests."""

import pytest
from PySide6.QtCore import QCoreApplication


@pytest.fixture(scope="session")
def qt_app() -> QCoreApplication:
    """
    One Qt application per test process, created before any model or widget.

    A full ``QApplication`` is used when the Qt widget libraries load, so the
    model tests and the window tests can share a process; otherwise the
    models still get a ``QCoreApplication``.
    """
    existing = QCoreApplication.instance()
    if existing is not None:
        return existing
    try:
        from PySide6.QtWidgets import QApplication  # noqa: PLC0415 - optional
    except ImportError:
        return QCoreApplication([])
    return QApplication([])
