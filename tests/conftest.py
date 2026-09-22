"""Global pytest fixtures and environment setup."""

import sys

import pytest

# Loopback addresses used to keep asyncio working under network isolation.
LOOPBACK_HOSTS = ["127.0.0.1", "::1"]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """
    Relax pytest-socket to loopback-only isolation on Windows.

    ``--disable-socket`` blocks socket *creation* for every family except
    AF_UNIX. Windows has no AF_UNIX event loop, so asyncio builds its self-pipe
    with ``socket.socketpair()``, which falls back to a loopback TCP pair and
    trips the block before any async test can start.

    Marking every item with ``allow_hosts`` swaps the strategy on Windows only:
    sockets may be created, but ``connect()`` is restricted to loopback, so
    outbound network calls stay blocked. POSIX platforms keep the stricter
    ``--disable-socket`` behaviour untouched.

    Args:
        items: The collected test items for this session.

    """
    if sys.platform != "win32":
        return

    for item in items:
        item.add_marker(pytest.mark.allow_hosts(LOOPBACK_HOSTS))


@pytest.fixture(autouse=True)
def _setup_test_environment() -> None:  # pyright: ignore[reportUnusedFunction]
    """Configure the base hermetic testing environment."""
    # Place any global database resets or mock initializations here
    return
