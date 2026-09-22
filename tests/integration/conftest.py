"""
Guards for the tests that drive the real NFStream engine.

NFStream starts ``multiprocessing`` worker processes. Inside a ``pytest-xdist``
worker those inherit the execnet stdio channel the worker uses to talk to the
controller, and the controller then loses the node:

    [gw0] node down: Not properly terminated
    worker 'gw0' crashed while running ...

The failure is in the test harness, not in the code under test: the same tests
pass consistently with ``-n 0``. Rather than leave a flaky suite, they are
skipped with a visible reason whenever xdist is in play.
"""

import pytest

SKIP_REASON = (
    "NFStream's worker processes destabilise pytest-xdist workers. "
    "Run these with: uv run pytest tests/integration -n 0"
)


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """
    Skip capture-backend tests when the session is distributed across workers.

    Args:
        config: The active pytest configuration.
        items: The collected test items.

    """
    if not hasattr(config, "workerinput"):
        return

    skip = pytest.mark.skip(reason=SKIP_REASON)
    for item in items:
        if item.get_closest_marker("capture_backend") is not None:
            item.add_marker(skip)
