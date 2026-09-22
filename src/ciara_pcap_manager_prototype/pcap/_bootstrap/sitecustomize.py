"""
Startup hook that prepares the packet-capture backend in every subprocess.

``os.add_dll_directory`` only affects the process that calls it, and NFStream
starts metering processes of its own that import the native engine before any
application code runs. Python imports ``sitecustomize`` automatically at
interpreter start-up, so putting this directory on ``PYTHONPATH`` -- which
*is* inherited by every descendant -- makes the fix reach them.

This directory must contain nothing else: it sits on ``PYTHONPATH`` and would
otherwise shadow real modules.
"""

import os
import sys


def _chain_to_shadowed_sitecustomize() -> None:
    """Run any other ``sitecustomize`` this module displaced on ``sys.path``."""
    here = os.path.dirname(os.path.abspath(__file__))
    for entry in sys.path:
        try:
            candidate = os.path.join(os.path.abspath(entry), "sitecustomize.py")
        except (TypeError, ValueError):
            continue
        if os.path.dirname(candidate) == here or not os.path.isfile(candidate):
            continue
        with open(candidate, encoding="utf-8") as handle:
            source = handle.read()
        exec(compile(source, candidate, "exec"), {"__name__": "sitecustomize"})  # noqa: S102
        return


try:
    from ciara_pcap_manager_prototype.pcap.compat import ensure_capture_backend

    ensure_capture_backend()
except Exception:  # noqa: BLE001, S110 - never break interpreter start-up
    pass

try:
    _chain_to_shadowed_sitecustomize()
except Exception:  # noqa: BLE001, S110 - never break interpreter start-up
    pass
