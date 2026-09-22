r"""
Packet-capture backend discovery.

NFStream's C engine links against ``libpcap``. On Windows that is supplied by
Npcap, which installs ``wpcap.dll`` into ``%SystemRoot%\System32\Npcap``
rather than ``System32`` itself. Machines that once had WinPcap still carry a
2013-era ``System32\wpcap.dll``, and because that directory is searched first
the engine binds to the old library and fails at import time with::

    ImportError: DLL load failed while importing _lib_engine:
    The specified procedure could not be found.

Prepending the Npcap directory to the DLL search path resolves the ambiguity.
This must happen before ``nfstream`` is imported for the first time.
"""

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

#: Overrides discovery when Npcap lives somewhere non-standard.
NPCAP_DIR_ENV_VAR = "CIARA_PCAP_NPCAP_DIR"

_LIBPCAP_DLL = "wpcap.dll"
_prepared = False


def candidate_directories() -> list[Path]:
    """
    Build the ordered list of directories that may hold ``wpcap.dll``.

    Returns:
        Candidate directories, most authoritative first.

    """
    candidates: list[Path] = []

    override = os.environ.get(NPCAP_DIR_ENV_VAR)
    if override:
        candidates.append(Path(override))

    system_root_env = (
        os.environ.get("SYSTEMROOT")
        or os.environ.get("SystemRoot")  # noqa: SIM112 - case-sensitive POSIX support
        or r"C:\Windows"
    )
    system_root = Path(system_root_env)
    candidates.append(system_root / "System32" / "Npcap")
    candidates.append(system_root / "SysWOW64" / "Npcap")
    candidates.append(Path(r"C:\Program Files\Npcap"))

    return candidates


def propagate_to_subprocesses(directory: Path) -> None:
    """
    Arrange for descendant interpreters to apply the same fix.

    ``os.add_dll_directory`` is process-local, but NFStream spawns metering
    processes that import the native engine before any of our code runs. The
    environment *is* inherited, so the discovered directory is pinned into it
    and a ``sitecustomize`` bootstrap is placed on ``PYTHONPATH``; CPython
    imports that module automatically at interpreter start-up.

    Args:
        directory: The directory holding a usable ``wpcap.dll``.

    """
    os.environ[NPCAP_DIR_ENV_VAR] = str(directory)

    bootstrap = str(Path(__file__).parent / "_bootstrap")
    existing = os.environ.get("PYTHONPATH", "")
    entries = [entry for entry in existing.split(os.pathsep) if entry]
    if bootstrap not in entries:
        os.environ["PYTHONPATH"] = os.pathsep.join([bootstrap, *entries])


def ensure_capture_backend() -> None:
    """
    Make the platform packet-capture library importable by the NFStream engine.

    The call is idempotent and a no-op on every platform except Windows, where
    ``libpcap`` is provided by Npcap in a directory that is not on the default
    DLL search path.
    """
    global _prepared  # noqa: PLW0603 - module-level idempotency latch
    if _prepared or sys.platform != "win32":
        _prepared = True
        return

    for directory in candidate_directories():
        if not (directory / _LIBPCAP_DLL).is_file():
            continue
        os.add_dll_directory(str(directory))
        propagate_to_subprocesses(directory)
        logger.debug("Added %s to the DLL search path for NFStream.", directory)
        _prepared = True
        return

    logger.warning(
        "Npcap was not found in any known location. NFStream will fall back to "
        "whatever %s the loader finds first, which may be an incompatible "
        "WinPcap build. Install Npcap or set %s.",
        _LIBPCAP_DLL,
        NPCAP_DIR_ENV_VAR,
    )
    _prepared = True
