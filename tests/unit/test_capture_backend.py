"""
Tests for the packet-capture backend discovery shim.

The shim exists because a Windows host with a legacy WinPcap installation
loads the wrong ``wpcap.dll`` and NFStream's engine then fails to import. These
tests drive the discovery logic on every platform by faking the filesystem, so
the behaviour is pinned even where Npcap is irrelevant.
"""

import os
import sys
from pathlib import Path

import pytest

from ciara_pcap_manager_prototype.pcap import compat


@pytest.fixture(autouse=True)
def _reset_latch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear the module's idempotency latch around every test."""
    monkeypatch.setattr(compat, "_prepared", False)


def test_the_override_environment_variable_is_searched_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(compat.NPCAP_DIR_ENV_VAR, r"X:\custom\npcap")

    assert compat.candidate_directories()[0] == Path(r"X:\custom\npcap")


def test_the_standard_npcap_locations_are_searched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(compat.NPCAP_DIR_ENV_VAR, raising=False)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")

    candidates = compat.candidate_directories()

    assert any(path.parts[-2:] == ("System32", "Npcap") for path in candidates)
    assert any(path.parts[-2:] == ("SysWOW64", "Npcap") for path in candidates)


def test_propagation_pins_the_directory_and_the_bootstrap_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv(compat.NPCAP_DIR_ENV_VAR, raising=False)

    compat.propagate_to_subprocesses(tmp_path)

    assert os.environ[compat.NPCAP_DIR_ENV_VAR] == str(tmp_path)
    first_entry = os.environ["PYTHONPATH"].split(os.pathsep)[0]
    assert Path(first_entry).name == "_bootstrap"
    assert (Path(first_entry) / "sitecustomize.py").is_file()


def test_propagation_preserves_an_existing_python_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PYTHONPATH", "/already/here")

    compat.propagate_to_subprocesses(tmp_path)

    assert os.environ["PYTHONPATH"].split(os.pathsep)[-1] == "/already/here"


def test_propagation_does_not_duplicate_the_bootstrap_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("PYTHONPATH", raising=False)

    compat.propagate_to_subprocesses(tmp_path)
    compat.propagate_to_subprocesses(tmp_path)

    entries = os.environ["PYTHONPATH"].split(os.pathsep)
    assert len(entries) == len(set(entries))


def test_preparation_only_searches_once(monkeypatch: pytest.MonkeyPatch) -> None:
    searches = 0

    def counted() -> list[Path]:
        nonlocal searches
        searches += 1
        return []

    monkeypatch.setattr(compat, "candidate_directories", counted)

    compat.ensure_capture_backend()
    compat.ensure_capture_backend()
    compat.ensure_capture_backend()

    assert searches <= 1


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has real work to do")
def test_preparation_is_a_no_op_away_from_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PYTHONPATH", raising=False)

    compat.ensure_capture_backend()

    assert "PYTHONPATH" not in os.environ


def test_a_missing_npcap_warns_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    if sys.platform != "win32":
        pytest.skip("The warning path only exists on Windows")
    monkeypatch.setattr(compat, "candidate_directories", lambda: [tmp_path])

    with caplog.at_level("WARNING"):
        compat.ensure_capture_backend()

    assert "Npcap was not found" in caplog.text
