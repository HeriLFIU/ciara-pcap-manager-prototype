"""
Tests for the Typer command line interface.

The workflow helpers are replaced so the CLI's own behaviour -- argument
parsing, exit codes, rendering and the JSON contract -- is what is under test.
"""

import json
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from ciara_pcap_cli import app as cli_module
from ciara_pcap_cli.app import app
from ciara_pcap_client import (
    ApiError,
    format_bytes,
    format_timestamp,
    ranked_applications,
    value_or,
)
from ciara_pcap_sdk.models import AnalysisJob, Flow
from typer.testing import CliRunner

from tests.support.factories import make_flow

JOB_ID = UUID("11111111-2222-3333-4444-555555555555")
EXIT_FAILURE = 1


class FakeClient(AbstractAsyncContextManager["FakeClient"]):
    """Stands in for the SDK client; the workflow helpers are stubbed anyway."""

    async def __aenter__(self) -> "FakeClient":
        """Enter the context."""
        return self

    async def __aexit__(self, *_: object) -> None:
        """Leave the context."""
        return


def sdk_job(status: str = "succeeded", **extra: Any) -> AnalysisJob:  # noqa: ANN401 - JSON
    """Build an SDK job model from a JSON payload."""
    payload: dict[str, Any] = {
        "job_id": str(JOB_ID),
        "status": status,
        "filename": "sample.pcap",
        "size_bytes": 851,
        "created_at": "2026-09-10T12:00:00Z",
        "summary": {
            "flow_count": 2,
            "packet_count": 10,
            "byte_count": 667,
            "first_seen_ms": 1_700_000_000_000,
            "last_seen_ms": 1_700_000_000_090,
            "top_applications": {"HTTP": 1, "DNS": 1},
        },
    } | extra
    return AnalysisJob.from_dict(payload)


def sdk_flows() -> list[Flow]:
    """Build two SDK flow models."""
    return [
        Flow.from_dict(json.loads(make_flow(flow_id=0).model_dump_json())),
        Flow.from_dict(
            json.loads(make_flow(flow_id=1, application_name="DNS").model_dump_json())
        ),
    ]


@pytest.fixture
def runner() -> CliRunner:
    """A Typer runner that keeps stdout and stderr apart."""
    return CliRunner()


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    """A file the CLI's `exists=True` argument check will accept."""
    path = tmp_path / "sample.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1body")
    return path


@pytest.fixture(autouse=True)
def _stub_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the SDK client factory for every test in this module."""

    def factory(*_: object, **__: object) -> FakeClient:
        return FakeClient()

    monkeypatch.setattr(cli_module, "build_client", factory)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("COLUMNS", "200")


def stub(
    monkeypatch: pytest.MonkeyPatch, name: str, result: Callable[..., Any]
) -> None:
    """Replace one workflow helper on the CLI module."""

    async def fake(*args: object, **kwargs: object) -> Any:  # noqa: ANN401 - passthrough
        return result(*args, **kwargs)

    monkeypatch.setattr(cli_module, name, fake)


def test_health_reports_a_reachable_backend(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Health:
        status = "ok"
        service = "ciara-pcap-api"

    stub(monkeypatch, "check_health", lambda *_, **__: Health())

    result = runner.invoke(app, ["health", "--api-url", "http://backend"])

    assert result.exit_code == 0
    assert "ok" in result.stdout


def test_health_fails_loudly_when_the_backend_is_down(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_: object, **__: object) -> Any:  # noqa: ANN401 - passthrough
        raise ApiError("connection refused")

    stub(monkeypatch, "check_health", explode)

    result = runner.invoke(app, ["health"])

    assert result.exit_code == EXIT_FAILURE


def test_analyze_prints_a_table_of_flows(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, capture: Path
) -> None:
    stub(monkeypatch, "analyze_capture", lambda *_, **__: (sdk_job(), sdk_flows()))

    result = runner.invoke(
        app, ["analyze", str(capture)], env={"COLUMNS": "200", "TERM": "xterm"}
    )

    assert result.exit_code == 0
    assert "10.0.0.1:5001" in result.stdout
    assert "HTTP" in result.stdout
    assert "DNS" in result.stdout


def test_analyze_emits_machine_readable_json(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, capture: Path
) -> None:
    stub(monkeypatch, "analyze_capture", lambda *_, **__: (sdk_job(), sdk_flows()))

    result = runner.invoke(app, ["analyze", str(capture), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["job"]["filename"] == "sample.pcap"
    assert [flow["flow_id"] for flow in payload["flows"]] == [0, 1]


def test_analyze_limit_truncates_the_table(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, capture: Path
) -> None:
    stub(monkeypatch, "analyze_capture", lambda *_, **__: (sdk_job(), sdk_flows()))

    result = runner.invoke(
        app, ["analyze", str(capture), "--limit", "1"], env={"COLUMNS": "200"}
    )

    assert result.exit_code == 0
    assert "Flows (1 of 2)" in result.stdout


def test_analyze_reports_a_failed_job_as_a_non_zero_exit(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, capture: Path
) -> None:
    stub(
        monkeypatch,
        "analyze_capture",
        lambda *_, **__: (sdk_job("failed", error="engine exploded"), []),
    )

    result = runner.invoke(app, ["analyze", str(capture)])

    assert result.exit_code == EXIT_FAILURE


def test_analyze_rejects_a_missing_file(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", str(tmp_path / "nope.pcap")])

    assert result.exit_code != 0


def test_jobs_lists_known_jobs(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub(monkeypatch, "fetch_jobs", lambda *_, **__: [sdk_job()])

    result = runner.invoke(app, ["jobs"], env={"COLUMNS": "200", "TERM": "xterm"})

    assert result.exit_code == 0
    assert "sample.pcap" in result.stdout


def test_jobs_says_so_when_there_are_none(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub(monkeypatch, "fetch_jobs", lambda *_, **__: [])

    result = runner.invoke(app, ["jobs"])

    assert result.exit_code == 0
    assert "No analysis jobs yet." in result.stdout


def test_flows_renders_an_existing_job(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub(monkeypatch, "get_job", lambda *_, **__: sdk_job())
    stub(monkeypatch, "fetch_all_flows", lambda *_, **__: sdk_flows())

    result = runner.invoke(
        app, ["flows", str(JOB_ID)], env={"COLUMNS": "200", "TERM": "xterm"}
    )

    assert result.exit_code == 0
    assert "Flows (2 of 2)" in result.stdout


def test_flows_rejects_a_malformed_job_id(runner: CliRunner) -> None:
    result = runner.invoke(app, ["flows", "not-a-uuid"])

    assert result.exit_code != 0


@pytest.mark.parametrize(
    ("count", "expected"),
    [(0, "0 B"), (512, "512 B"), (2048, "2.0 KB"), (5 * 1024 * 1024, "5.0 MB")],
)
def test_byte_formatting(count: int, expected: str) -> None:
    assert format_bytes(count) == expected


def test_timestamp_formatting_is_utc_with_milliseconds() -> None:
    assert format_timestamp(1_700_000_000_090) == "2023-11-14 22:13:20.090"


def test_top_applications_of_a_summariless_job_is_empty() -> None:
    job = sdk_job(summary={"flow_count": 0, "packet_count": 0, "byte_count": 0})

    summary = value_or(job.summary, None)
    assert summary is not None
    assert ranked_applications(summary) == []
