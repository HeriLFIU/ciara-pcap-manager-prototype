"""
The ``ciara-pcap`` command line interface.

Every network call goes through the generated SDK by way of
:mod:`ciara_pcap_client`, so the CLI cannot drift from the backend contract:
if an endpoint changes, regenerating the SDK breaks this file at type-check
time rather than in production.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated, NoReturn
from uuid import UUID

import typer
from ciara_pcap_client import (
    DEFAULT_BASE_URL,
    ApiError,
    analyze_capture,
    build_client,
    check_health,
    fetch_all_flows,
    get_job,
    ranked_applications,
)
from ciara_pcap_client import list_jobs as fetch_jobs
from ciara_pcap_sdk.models import AnalysisJob, Flow
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ciara_pcap_cli.rendering import (
    flows_table,
    jobs_table,
    status_text,
    summary_table,
)

app = typer.Typer(
    name="ciara-pcap",
    help="Analyse offline packet captures through the CIARA PCAP API.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
error_console = Console(stderr=True)

ApiUrlOption = Annotated[
    str,
    typer.Option(
        "--api-url",
        envvar="CIARA_PCAP_API_URL",
        help="Base URL of the backend.",
    ),
]
JsonOption = Annotated[
    bool,
    typer.Option("--json", help="Emit machine-readable JSON instead of a table."),
]


@app.callback()
def configure(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Log SDK and HTTP activity.")
    ] = False,
) -> None:
    """
    Configure logging for the whole command line application.

    Args:
        verbose: Enable debug logging.

    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


@app.command()
def health(api_url: ApiUrlOption = DEFAULT_BASE_URL) -> None:
    """
    Check that the backend is reachable.

    Args:
        api_url: Base URL of the backend.

    """
    asyncio.run(_health(api_url))


@app.command()
def analyze(
    pcap: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            help="The .pcap or .pcapng file to analyse.",
        ),
    ],
    api_url: ApiUrlOption = DEFAULT_BASE_URL,
    as_json: JsonOption = False,
    limit: Annotated[
        int,
        typer.Option("--limit", min=0, help="Rows to print. 0 prints every flow."),
    ] = 50,
    timeout: Annotated[
        float, typer.Option("--timeout", min=1, help="Seconds to wait for the job.")
    ] = 600.0,
) -> None:
    """
    Upload a capture, wait for the analysis and print the flow metadata.

    Args:
        pcap: The capture file to analyse.
        api_url: Base URL of the backend.
        as_json: Emit JSON instead of a table.
        limit: Maximum rows to print, or 0 for all of them.
        timeout: Seconds to wait for the job to finish.

    """
    asyncio.run(_analyze(pcap, api_url, as_json=as_json, limit=limit, timeout=timeout))


@app.command(name="jobs")
def list_jobs(
    api_url: ApiUrlOption = DEFAULT_BASE_URL, as_json: JsonOption = False
) -> None:
    """
    List the analysis jobs the backend knows about.

    Args:
        api_url: Base URL of the backend.
        as_json: Emit JSON instead of a table.

    """
    asyncio.run(_list_jobs(api_url, as_json=as_json))


@app.command()
def flows(
    job_id: Annotated[UUID, typer.Argument(help="A job id returned by `analyze`.")],
    api_url: ApiUrlOption = DEFAULT_BASE_URL,
    as_json: JsonOption = False,
    limit: Annotated[
        int, typer.Option("--limit", min=0, help="Rows to print. 0 prints every flow.")
    ] = 50,
) -> None:
    """
    Print the flows of a job that has already been analysed.

    Args:
        job_id: The job to read.
        api_url: Base URL of the backend.
        as_json: Emit JSON instead of a table.
        limit: Maximum rows to print, or 0 for all of them.

    """
    asyncio.run(_flows(job_id, api_url, as_json=as_json, limit=limit))


async def _health(api_url: str) -> None:
    """
    Print the backend health payload.

    Args:
        api_url: Base URL of the backend.

    """
    async with build_client(api_url) as client:
        try:
            payload = await check_health(client)
        except (ApiError, OSError) as exc:
            _fail(f"{api_url} is not reachable: {exc}")
        console.print(f"[green]{payload.status}[/green]  {payload.service}  {api_url}")


async def _analyze(
    pcap: Path, api_url: str, *, as_json: bool, limit: int, timeout: float
) -> None:
    """
    Run the full analysis workflow and print the result.

    Args:
        pcap: The capture file to analyse.
        api_url: Base URL of the backend.
        as_json: Emit JSON instead of a table.
        limit: Maximum rows to print, or 0 for all of them.
        timeout: Seconds to wait for the job to finish.

    """
    async with build_client(api_url) as client:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            console=console,
            transient=True,
            disable=as_json,
        )
        with progress:
            task = progress.add_task(f"Uploading {pcap.name}", total=None)

            def on_update(job: AnalysisJob) -> None:
                progress.update(task, description=f"Job {job.job_id} is {job.status}")

            def on_page(loaded: int, total: int) -> None:
                progress.update(task, description=f"Fetched {loaded}/{total} flows")

            try:
                job, extracted = await analyze_capture(
                    client,
                    pcap,
                    timeout=timeout,
                    on_update=on_update,
                    on_page=on_page,
                )
            except (ApiError, OSError) as exc:
                _fail(str(exc))

    if job.status != "succeeded":
        _fail(f"Analysis failed: {job.error or 'the backend gave no detail'}")

    _render(job, extracted, as_json=as_json, limit=limit)


async def _list_jobs(api_url: str, *, as_json: bool) -> None:
    """
    Print every known job.

    Args:
        api_url: Base URL of the backend.
        as_json: Emit JSON instead of a table.

    """
    async with build_client(api_url) as client:
        try:
            jobs = await fetch_jobs(client)
        except (ApiError, OSError) as exc:
            _fail(str(exc))

    if as_json:
        console.print_json(json.dumps([job.to_dict() for job in jobs]))
        return
    if not jobs:
        console.print("[dim]No analysis jobs yet.[/dim]")
        return
    console.print(jobs_table(jobs))


async def _flows(job_id: UUID, api_url: str, *, as_json: bool, limit: int) -> None:
    """
    Print the flows of an existing job.

    Args:
        job_id: The job to read.
        api_url: Base URL of the backend.
        as_json: Emit JSON instead of a table.
        limit: Maximum rows to print, or 0 for all of them.

    """
    async with build_client(api_url) as client:
        try:
            job = await get_job(client, job_id)
            extracted = await fetch_all_flows(client, job_id)
        except (ApiError, OSError) as exc:
            _fail(str(exc))

    _render(job, extracted, as_json=as_json, limit=limit)


def _render(
    job: AnalysisJob, extracted: list[Flow], *, as_json: bool, limit: int
) -> None:
    """
    Print a job and its flows in the requested format.

    Args:
        job: The terminal job.
        extracted: The flows the job produced.
        as_json: Emit JSON instead of a table.
        limit: Maximum rows to print, or 0 for all of them.

    """
    if as_json:
        console.print_json(
            json.dumps(
                {
                    "job": job.to_dict(),
                    "flows": [flow.to_dict() for flow in extracted],
                }
            )
        )
        return

    console.print()
    console.print(f"[bold]{job.filename}[/bold]  ", status_text(str(job.status)))
    if job.summary:
        console.print(summary_table(job.summary))

    shown = extracted if limit == 0 else extracted[:limit]
    console.print()
    console.print(flows_table(shown, title=f"Flows ({len(shown)} of {len(extracted)})"))
    if len(shown) < len(extracted):
        console.print(
            f"[dim]Showing {len(shown)} of {len(extracted)} flows. "
            f"Use --limit 0 for all, or --json to pipe them.[/dim]"
        )
    if job.summary and not ranked_applications(job.summary):
        console.print("[dim]nDPI reported no application labels.[/dim]")


def _fail(message: str) -> NoReturn:
    """
    Print an error and abort with a non-zero exit code.

    Args:
        message: The message to show the user.

    Raises:
        typer.Exit: Always.

    """
    error_console.print(f"[bold red]error:[/bold red] {message}")
    raise typer.Exit(code=1)
