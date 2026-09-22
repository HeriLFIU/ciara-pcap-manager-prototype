"""
Application factory and lifespan.

Everything expensive — the capture directory, the job store and the worker
pool — is created once per process in the lifespan and published on
``app.state``, where :mod:`ciara_pcap_api.api.deps` picks it up.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.routing import APIRoute
from starlette.middleware.cors import CORSMiddleware

from ciara_pcap_api.api.main import api_router
from ciara_pcap_api.core.config import ApiSettings, get_settings
from ciara_pcap_api.core.storage import CaptureStorage
from ciara_pcap_api.services.analysis import AnalysisService
from ciara_pcap_manager_prototype.jobs.memory import InMemoryJobStore
from ciara_pcap_manager_prototype.pcap.runner import FlowExtractionRunner

logger = logging.getLogger(__name__)


def custom_generate_unique_id(route: APIRoute) -> str:
    """
    Derive a readable OpenAPI ``operationId`` from the endpoint function name.

    FastAPI's default identifiers embed the path and method, which the SDK
    generator turns into names like ``upload_capture_api_v1_captures_post``.
    Using the function name alone keeps the generated client idiomatic. The
    cost is that endpoint function names must stay unique across the whole
    application, because OpenAPI requires globally unique operation ids.

    Args:
        route: The route being registered.

    Returns:
        The operation id to publish in the schema.

    """
    return route.name


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """
    Build and tear down the application's long-lived collaborators.

    Args:
        app: The application being started.

    Yields:
        Control, while the application serves requests.

    """
    settings: ApiSettings = app.state.settings
    directory = settings.ensure_storage_dir()
    logger.info("Storing uploaded captures in %s", directory)

    service = AnalysisService(
        store=InMemoryJobStore(),
        storage=CaptureStorage(
            directory,
            max_bytes=settings.max_upload_bytes,
            chunk_bytes=settings.upload_chunk_bytes,
        ),
        runner=FlowExtractionRunner(
            max_workers=settings.extraction_workers,
            n_dissections=settings.n_dissections,
            max_flows=settings.max_flows_per_capture,
            timeout_seconds=settings.extraction_timeout_seconds,
        ),
    )
    app.state.analysis_service = service
    try:
        yield
    finally:
        await service.aclose()


def create_app(settings: ApiSettings | None = None) -> FastAPI:
    """
    Build the FastAPI application.

    Args:
        settings: Overrides the environment-derived settings. Tests use this.

    Returns:
        The configured application.

    """
    resolved = settings or get_settings()
    app = FastAPI(
        title=resolved.project_name,
        version="0.1.0",
        summary="Extracts bidirectional flow metadata from offline packet captures.",
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
        generate_unique_id_function=custom_generate_unique_id,
    )
    app.state.settings = resolved

    if resolved.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=resolved.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(api_router, prefix=resolved.api_v1_prefix)
    return app


app = create_app()
