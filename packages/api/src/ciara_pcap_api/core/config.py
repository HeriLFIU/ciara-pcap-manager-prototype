"""
Backend configuration.

Extends the shared core settings with the knobs that only an HTTP server
cares about, so a worker process never has to know what CORS is.
"""

from functools import lru_cache

from pydantic import Field

from ciara_pcap_manager_prototype.config import CoreSettings


class ApiSettings(CoreSettings):
    """Settings for the FastAPI application."""

    project_name: str = Field(
        default="CIARA PCAP Analysis API",
        description="Title advertised in the OpenAPI document.",
    )
    api_v1_prefix: str = Field(
        default="/api/v1", description="Path prefix for the versioned API."
    )
    host: str = Field(default="127.0.0.1", description="Interface uvicorn binds to.")
    port: int = Field(default=8000, description="Port uvicorn binds to.")
    log_level: str = Field(default="info", description="Uvicorn log level.")
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173"],
        description="Browser origins allowed to call the API. Used by the "
        "future web frontend; the CLI and GUI are not subject to CORS.",
    )


@lru_cache(maxsize=1)
def get_settings() -> ApiSettings:
    """
    Build the application settings once per process.

    Returns:
        The cached settings instance.

    """
    return ApiSettings()
