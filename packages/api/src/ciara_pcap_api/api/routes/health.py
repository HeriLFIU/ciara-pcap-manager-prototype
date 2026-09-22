"""Liveness endpoint."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Reports that the API is reachable."""

    status: str = Field(description="Always `ok` when the API is serving.")
    service: str = Field(description="Human-readable service name.")


@router.get("/health", summary="Liveness probe")
async def read_health() -> HealthResponse:
    """
    Report that the API is reachable.

    Returns:
        A constant healthy payload.

    """
    return HealthResponse(status="ok", service="ciara-pcap-api")
