"""Aggregates every versioned route module into a single router."""

from fastapi import APIRouter

from ciara_pcap_api.api.routes import captures, health

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(captures.router)
