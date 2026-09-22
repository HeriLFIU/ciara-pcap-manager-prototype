"""
Shared FastAPI dependencies.

Collaborators are built once during the application lifespan and published on
``app.state``; this dependency is the only place routes reach for them, so a
route never touches ``Request.app`` itself.
"""

from typing import Annotated

from fastapi import Depends, Request

from ciara_pcap_api.services.analysis import AnalysisService


def get_analysis_service(request: Request) -> AnalysisService:
    """
    Return the analysis service bound to the running application.

    Args:
        request: The active request.

    Returns:
        The analysis service.

    """
    service: AnalysisService = request.app.state.analysis_service
    return service


AnalysisServiceDep = Annotated[AnalysisService, Depends(get_analysis_service)]
