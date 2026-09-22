from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.analysis_job import AnalysisJob
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    job_id: UUID,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/captures/{job_id}".format(
            job_id=quote(str(job_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AnalysisJob | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = AnalysisJob.from_dict(response.json())

        return response_200

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AnalysisJob | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    job_id: UUID,
    *,
    client: AuthenticatedClient | Client,
) -> Response[AnalysisJob | HTTPValidationError]:
    """Read one analysis job

     Read the current state of an analysis job.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.

    Returns:
        The job, including its summary once extraction succeeded.

    Raises:
        HTTPException: If the job does not exist.

    Args:
        job_id (UUID):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnalysisJob | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        job_id=job_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    job_id: UUID,
    *,
    client: AuthenticatedClient | Client,
) -> AnalysisJob | HTTPValidationError | None:
    """Read one analysis job

     Read the current state of an analysis job.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.

    Returns:
        The job, including its summary once extraction succeeded.

    Raises:
        HTTPException: If the job does not exist.

    Args:
        job_id (UUID):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnalysisJob | HTTPValidationError
    """

    return sync_detailed(
        job_id=job_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    job_id: UUID,
    *,
    client: AuthenticatedClient | Client,
) -> Response[AnalysisJob | HTTPValidationError]:
    """Read one analysis job

     Read the current state of an analysis job.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.

    Returns:
        The job, including its summary once extraction succeeded.

    Raises:
        HTTPException: If the job does not exist.

    Args:
        job_id (UUID):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnalysisJob | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        job_id=job_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    job_id: UUID,
    *,
    client: AuthenticatedClient | Client,
) -> AnalysisJob | HTTPValidationError | None:
    """Read one analysis job

     Read the current state of an analysis job.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.

    Returns:
        The job, including its summary once extraction succeeded.

    Raises:
        HTTPException: If the job does not exist.

    Args:
        job_id (UUID):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnalysisJob | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            job_id=job_id,
            client=client,
        )
    ).parsed
