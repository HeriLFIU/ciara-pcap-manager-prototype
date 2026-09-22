from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.flow_page import FlowPage
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    job_id: UUID,
    *,
    offset: int | Unset = 0,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["offset"] = offset

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/captures/{job_id}/flows".format(
            job_id=quote(str(job_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> FlowPage | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = FlowPage.from_dict(response.json())

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
) -> Response[FlowPage | HTTPValidationError]:
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
    offset: int | Unset = 0,
    limit: int | Unset = 100,
) -> Response[FlowPage | HTTPValidationError]:
    """Page through extracted flows

     Read one page of the flows extracted from a capture.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.
        offset: Index of the first flow to return.
        limit: Maximum number of flows to return.

    Returns:
        The requested page of flows.

    Raises:
        HTTPException: If the job does not exist.

    Args:
        job_id (UUID):
        offset (int | Unset): Index of the first flow. Default: 0.
        limit (int | Unset): Maximum flows to return. Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FlowPage | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        job_id=job_id,
        offset=offset,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    job_id: UUID,
    *,
    client: AuthenticatedClient | Client,
    offset: int | Unset = 0,
    limit: int | Unset = 100,
) -> FlowPage | HTTPValidationError | None:
    """Page through extracted flows

     Read one page of the flows extracted from a capture.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.
        offset: Index of the first flow to return.
        limit: Maximum number of flows to return.

    Returns:
        The requested page of flows.

    Raises:
        HTTPException: If the job does not exist.

    Args:
        job_id (UUID):
        offset (int | Unset): Index of the first flow. Default: 0.
        limit (int | Unset): Maximum flows to return. Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FlowPage | HTTPValidationError
    """

    return sync_detailed(
        job_id=job_id,
        client=client,
        offset=offset,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    job_id: UUID,
    *,
    client: AuthenticatedClient | Client,
    offset: int | Unset = 0,
    limit: int | Unset = 100,
) -> Response[FlowPage | HTTPValidationError]:
    """Page through extracted flows

     Read one page of the flows extracted from a capture.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.
        offset: Index of the first flow to return.
        limit: Maximum number of flows to return.

    Returns:
        The requested page of flows.

    Raises:
        HTTPException: If the job does not exist.

    Args:
        job_id (UUID):
        offset (int | Unset): Index of the first flow. Default: 0.
        limit (int | Unset): Maximum flows to return. Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FlowPage | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        job_id=job_id,
        offset=offset,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    job_id: UUID,
    *,
    client: AuthenticatedClient | Client,
    offset: int | Unset = 0,
    limit: int | Unset = 100,
) -> FlowPage | HTTPValidationError | None:
    """Page through extracted flows

     Read one page of the flows extracted from a capture.

    Args:
        service: The analysis service.
        job_id: Identifier returned by the upload endpoint.
        offset: Index of the first flow to return.
        limit: Maximum number of flows to return.

    Returns:
        The requested page of flows.

    Raises:
        HTTPException: If the job does not exist.

    Args:
        job_id (UUID):
        offset (int | Unset): Index of the first flow. Default: 0.
        limit (int | Unset): Maximum flows to return. Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FlowPage | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            job_id=job_id,
            client=client,
            offset=offset,
            limit=limit,
        )
    ).parsed
