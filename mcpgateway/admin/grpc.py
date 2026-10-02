# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/grpc.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI gRPC service management routes, plus the optional grpcio imports and
the process-wide ``grpc_service_mgr`` instance.
"""

# Standard
import logging
from typing import Any, Dict, Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import _check_public_visibility_allowed, _validated_team_id_param
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_user_email
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import PaginatedResponse
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.orjson_response import ORJSONResponse

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


# Conditional imports for gRPC support (only if grpcio is installed)
try:
    # First-Party
    from mcpgateway.schemas import GrpcServiceCreate, GrpcServiceRead, GrpcServiceUpdate
    from mcpgateway.services.grpc_service import GrpcService, GrpcServiceError, GrpcServiceNameConflictError, GrpcServiceNotFoundError

    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    # Define placeholder types to avoid NameError
    GrpcServiceCreate = None  # type: ignore
    GrpcServiceRead = None  # type: ignore
    GrpcServiceUpdate = None  # type: ignore
    GrpcService = None  # type: ignore

    # Define placeholder exception classes that maintain the hierarchy
    class GrpcServiceError(Exception):  # type: ignore
        """Placeholder for GrpcServiceError when grpcio is not installed."""

    class GrpcServiceNotFoundError(GrpcServiceError):  # type: ignore
        """Placeholder for GrpcServiceNotFoundError when grpcio is not installed."""

    class GrpcServiceNameConflictError(GrpcServiceError):  # type: ignore
        """Placeholder for GrpcServiceNameConflictError when grpcio is not installed."""


grpc_service_mgr: Optional[Any] = GrpcService() if (settings.mcpgateway_grpc_enabled and GRPC_AVAILABLE and GrpcService is not None) else None


# gRPC Service Management Endpoints


@router.get("/grpc", response_model=PaginatedResponse)
@require_permission("admin.grpc", allow_admin_bypass=False)
async def admin_list_grpc_services(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """List all gRPC services for the admin UI with pagination support.

    This endpoint retrieves a paginated list of gRPC services. Administrators can
    optionally include inactive services for management or auditing purposes.
    Uses offset-based (page/per_page) pagination.

    Args:
        page: Page number (1-indexed) for offset pagination
        per_page: Number of items per page
        include_inactive: Whether to include inactive services in the results
        team_id: Optional team ID to filter by specific team
        db: Database session dependency
        user: Authenticated user dependency

    Returns:
        Dict[str, Any]: A dictionary containing:
            - data: List of gRPC service records formatted with by_alias=True
            - pagination: Pagination metadata
            - links: Pagination links (optional)

    Raises:
        HTTPException: If gRPC support is disabled or not available
    """
    if not GRPC_AVAILABLE or not settings.mcpgateway_grpc_enabled:
        raise HTTPException(status_code=404, detail="gRPC support is not available or disabled")

    user_email = get_user_email(user)

    # Call grpc_service_mgr.list_services with page-based pagination
    paginated_result = await grpc_service_mgr.list_services(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        team_id=team_id,
    )

    # Return standardized paginated response
    return {
        "data": [service.model_dump(by_alias=True) for service in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@router.post("/grpc")
@require_permission("admin.grpc", allow_admin_bypass=False)
async def admin_create_grpc_service(
    service: GrpcServiceCreate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Create a new gRPC service.

    Args:
        service: gRPC service creation data
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        Created gRPC service

    Raises:
        HTTPException: If gRPC support is disabled or creation fails
    """
    if not GRPC_AVAILABLE or not settings.mcpgateway_grpc_enabled:
        raise HTTPException(status_code=404, detail="gRPC support is not available or disabled")

    try:
        _check_public_visibility_allowed(service.visibility or "", team_id=getattr(service, "team_id", None))
        metadata = MetadataCapture.extract_creation_metadata(request, user)
        user_email = get_user_email(user)
        result = await grpc_service_mgr.register_service(db, service, user_email, metadata)
        return ORJSONResponse(content=jsonable_encoder(result), status_code=201)
    except GrpcServiceNameConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except GrpcServiceError as e:
        LOGGER.error(f"gRPC service error: {e}")
        raise HTTPException(status_code=500, detail="gRPC service error")


@router.get("/grpc/{service_id}", response_model=GrpcServiceRead)
@require_permission("admin.grpc", allow_admin_bypass=False)
async def admin_get_grpc_service(
    service_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get a specific gRPC service.

    Args:
        service_id: Service ID
        db: Database session
        user: Authenticated user

    Returns:
        The gRPC service

    Raises:
        HTTPException: If gRPC support is disabled or service not found
    """
    if not GRPC_AVAILABLE or not settings.mcpgateway_grpc_enabled:
        raise HTTPException(status_code=404, detail="gRPC support is not available or disabled")

    try:
        user_email = get_user_email(user)
        return await grpc_service_mgr.get_service(db, service_id, user_email)
    except GrpcServiceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/grpc/{service_id}")
@require_permission("admin.grpc", allow_admin_bypass=False)
async def admin_update_grpc_service(
    service_id: str,
    service: GrpcServiceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Update a gRPC service.

    Args:
        service_id: Service ID
        service: Update data
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        Updated gRPC service

    Raises:
        HTTPException: If gRPC support is disabled or update fails
    """
    if not GRPC_AVAILABLE or not settings.mcpgateway_grpc_enabled:
        raise HTTPException(status_code=404, detail="gRPC support is not available or disabled")

    try:
        _check_public_visibility_allowed(service.visibility or "", team_id=getattr(service, "team_id", None))
        metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        user_email = get_user_email(user)
        result = await grpc_service_mgr.update_service(db, service_id, service, user_email, metadata)
        return ORJSONResponse(content=jsonable_encoder(result))
    except GrpcServiceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except GrpcServiceNameConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except GrpcServiceError as e:
        LOGGER.error(f"gRPC service error: {e}")
        raise HTTPException(status_code=500, detail="gRPC service error")


@router.post("/grpc/{service_id}/state")
@require_permission("admin.grpc", allow_admin_bypass=False)
async def admin_set_grpc_service_state(
    service_id: str,
    activate: Optional[bool] = Query(None, description="Set enabled state. If not provided, inverts current state."),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
):
    """Set a gRPC service's enabled state.

    Args:
        service_id: Service ID
        activate: If provided, sets enabled to this value. If None, inverts current state (legacy behavior).
        db: Database session
        user: Authenticated user

    Returns:
        Updated gRPC service

    Raises:
        HTTPException: If gRPC support is disabled or state change fails
    """
    if not GRPC_AVAILABLE or not settings.mcpgateway_grpc_enabled:
        raise HTTPException(status_code=404, detail="gRPC support is not available or disabled")

    try:
        if activate is None:
            # Legacy toggle behavior - invert current state
            service = await grpc_service_mgr.get_service(db, service_id)
            activate = not service.enabled
        result = await grpc_service_mgr.set_service_state(db, service_id, activate)
        return ORJSONResponse(content=jsonable_encoder(result))
    except GrpcServiceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/grpc/{service_id}/delete")
@require_permission("admin.grpc", allow_admin_bypass=False)
async def admin_delete_grpc_service(
    service_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
):
    """Delete a gRPC service.

    Args:
        service_id: Service ID
        db: Database session
        user: Authenticated user

    Returns:
        No content response

    Raises:
        HTTPException: If gRPC support is disabled or deletion fails
    """
    if not GRPC_AVAILABLE or not settings.mcpgateway_grpc_enabled:
        raise HTTPException(status_code=404, detail="gRPC support is not available or disabled")

    try:
        await grpc_service_mgr.delete_service(db, service_id)
        return Response(status_code=204)
    except GrpcServiceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/grpc/{service_id}/reflect")
@require_permission("admin.grpc", allow_admin_bypass=False)
async def admin_reflect_grpc_service(
    service_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
):
    """Trigger re-reflection on a gRPC service.

    Args:
        service_id: Service ID
        db: Database session
        user: Authenticated user

    Returns:
        Updated gRPC service with reflection results

    Raises:
        HTTPException: If gRPC support is disabled or reflection fails
    """
    if not GRPC_AVAILABLE or not settings.mcpgateway_grpc_enabled:
        raise HTTPException(status_code=404, detail="gRPC support is not available or disabled")

    try:
        result = await grpc_service_mgr.reflect_service(db, service_id)
        return ORJSONResponse(content=jsonable_encoder(result))
    except GrpcServiceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except GrpcServiceError as e:
        LOGGER.error(f"gRPC service error: {e}")
        raise HTTPException(status_code=500, detail="gRPC service error")


@router.get("/grpc/{service_id}/methods")
@require_permission("admin.grpc", allow_admin_bypass=False)
async def admin_get_grpc_methods(
    service_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
):
    """Get methods for a gRPC service.

    Args:
        service_id: Service ID
        db: Database session
        user: Authenticated user

    Returns:
        List of gRPC methods

    Raises:
        HTTPException: If gRPC support is disabled or service not found
    """
    if not GRPC_AVAILABLE or not settings.mcpgateway_grpc_enabled:
        raise HTTPException(status_code=404, detail="gRPC support is not available or disabled")

    try:
        methods = await grpc_service_mgr.get_service_methods(db, service_id)
        return ORJSONResponse(content={"methods": methods})
    except GrpcServiceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
