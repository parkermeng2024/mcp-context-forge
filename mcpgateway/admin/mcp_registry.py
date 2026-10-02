# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/mcp_registry.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI MCP Registry routes: catalog browsing, server registration,
availability status, bulk registration, and the registry partial.
"""

# Standard
import html
from typing import List, Optional, Union

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
import orjson
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_scoped_resource_access_context
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import (
    CatalogBulkRegisterRequest,
    CatalogBulkRegisterResponse,
    CatalogListRequest,
    CatalogListResponse,
    CatalogServerRegisterRequest,
    CatalogServerRegisterResponse,
    CatalogServerStatusResponse,
)
from mcpgateway.services.catalog_service import catalog_service, CatalogRegistrationPermissionError
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


##################################################
# MCP Registry Endpoints
##################################################


@router.get("/mcp-registry/servers", response_model=CatalogListResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def list_catalog_servers(
    _request: Request,
    category: Optional[str] = None,
    auth_type: Optional[str] = None,
    provider: Optional[str] = None,
    search: Optional[str] = None,
    tags: Optional[List[str]] = Query(None),
    show_registered_only: bool = False,
    show_available_only: bool = True,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> CatalogListResponse:
    """Get list of catalog servers with filtering.

    Args:
        _request: FastAPI request object
        category: Filter by category
        auth_type: Filter by authentication type
        provider: Filter by provider
        search: Search in name/description
        tags: Filter by tags
        show_registered_only: Show only already registered servers
        show_available_only: Show only available servers
        limit: Maximum results
        offset: Pagination offset
        db: Database session
        _user: Authenticated user

    Returns:
        List of catalog servers matching filters

    Raises:
        HTTPException: If the catalog feature is disabled.
    """
    if not settings.mcpgateway_catalog_enabled:
        raise HTTPException(status_code=404, detail="Catalog feature is disabled")

    user_email, token_teams = get_scoped_resource_access_context(_request, _user)
    catalog_request = CatalogListRequest(
        category=category,
        auth_type=auth_type,
        provider=provider,
        search=search,
        tags=tags or [],
        show_registered_only=show_registered_only,
        show_available_only=show_available_only,
        limit=limit,
        offset=offset,
    )

    return await catalog_service.get_catalog_servers(catalog_request, db, user_email=user_email, token_teams=token_teams)


@router.post("/mcp-registry/{server_id}/register", response_model=CatalogServerRegisterResponse)
@require_permission("servers.create", allow_admin_bypass=False)
@require_permission("gateways.create", allow_admin_bypass=False)
async def register_catalog_server(
    server_id: str,
    http_request: Request,
    request: Optional[CatalogServerRegisterRequest] = None,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> Union[CatalogServerRegisterResponse, HTMLResponse]:
    """Register a catalog server.

    Args:
        server_id: Catalog server ID to register
        http_request: FastAPI request object (for HTMX detection)
        request: Optional registration parameters
        db: Database session
        _user: Authenticated user

    Returns:
        Registration response with success status (JSON or HTML)

    Raises:
        HTTPException: If the catalog feature is disabled.
    """
    if not settings.mcpgateway_catalog_enabled:
        raise HTTPException(status_code=404, detail="Catalog feature is disabled")

    user_email, token_teams = get_scoped_resource_access_context(http_request, _user)

    try:
        result = await catalog_service.register_catalog_server(
            catalog_id=server_id,
            request=request,
            db=db,
            created_by=user_email,
            owner_email=user_email,
            token_teams=token_teams,
        )
    except CatalogRegistrationPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # Check if this is an HTMX request
    is_htmx = http_request.headers.get("HX-Request") == "true"

    if is_htmx:
        # Return HTML fragment for HTMX - properly escape all dynamic values
        safe_server_id = html.escape(server_id, quote=True)
        safe_message = html.escape(result.message, quote=True)

        if result.success:
            # Check if this is an OAuth server requiring configuration (use explicit flag, not string matching)
            if result.oauth_required:
                # OAuth servers are registered but disabled until configured
                button_fragment = f"""
                <button
                    class="w-full px-4 py-2 bg-yellow-600 text-white rounded-md cursor-default"
                    disabled
                    title="{safe_message}"
                >
                    <svg class="inline-block h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                    </svg>
                    OAuth Config Required
                </button>
                """
                # Trigger refresh - template will show yellow state from requires_oauth_config field
                response = HTMLResponse(content=button_fragment)
                response.headers["HX-Trigger-After-Swap"] = orjson.dumps({"catalogRegistrationSuccess": {"delayMs": 1500}}).decode()
                return response
            # Success: Show success button state
            button_fragment = f"""
            <button
                class="w-full px-4 py-2 bg-green-600 text-white rounded-md cursor-default"
                disabled
                title="{safe_message}"
            >
                <svg class="inline-block h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
                Registered Successfully
            </button>
            """
            # Only non-OAuth success triggers delayed table refresh
            response = HTMLResponse(content=button_fragment)
            response.headers["HX-Trigger-After-Swap"] = orjson.dumps({"catalogRegistrationSuccess": {"delayMs": 1500}}).decode()
            return response
        # Error: Show error state with retry button (no auto-refresh so retry persists)
        error_msg = html.escape(result.error or result.message, quote=True)
        button_fragment = f"""
        <button
            id="{safe_server_id}-register-btn"
            class="w-full px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
            hx-post="{settings.app_root_path}/admin/mcp-registry/{safe_server_id}/register"
            hx-target="#{safe_server_id}-button-container"
            hx-swap="innerHTML"
            hx-disabled-elt="this"
            hx-on::before-request="this.innerHTML = '<span class=\\'inline-flex items-center\\'><span class=\\'inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2\\'></span>Retrying...</span>'"
            hx-on::response-error="this.innerHTML = '<span class=\\'inline-flex items-center\\'><svg class=\\'inline-block h-4 w-4 mr-2\\' fill=\\'none\\' stroke=\\'currentColor\\' viewBox=\\'0 0 24 24\\'><path stroke-linecap=\\'round\\' stroke-linejoin=\\'round\\' stroke-width=\\'2\\' d=\\'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z\\'></path></svg>Network Error - Click to Retry</span>'"
            title="{error_msg}"
        >
            <svg class="inline-block h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            Failed - Click to Retry
        </button>
        """
        # No HX-Trigger for errors - let the retry button persist
        return HTMLResponse(content=button_fragment)

    # Return JSON for non-HTMX requests (API clients)
    return result


@router.get("/mcp-registry/{server_id}/status", response_model=CatalogServerStatusResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def check_catalog_server_status(
    server_id: str,
    _db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> CatalogServerStatusResponse:
    """Check catalog server availability.

    Args:
        server_id: Catalog server ID to check
        _db: Database session
        _user: Authenticated user

    Returns:
        Server status including availability and response time

    Raises:
        HTTPException: If the catalog feature is disabled.
    """
    if not settings.mcpgateway_catalog_enabled:
        raise HTTPException(status_code=404, detail="Catalog feature is disabled")

    return await catalog_service.check_server_availability(server_id)


@router.post("/mcp-registry/bulk-register", response_model=CatalogBulkRegisterResponse)
@require_permission("servers.create", allow_admin_bypass=False)
@require_permission("gateways.create", allow_admin_bypass=False)
async def bulk_register_catalog_servers(
    http_request: Request,
    request: CatalogBulkRegisterRequest,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> CatalogBulkRegisterResponse:
    """Register multiple catalog servers at once.

    Args:
        http_request: FastAPI request object
        request: Bulk registration request with server IDs
        db: Database session
        _user: Authenticated user

    Returns:
        Bulk registration response with success/failure details

    Raises:
        HTTPException: If the catalog feature is disabled or scope is invalid.
    """
    if not settings.mcpgateway_catalog_enabled:
        raise HTTPException(status_code=404, detail="Catalog feature is disabled")

    user_email, token_teams = get_scoped_resource_access_context(http_request, _user)

    try:
        return await catalog_service.bulk_register_servers(
            request,
            db,
            created_by=user_email,
            owner_email=user_email,
            token_teams=token_teams,
        )
    except CatalogRegistrationPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/mcp-registry/partial")
@require_permission("servers.read", allow_admin_bypass=False)
async def catalog_partial(
    request: Request,
    category: Optional[str] = None,
    auth_type: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Get HTML partial for catalog servers (used by HTMX).

    Args:
        request: FastAPI request object
        category: Filter by category
        auth_type: Filter by authentication type
        search: Search term
        page: Page number (1-indexed)
        db: Database session
        _user: Authenticated user

    Returns:
        HTML partial with filtered catalog servers

    Raises:
        HTTPException: If the catalog feature is disabled.
    """
    if not settings.mcpgateway_catalog_enabled:
        raise HTTPException(status_code=404, detail="Catalog feature is disabled")

    root_path = _resolve_root_path(request)
    user_email, token_teams = get_scoped_resource_access_context(request, _user)

    # Calculate pagination
    page_size = settings.mcpgateway_catalog_page_size
    offset = (page - 1) * page_size

    catalog_request = CatalogListRequest(category=category, auth_type=auth_type, search=search, show_available_only=False, limit=page_size, offset=offset)

    response = await catalog_service.get_catalog_servers(catalog_request, db, user_email=user_email, token_teams=token_teams)

    # Get ALL servers (no filters, no pagination) for counting statistics
    all_servers_request = CatalogListRequest(show_available_only=False, limit=1000, offset=0)
    all_servers_response = await catalog_service.get_catalog_servers(all_servers_request, db, user_email=user_email, token_teams=token_teams)

    # Pass filter parameters to template for pagination links
    filter_params = {
        "category": category,
        "auth_type": auth_type,
        "search": search,
    }

    # Calculate statistics and pagination info
    total_servers = response.total
    registered_count = sum(1 for s in response.servers if s.is_registered)
    total_pages = (total_servers + page_size - 1) // page_size  # Ceiling division

    # Count ALL servers by category, auth type, and provider (not just current page)
    servers_by_category = {}
    servers_by_auth_type = {}
    servers_by_provider = {}

    for server in all_servers_response.servers:
        servers_by_category[server.category] = servers_by_category.get(server.category, 0) + 1
        servers_by_auth_type[server.auth_type] = servers_by_auth_type.get(server.auth_type, 0) + 1
        servers_by_provider[server.provider] = servers_by_provider.get(server.provider, 0) + 1

    stats = {
        "total_servers": all_servers_response.total,  # Use total from all servers
        "registered_servers": registered_count,
        "categories": all_servers_response.categories,
        "auth_types": all_servers_response.auth_types,
        "providers": all_servers_response.providers,
        "servers_by_category": servers_by_category,
        "servers_by_auth_type": servers_by_auth_type,
        "servers_by_provider": servers_by_provider,
    }

    context = {
        "request": request,
        "servers": response.servers,
        "stats": stats,
        "root_path": root_path,
        "page": page,
        "total_pages": total_pages,
        "page_size": page_size,
        "filter_params": filter_params,
    }

    return request.app.state.templates.TemplateResponse(request, "mcp_registry_partial.html", context)


