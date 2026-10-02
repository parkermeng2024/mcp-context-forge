# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/search.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI unified search: the grouped search route and its per-entity fan-out,
plus the OpenAPI catalog full-text search helper.
"""

# Standard
import logging
from typing import Any, Optional, cast as typing_cast

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.a2a import admin_search_a2a_agents
from mcpgateway.admin.common import (
    _build_search_response,
    _get_user_team_ids,
    _has_permission,
    _normalize_int_query,
    _normalize_search_query,
    _normalize_tags_query,
    _parse_tag_filter_groups,
    _validated_team_id_param,
)
from mcpgateway.admin.gateways import admin_search_gateways
from mcpgateway.admin.prompts import admin_search_prompts
from mcpgateway.admin.resources import admin_search_resources
from mcpgateway.admin.roots import admin_search_roots
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.admin.servers import admin_search_servers
from mcpgateway.admin.teams import admin_search_teams
from mcpgateway.admin.tools import admin_search_tools
from mcpgateway.admin.users import admin_search_users
from mcpgateway.auth_context import get_scoped_resource_access_context
from mcpgateway.common.query_params import QueryEntityTypes, QueryGatewayIdList, QueryTagsFilter
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import _ACCESS_DENIED_MSG, get_current_user_with_permissions, require_permission
from mcpgateway.schemas import CatalogListRequest
from mcpgateway.services.catalog_service import catalog_service

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


@require_permission("servers.read", allow_admin_bypass=False)
async def admin_search_catalog(
    q: str,
    limit: int,
    db: Session,
    user: Any,
    request: Request,
) -> dict[str, Any]:
    """Search visible open-auth catalog servers by name or description."""
    search_query = _normalize_search_query(q)
    if not search_query or not settings.mcpgateway_catalog_enabled:
        return _build_search_response(entity_key="catalog", entity_type="catalog", items=[], query=search_query, tags="", tag_groups=[])

    user_email, token_teams = get_scoped_resource_access_context(request, user)
    catalog_request = CatalogListRequest(search=search_query, auth_type="Open", limit=limit)
    catalog_response = await catalog_service.get_catalog_servers(
        catalog_request,
        db,
        user_email=user_email,
        token_teams=token_teams,
    )
    items = [{"id": server.id, "name": server.name, "description": server.description} for server in catalog_response.servers]
    return _build_search_response(entity_key="catalog", entity_type="catalog", items=items, query=search_query, tags="", tag_groups=[])


async def perform_unified_search(
    *,
    request: Optional[Request] = None,
    q: str,
    tags: Optional[str],
    entity_types: Optional[str],
    include_inactive: bool,
    limit: int,
    limit_per_type: Optional[int],
    gateway_id: Optional[str],
    team_id: Optional[str],
    db: Session,
    user: Any,
) -> dict[str, Any]:
    """Unified search across primary entities (shared, permission-agnostic core).

    Single source of truth for unified search. Performs no top-level permission
    check — callers own the outer gate (``admin.dashboard`` for the admin route,
    auth-only for ``/v1/search``). Per-entity RBAC and token scoping are still
    enforced inside each ``admin_search_*`` call.

    Searches servers, gateways, tools, resources, prompts, agents, teams, roots,
    and optionally catalog entries or users (when explicitly requested and permitted).

    Args:
        request: Current request object.
        q (str): Free-text search query.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        entity_types (Optional[str]): Optional comma-separated entity type list.
            Supported values: servers, gateways, tools, resources, prompts,
            agents, teams, users, roots, catalog.
        include_inactive (bool): Whether to include inactive entities.
        limit (int): Default per-entity limit for returned items.
        limit_per_type (Optional[int]): Optional alias overriding ``limit``.
        gateway_id (Optional[str]): Gateway filter for tools/resources/prompts.
        team_id (Optional[str]): Team scope filter.
        db (Session): Database session.
        user: Authenticated user context.

    Returns:
        dict[str, Any]: Grouped and flattened search results with metadata.

    Raises:
        HTTPException: If ``entity_types`` is provided but contains no supported values.
    """
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    normalized_entity_types = _normalize_tags_query(entity_types)
    tag_groups = _parse_tag_filter_groups(normalized_tags)

    supported_entity_types = ["servers", "gateways", "tools", "resources", "prompts", "agents", "teams", "users", "roots", "catalog"]
    default_entity_types = ["servers", "gateways", "tools", "resources", "prompts", "agents", "teams", "roots"]
    selected_entity_types: list[str] = []
    if normalized_entity_types:
        for raw_entity_type in normalized_entity_types.split(","):
            candidate = raw_entity_type.strip().lower()
            if not candidate:
                continue
            if candidate == "a2a":
                candidate = "agents"
            if candidate in supported_entity_types and candidate not in selected_entity_types:
                selected_entity_types.append(candidate)
    else:
        selected_entity_types = default_entity_types.copy()

    users_explicitly_requested = bool(normalized_entity_types and "users" in selected_entity_types)
    if "users" in selected_entity_types:
        can_search_users = await _has_permission(db=db, user=user, permission="admin.user_management")
        if not can_search_users:
            selected_entity_types = [entity_type for entity_type in selected_entity_types if entity_type != "users"]
            if users_explicitly_requested and not selected_entity_types:
                raise HTTPException(status_code=403, detail=_ACCESS_DENIED_MSG)

    if not selected_entity_types:
        raise HTTPException(status_code=400, detail="No valid entity_types requested")

    resolved_limit = _normalize_int_query(limit, 8)
    effective_limit = _normalize_int_query(limit_per_type, resolved_limit)
    effective_limit = max(1, min(effective_limit, settings.pagination_max_page_size))

    if not search_query and not tag_groups:
        return {
            "query": search_query,
            "tags": normalized_tags,
            "entity_types": selected_entity_types,
            "limit_per_type": effective_limit,
            "filters_applied": {"q": search_query, "tags": normalized_tags, "tag_groups": tag_groups},
            "results": {key: [] for key in selected_entity_types},
            "groups": [],
            "items": [],
            "count": 0,
        }

    async def _safe_entity_search(search_callable, empty_key: str, **kwargs: Any) -> dict[str, Any]:
        """Execute entity search and return empty results on auth denials.

        Intentional silent 401/403 suppression: unified search spans entity types
        with heterogeneous permission gates (e.g. roots require admin.system_config
        with no admin bypass), and a single denial must not fail the whole search
        or leak existence of restricted entities to unprivileged callers.

        Args:
            search_callable: Async entity search function to execute.
            empty_key: Entity collection key used for fallback empty payloads.
            **kwargs: Parameters forwarded to ``search_callable``.

        Returns:
            Search result payload or an empty payload for auth-denied entities.

        Raises:
            HTTPException: Re-raised when the failure is not an auth-denied status.
        """
        try:
            return await search_callable(**kwargs)
        except HTTPException as exc:
            if exc.status_code in {401, 403}:
                return {empty_key: [], "items": [], "count": 0}
            raise

    # Pre-fetch team IDs once and inject into the user context so that
    # individual search functions reuse them via _get_user_team_ids().
    _team_ids = await _get_user_team_ids(user, db)
    user = dict(user)  # shallow copy to avoid mutating the caller's dict
    user["_cached_team_ids"] = _team_ids

    grouped_results: dict[str, list[dict[str, Any]]] = {entity_type: [] for entity_type in selected_entity_types}

    if "servers" in selected_entity_types:
        servers_result = await _safe_entity_search(
            admin_search_servers,
            "servers",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["servers"] = typing_cast(list[dict[str, Any]], servers_result.get("servers", servers_result.get("items", [])))

    if "gateways" in selected_entity_types:
        gateways_result = await _safe_entity_search(
            admin_search_gateways,
            "gateways",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["gateways"] = typing_cast(list[dict[str, Any]], gateways_result.get("gateways", gateways_result.get("items", [])))

    if "tools" in selected_entity_types:
        tools_result = await _safe_entity_search(
            admin_search_tools,
            "tools",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            gateway_id=gateway_id,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["tools"] = typing_cast(list[dict[str, Any]], tools_result.get("tools", tools_result.get("items", [])))

    if "resources" in selected_entity_types:
        resources_result = await _safe_entity_search(
            admin_search_resources,
            "resources",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            gateway_id=gateway_id,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["resources"] = typing_cast(list[dict[str, Any]], resources_result.get("resources", resources_result.get("items", [])))

    if "prompts" in selected_entity_types:
        prompts_result = await _safe_entity_search(
            admin_search_prompts,
            "prompts",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            gateway_id=gateway_id,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["prompts"] = typing_cast(list[dict[str, Any]], prompts_result.get("prompts", prompts_result.get("items", [])))

    if "agents" in selected_entity_types:
        agents_result = await _safe_entity_search(
            admin_search_a2a_agents,
            "agents",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["agents"] = typing_cast(list[dict[str, Any]], agents_result.get("agents", agents_result.get("items", [])))

    # Teams and users do not support tag filtering; only include when a text query exists.
    if "teams" in selected_entity_types and search_query:
        teams_result = await _safe_entity_search(
            admin_search_teams,
            "teams",
            q=search_query,
            include_inactive=include_inactive,
            limit=effective_limit,
            visibility=None,
            db=db,
            user=user,
        )
        if isinstance(teams_result, list):
            grouped_results["teams"] = typing_cast(list[dict[str, Any]], teams_result)
        else:
            grouped_results["teams"] = typing_cast(list[dict[str, Any]], teams_result.get("teams", teams_result.get("items", [])))

    if "users" in selected_entity_types and search_query:
        users_result = await _safe_entity_search(
            admin_search_users,
            "users",
            q=search_query,
            limit=effective_limit,
            db=db,
            user=user,
        )
        grouped_results["users"] = typing_cast(list[dict[str, Any]], users_result.get("users", users_result.get("items", [])))

    # Roots do not support tag filtering; only include when a text query exists.
    if "roots" in selected_entity_types and search_query:
        roots_result = await _safe_entity_search(
            admin_search_roots,
            "roots",
            request=request,
            q=search_query,
            limit=effective_limit,
            db=db,
            user=user,
        )
        grouped_results["roots"] = typing_cast(list[dict[str, Any]], roots_result.get("roots", roots_result.get("items", [])))

    # Catalog does not support tag filtering and remains opt-in for unified search.
    if "catalog" in selected_entity_types and search_query:
        catalog_result = await _safe_entity_search(
            admin_search_catalog,
            "catalog",
            request=request,
            q=search_query,
            limit=effective_limit,
            db=db,
            user=user,
        )
        grouped_results["catalog"] = typing_cast(list[dict[str, Any]], catalog_result.get("catalog", catalog_result.get("items", [])))

    groups = []
    flat_items: list[dict[str, Any]] = []
    for entity_type in selected_entity_types:
        items = grouped_results.get(entity_type, [])
        groups.append({"entity_type": entity_type, "count": len(items), "items": items})
        for item in items:
            enriched_item = dict(item)
            enriched_item["entity_type"] = entity_type
            flat_items.append(enriched_item)

    return {
        "query": search_query,
        "tags": normalized_tags,
        "entity_types": selected_entity_types,
        "limit_per_type": effective_limit,
        "filters_applied": {"q": search_query, "tags": normalized_tags, "tag_groups": tag_groups},
        "results": grouped_results,
        "groups": groups,
        "items": flat_items,
        "count": len(flat_items),
    }


@router.get("/search", response_class=JSONResponse)
@require_permission("admin.dashboard", allow_admin_bypass=False)
async def admin_unified_search(
    request: Request = None,
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    entity_types: QueryEntityTypes = None,
    include_inactive: bool = False,
    limit: int = Query(8, ge=1, le=settings.pagination_max_page_size, description="Per-entity result limit"),
    limit_per_type: Optional[int] = Query(
        None,
        ge=1,
        le=settings.pagination_max_page_size,
        description="Optional alias for per-entity result limit",
    ),
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Unified search across primary admin entities (admin-gated wrapper).

    Thin wrapper that enforces the ``admin.dashboard`` permission and delegates
    to :func:`perform_unified_search`.

    Args:
        request: Current request object.
        q (str): Free-text search query.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        entity_types (Optional[str]): Optional comma-separated entity type list.
            Supported values: servers, gateways, tools, resources, prompts,
            agents, teams, users, roots.
        include_inactive (bool): Whether to include inactive entities.
        limit (int): Default per-entity limit for returned items.
        limit_per_type (Optional[int]): Optional alias overriding ``limit``.
        gateway_id (Optional[str]): Gateway filter for tools/resources/prompts.
        team_id (Optional[str]): Team scope filter.
        db (Session): Database session.
        user: Authenticated user context.

    Returns:
        dict[str, Any]: Grouped and flattened search results with metadata.
    """
    return await perform_unified_search(
        request=request,
        q=q,
        tags=tags,
        entity_types=entity_types,
        include_inactive=include_inactive,
        limit=limit,
        limit_per_type=limit_per_type,
        gateway_id=gateway_id,
        team_id=team_id,
        db=db,
        user=user,
    )
