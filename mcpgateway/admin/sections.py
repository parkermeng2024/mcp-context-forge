# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/sections.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI lazy-section routes: resources, prompts, servers, and gateways
section payloads for the dashboard tabs.
"""

# Standard
import logging
from typing import Optional
import urllib.parse

# Third-Party
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import serialize_datetime
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_scoped_resource_access_context
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.server_service import ServerService
from mcpgateway.utils.orjson_response import ORJSONResponse

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


@router.get("/sections/resources")
@require_permission("resources.read", allow_admin_bypass=False)
async def get_resources_section(
    request: Request,
    team_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get resources data filtered by team.

    Args:
        request: FastAPI request object
        team_id: Optional team ID to filter by
        db: Database session
        user: Current authenticated user context

    Returns:
        JSONResponse: Resources data with team filtering applied
    """
    try:
        local_resource_service = ResourceService()
        user_email, token_teams = get_scoped_resource_access_context(request, user)
        LOGGER.debug(f"User {user_email} requesting resources section with team_id={team_id}, token_teams={token_teams}")

        # Filter in the service, not here: a strict team_id comparison would drop
        # globally-public rows owned by other teams.
        resources_result = await local_resource_service.list_resources(db, include_inactive=True, user_email=user_email, token_teams=token_teams, team_id=team_id)
        if isinstance(resources_result, tuple):
            resources_list = resources_result[0]
        else:
            resources_list = resources_result

        # Convert to JSON-serializable format
        resources = []
        for resource in resources_list:
            resource_dict = (
                resource.model_dump(by_alias=True)
                if hasattr(resource, "model_dump")
                else {
                    "id": resource.id,
                    "name": resource.name,
                    "description": resource.description,
                    "uri": resource.uri,
                    "tags": resource.tags or [],
                    "isActive": resource.enabled,
                    "team_id": getattr(resource, "team_id", None),
                    "visibility": getattr(resource, "visibility", "private"),
                }
            )
            resources.append(resource_dict)

        return ORJSONResponse(content={"resources": resources, "team_id": team_id})

    except Exception as e:
        LOGGER.error(f"Error loading resources section: {e}")
        return ORJSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/sections/prompts")
@require_permission("prompts.read", allow_admin_bypass=False)
async def get_prompts_section(
    request: Request,
    team_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get prompts data filtered by team.

    Args:
        request: FastAPI request object
        team_id: Optional team ID to filter by
        db: Database session
        user: Current authenticated user context

    Returns:
        JSONResponse: Prompts data with team filtering applied
    """
    try:
        local_prompt_service = PromptService()
        user_email, token_teams = get_scoped_resource_access_context(request, user)
        LOGGER.debug(f"User {user_email} requesting prompts section with team_id={team_id}, token_teams={token_teams}")

        # Filter in the service, not here: a strict team_id comparison would drop
        # globally-public rows owned by other teams.
        prompts_result = await local_prompt_service.list_prompts(db, include_inactive=True, user_email=user_email, token_teams=token_teams, team_id=team_id)
        if isinstance(prompts_result, tuple):
            prompts_list = prompts_result[0]
        else:
            prompts_list = prompts_result

        # Convert to JSON-serializable format
        prompts = []
        for prompt in prompts_list:
            prompt_dict = (
                prompt.model_dump(by_alias=True)
                if hasattr(prompt, "model_dump")
                else {
                    "id": prompt.id,
                    "name": prompt.name,
                    "description": prompt.description,
                    "arguments": prompt.arguments or [],
                    "tags": prompt.tags or [],
                    # Prompt enabled/disabled state is stored on the prompt as `enabled`.
                    "isActive": getattr(prompt, "enabled", False),
                    "team_id": getattr(prompt, "team_id", None),
                    "visibility": getattr(prompt, "visibility", "private"),
                }
            )
            prompts.append(prompt_dict)

        return ORJSONResponse(content={"prompts": prompts, "team_id": team_id})

    except Exception as e:
        LOGGER.error(f"Error loading prompts section: {e}")
        return ORJSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/sections/servers")
@require_permission("servers.read", allow_admin_bypass=False)
async def get_servers_section(
    request: Request,
    team_id: Optional[str] = None,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get servers data filtered by team.

    Args:
        request: FastAPI request, used to derive the caller's Layer-1 visibility scope
        team_id: Optional team ID to filter by
        include_inactive: Whether to include inactive servers
        db: Database session
        user: Current authenticated user context

    Returns:
        JSONResponse: Servers data with team filtering applied
    """
    try:
        local_server_service = ServerService()
        user_email, token_teams = get_scoped_resource_access_context(request, user)
        LOGGER.debug(f"User {user_email} requesting servers section with team_id={team_id}, include_inactive={include_inactive}, token_teams={token_teams}")

        # Filter in the service, not here: a strict team_id comparison would drop
        # globally-public rows owned by other teams.
        servers_result = await local_server_service.list_servers(db, include_inactive=include_inactive, user_email=user_email, token_teams=token_teams, team_id=team_id)
        if isinstance(servers_result, tuple):
            servers_list = servers_result[0]
        else:
            servers_list = servers_result

        # Convert to JSON-serializable format
        servers = []
        for server in servers_list:
            server_dict = (
                server.model_dump(by_alias=True)
                if hasattr(server, "model_dump")
                else {
                    "id": server.id,
                    "name": server.name,
                    "description": server.description,
                    "tags": server.tags or [],
                    "isActive": server.enabled,
                    "team_id": getattr(server, "team_id", None),
                    "visibility": getattr(server, "visibility", "private"),
                }
            )
            servers.append(server_dict)

        return ORJSONResponse(content={"servers": servers, "team_id": team_id})

    except Exception as e:
        LOGGER.error(f"Error loading servers section: {e}")
        return ORJSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/sections/gateways")
@require_permission("gateways.read", allow_admin_bypass=False)
async def get_gateways_section(
    request: Request,
    team_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get gateways data filtered by team.

    Args:
        request: FastAPI request, used to derive the caller's Layer-1 visibility scope
        team_id: Optional team ID to filter by
        db: Database session
        user: Current authenticated user context

    Returns:
        JSONResponse: Gateways data with team filtering applied
    """
    try:
        local_gateway_service = GatewayService()
        user_email, token_teams = get_scoped_resource_access_context(request, user)

        # Filter in the service, not here: a strict team_id comparison would drop
        # globally-public rows owned by other teams.
        gateways_list, _ = await local_gateway_service.list_gateways(db, include_inactive=True, user_email=user_email, token_teams=token_teams, team_id=team_id)

        # Convert to JSON-serializable format
        gateways = []
        for gateway in gateways_list:
            if hasattr(gateway, "model_dump"):
                # Get dict and serialize datetime objects
                gateway_dict = gateway.model_dump(by_alias=True)
                # Convert datetime objects to strings
                for key, value in gateway_dict.items():
                    gateway_dict[key] = serialize_datetime(value)
            else:
                # Parse URL to extract host and port
                parsed_url = urllib.parse.urlparse(gateway.url) if gateway.url else None
                gateway_dict = {
                    "id": gateway.id,
                    "name": gateway.name,
                    "host": parsed_url.hostname if parsed_url else "",
                    "port": parsed_url.port if parsed_url else 80,
                    "tags": gateway.tags or [],
                    "isActive": getattr(gateway, "enabled", False),
                    "team_id": getattr(gateway, "team_id", None),
                    "visibility": getattr(gateway, "visibility", "private"),
                    "created_at": serialize_datetime(getattr(gateway, "created_at", None)),
                    "updated_at": serialize_datetime(getattr(gateway, "updated_at", None)),
                }
            gateways.append(gateway_dict)

        return ORJSONResponse(content={"gateways": gateways, "team_id": team_id})

    except Exception as e:
        LOGGER.error(f"Error loading gateways section: {e}")
        return ORJSONResponse(content={"error": str(e)}, status_code=500)
