# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/tags.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI tag route: list tags across entity types.
"""

# Standard
import logging
from typing import Any, Dict, List, Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import PaginatedResponse
from mcpgateway.services.tag_service import TagService

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


####################
# Admin Tag Routes #
####################


@router.get("/tags", response_model=PaginatedResponse)
@require_permission("tags.read", allow_admin_bypass=False)
async def admin_list_tags(
    entity_types: Optional[str] = None,
    include_entities: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> List[Dict[str, Any]]:
    """
    List all unique tags with statistics for the admin UI.

    Args:
        entity_types: Comma-separated list of entity types to filter by
                     (e.g., "tools,resources,prompts,servers,gateways").
                     If not provided, returns tags from all entity types.
        include_entities: Whether to include the list of entities that have each tag
        db: Database session
        user: Authenticated user

    Returns:
        List of tag information with statistics

    Raises:
        HTTPException: If tag retrieval fails

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import admin_list_tags
        >>> admin_list_tags.__name__
        'admin_list_tags'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(admin_list_tags)
        True
    """
    tag_service = TagService()

    # Parse entity types parameter if provided
    entity_types_list = None
    if entity_types:
        entity_types_list = [et.strip().lower() for et in entity_types.split(",") if et.strip()]

    LOGGER.debug(f"Admin user {user} is retrieving tags for entity types: {entity_types_list}, include_entities: {include_entities}")

    try:
        user_email = user.get("email") if isinstance(user, dict) else None
        token_teams = user.get("token_teams") if isinstance(user, dict) else None
        is_admin = bool(user.get("is_admin")) if isinstance(user, dict) else False

        # Preserve admin bypass only when token/user context is unrestricted.
        if is_admin and token_teams is None:
            user_email = None

        tags = await tag_service.get_all_tags(
            db,
            entity_types=entity_types_list,
            include_entities=include_entities,
            user_email=user_email,
            token_teams=token_teams,
        )

        # Convert to list of dicts for admin UI
        result: List[Dict[str, Any]] = []
        for tag in tags:
            tag_dict: Dict[str, Any] = {
                "name": tag.name,
                "tools": tag.stats.tools,
                "resources": tag.stats.resources,
                "prompts": tag.stats.prompts,
                "servers": tag.stats.servers,
                "gateways": tag.stats.gateways,
                "total": tag.stats.total,
            }

            # Include entities if requested
            if include_entities and tag.entities:
                tag_dict["entities"] = [
                    {
                        "id": entity.id,
                        "name": entity.name,
                        "type": entity.type,
                        "description": entity.description,
                    }
                    for entity in tag.entities
                ]

            result.append(tag_dict)

        return result
    except Exception as e:
        LOGGER.error(f"Failed to retrieve tags for admin: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve tags")
