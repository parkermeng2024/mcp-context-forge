# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/common.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Shared Admin UI helpers: search/list utilities, team-id normalization, redirect building, and service singletons.
"""

# Standard
import logging
from typing import Any, Optional, Union
import urllib.parse
import uuid

# Third-Party
from fastapi import HTTPException, Query
import orjson
from sqlalchemy import and_, false, or_
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.auth_context import extract_token_team_ids, get_user_email
from mcpgateway.config import settings
from mcpgateway.services.a2a_service import A2AAgentService
from mcpgateway.services.export_service import ExportService
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.services.import_service import ImportService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import ServerService
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.services.tool_service import ToolService
from mcpgateway.utils.sqlalchemy_modifier import json_contains_tag_expr

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")


# Initialize services
server_service: ServerService = ServerService()
tool_service: ToolService = ToolService()
prompt_service: PromptService = PromptService()
gateway_service: GatewayService = GatewayService()
resource_service: ResourceService = ResourceService()
root_service: RootService = RootService()
export_service: ExportService = ExportService()
import_service: ImportService = ImportService()
# Initialize A2A service only if A2A features are enabled
a2a_service: Optional[A2AAgentService] = A2AAgentService() if settings.mcpgateway_a2a_enabled else None


def _normalize_team_id(team_id: Optional[str]) -> Optional[str]:
    """Validate and normalize team IDs for UI endpoints.

    Args:
        team_id: Raw team ID from request params.

    Returns:
        Normalized team ID string or None.

    Raises:
        ValueError: If the team ID is not a valid UUID.
    """
    if not team_id:
        return None
    try:
        return uuid.UUID(str(team_id)).hex
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("Invalid team ID") from exc


def _validated_team_id_param(team_id: Optional[str] = Query(None, description="Filter by team ID")) -> Optional[str]:
    """Normalize team ID query params and raise on invalid UUIDs.

    Args:
        team_id: Raw team ID from query params.

    Returns:
        Normalized team ID string or None.

    Raises:
        HTTPException: If the team ID is not a valid UUID.
    """
    try:
        return _normalize_team_id(team_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid team ID") from exc


def _form_team_id(form: Any) -> Optional[str]:
    """Extract and normalize team_id from form data, converting whitespace-only values to None.

    Normalizes at the point of extraction so that both the public-visibility guard
    and ``TeamManagementService.verify_team_for_user`` receive the same value, making
    ``?team_id=%20`` behave identically to an absent ``team_id`` end-to-end.

    Args:
        form: The multipart form data object from the request.

    Returns:
        The stripped team_id string, or None if absent or whitespace-only.
    """
    raw = form.get("team_id")
    if not raw:
        return None
    return str(raw).strip() or None


def _build_admin_redirect(
    root_path: str,
    fragment: str,
    *,
    error: Optional[str] = None,
    message: Optional[str] = None,
    include_inactive: bool = False,
    team_id: Optional[str] = None,
) -> str:
    """Build an admin redirect URL preserving query parameters.

    Args:
        root_path: The root path prefix for the application.
        fragment: The URL fragment/hash (e.g. "tools", "catalog").
        error: Optional error message to include as a query parameter.
        message: Optional success/info message to include as a query parameter.
        include_inactive: Whether the include_inactive flag was set.
        team_id: Optional team ID to preserve in the redirect.

    Returns:
        A fully constructed redirect URL string.
    """
    params: dict[str, str] = {}
    if error:
        params["error"] = error
    if message:
        params["message"] = message
    if include_inactive:
        params["include_inactive"] = "true"
    if team_id:
        try:
            params["team_id"] = _normalize_team_id(team_id)
        except ValueError:
            pass
    query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote) if params else ""
    sep = "/?" if query else ""
    return f"{root_path}/admin{sep}{query}#{fragment}"


def _escape_like(value: str) -> str:
    """Escape SQL LIKE wildcard characters.

    Args:
        value (str): Raw search string.

    Returns:
        str: Escaped string safe for use in ``LIKE`` expressions with ``ESCAPE '\\'``.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _like_contains(column, value: str):
    """Case-insensitive substring match with proper LIKE wildcard escaping.

    Wraps the escaped *value* with ``%`` wildcards and adds an explicit
    ``ESCAPE '\\\\'`` clause so that ``%`` and ``_`` in the search term are
    treated literally on all backends (SQLite requires the clause).

    Args:
        column: SQLAlchemy column expression (pre-wrapped with ``func.lower``
            / ``coalesce`` as needed by the caller).
        value: Raw search term — escaping is applied internally.

    Returns:
        A SQLAlchemy binary expression suitable for ``.where()``.
    """
    return column.like("%" + _escape_like(value) + "%", escape="\\")


async def _get_user_team_ids(user: dict, db: Session) -> list:
    """Return team IDs for the authenticated user.

    When called from :func:`admin_unified_search`, the user dict carries a
    ``_cached_team_ids`` key so the expensive lookup is executed only once
    per request instead of once per entity type.

    If the auth context includes explicit ``token_teams`` (API tokens), the
    returned IDs are derived from that token scope so search endpoints cannot
    return entities outside the token's team restrictions.

    Args:
        user (dict): Authenticated user context.
        db (Session): Database session.

    Returns:
        list: Team ID list for the user.
    """
    cached = user.get("_cached_team_ids")
    if cached is not None:
        return cached

    team_ids = extract_token_team_ids(user)
    if team_ids is not None:
        return team_ids

    user_email = get_user_email(user)
    team_service = TeamManagementService(db)
    user_teams = await team_service.get_user_teams(user_email)
    return [t.id for t in user_teams]


def _check_public_visibility_allowed(visibility: str, team_id: Optional[str] = None) -> None:
    """Raise HTTP 422 if public visibility is disabled and the request is team-scoped.

    Public visibility is only restricted when a team_id is present — on the
    global admin view (no team) public entities are still permitted.

    Args:
        visibility: The visibility value from the incoming form or request body.
        team_id: The team ID from the form or request body, if any.

    Raises:
        HTTPException: 422 when flag is false, team_id is set, and visibility is 'public'.
    """
    if not settings.allow_public_visibility and visibility == "public" and team_id and team_id.strip():
        raise HTTPException(
            status_code=422,
            detail="Public visibility is disabled by platform configuration (ALLOW_PUBLIC_VISIBILITY=false).",
        )


def _is_explicit_token_team_scope(user: Any) -> bool:
    """Return whether the auth context carries explicit token team scope.

    Tokens with ``token_teams`` present and not ``None`` are scope-constrained
    (including public-only tokens with ``[]``). ``None`` denotes admin bypass.

    Args:
        user (Any): Authenticated user context.

    Returns:
        bool: True when ``token_teams`` is present and not ``None``.
    """
    return extract_token_team_ids(user) is not None


def _owner_access_condition(owner_column, team_column, *, user_email: str, team_ids: list[str], user: Any):
    """Build owner visibility predicate honoring token team scoping.

    For explicit token scopes, owner visibility is constrained to token teams.
    For legacy/session contexts without explicit scope (or admin bypass), keep
    existing owner visibility semantics.

    Args:
        owner_column: SQLAlchemy owner-email column expression.
        team_column: SQLAlchemy team-id column expression.
        user_email (str): Current user email.
        team_ids (list[str]): Team IDs visible to this auth context.
        user (Any): Authenticated user context.

    Returns:
        Any: SQLAlchemy boolean predicate for owner visibility.
    """
    if _is_explicit_token_team_scope(user):
        if not team_ids:
            return false()
        return and_(owner_column == user_email, team_column.in_(team_ids))
    return owner_column == user_email


def _merge_select_all_ids(form: Any, flag_key: str, all_ids_key: str, checked_list: list[str]) -> list[str]:
    """Merge server-fetched IDs with UI-checked IDs when "Select All" is active.

    When the user clicks "Select All" in a paginated list, the browser populates
    *all_ids_key* with IDs fetched from the corresponding /ids endpoint. Because
    that endpoint may be team-scoped, it can miss platform-public items that are
    still visible (and checked) in the UI. Taking the union of both sources
    ensures every explicitly selected item is preserved.

    Note: both sources are client-supplied form values. Downstream persistence
    code is responsible for enforcing final access control on the merged IDs.

    Args:
        form: Starlette form object.
        flag_key (str): Form field that signals "Select All" mode (e.g. ``"selectAllTools"``).
        all_ids_key (str): Form field holding the JSON-encoded server-fetched IDs.
        checked_list (list[str]): IDs collected from checked checkboxes in the form.

    Returns:
        list[str]: Merged, deduplicated list of string IDs; or *checked_list* unchanged
        when Select All is not active or the JSON payload cannot be parsed.
    """
    if form.get(flag_key) != "true":
        return checked_list
    raw = form.get(all_ids_key) or "[]"
    try:
        server_ids = orjson.loads(raw)
        # Normalise to str to avoid silent int/str duplicates from different sources.
        merged = list({str(i) for i in server_ids} | set(checked_list))
        LOGGER.info("Select All (%s): %d items after merge", all_ids_key, len(merged))
        return merged
    except orjson.JSONDecodeError:
        LOGGER.warning("Failed to parse %s JSON, falling back to checked items", all_ids_key)
        return checked_list


def _normalize_search_query(query: Optional[str]) -> str:
    """Normalize search query values for consistent filtering.

    Args:
        query (Optional[str]): Raw query value or FastAPI ``Query`` wrapper.

    Returns:
        str: Lowercased, trimmed query string (empty string when unset).
    """
    if query is None:
        return ""
    if isinstance(query, str):
        return query.strip().lower()

    # Support direct unit-test invocation where FastAPI Query(...) defaults
    # can be passed through instead of resolved string values.
    default_value = getattr(query, "default", None)
    if default_value is None:
        return ""
    if isinstance(default_value, str):
        return default_value.strip().lower()
    return str(default_value).strip().lower()


def _normalize_tags_query(tags: Any) -> str:
    """Normalize tags query values.

    Handles plain strings and FastAPI `Query(...)` defaults when handlers are
    called directly in unit tests.

    Args:
        tags (Any): Raw tags value or FastAPI ``Query`` wrapper.

    Returns:
        str: Trimmed tags expression (empty string when unset).
    """
    if tags is None:
        return ""
    if isinstance(tags, str):
        return tags.strip()

    default_value = getattr(tags, "default", None)
    if default_value is None:
        return ""
    if isinstance(default_value, str):
        return default_value.strip()
    return str(default_value).strip()


def _normalize_int_query(value: Any, fallback: int) -> int:
    """Normalize integer query values, including FastAPI Query defaults.

    Args:
        value (Any): Raw integer value or FastAPI ``Query`` wrapper.
        fallback (int): Fallback value when normalization fails.

    Returns:
        int: Normalized integer value.
    """
    if isinstance(value, int):
        return value

    default_value = getattr(value, "default", None)
    if isinstance(default_value, int):
        return default_value

    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


_TAG_MAX_GROUPS = 20
_TAG_MAX_TERMS_PER_GROUP = 10


def _parse_tag_filter_groups(tags: Optional[str]) -> list[list[str]]:
    """Parse tag filter expressions.

    Expression syntax:
    - `,` separates OR groups (capped at :data:`_TAG_MAX_GROUPS`)
    - `+` separates AND terms inside a group (capped at :data:`_TAG_MAX_TERMS_PER_GROUP`)

    Examples:
      - `"prod,staging"` => [["prod"], ["staging"]]
      - `"mcp+critical"` => [["mcp", "critical"]]
      - `"mcp+critical,ui"` => [["mcp", "critical"], ["ui"]]

    Args:
        tags (Optional[str]): Tag expression with comma-separated OR groups and
            plus-separated AND terms.

    Returns:
        list[list[str]]: Parsed tag groups ready for SQL filter construction.
    """
    if not tags:
        return []

    groups: list[list[str]] = []
    for raw_group in tags.split(","):
        if len(groups) >= _TAG_MAX_GROUPS:
            break
        candidate = [term.strip() for term in raw_group.split("+") if term.strip()][:_TAG_MAX_TERMS_PER_GROUP]
        if candidate:
            groups.append(candidate)
    return groups


def _apply_tag_filter_groups(query: Any, db: Session, column: Any, tag_groups: list[list[str]]) -> Any:
    """Apply parsed tag filter groups to a SQLAlchemy query.

    Args:
        query (Any): SQLAlchemy ``select`` query to update.
        db (Session): Database session.
        column (Any): SQLAlchemy model column containing tags.
        tag_groups (list[list[str]]): Parsed OR-of-AND tag groups.

    Returns:
        Any: Updated query with tag filters applied.
    """
    if not tag_groups:
        return query

    group_exprs = []
    for group in tag_groups:
        # Single term group => OR semantics (term exists)
        # Multi-term group => AND semantics (all terms exist)
        group_exprs.append(json_contains_tag_expr(db, column, group, match_any=len(group) == 1))

    if len(group_exprs) == 1:
        return query.where(group_exprs[0])
    return query.where(or_(*group_exprs))


def _build_search_response(
    *,
    entity_key: str,
    entity_type: str,
    items: list[dict[str, Any]],
    query: str,
    tags: str,
    tag_groups: list[list[str]],
) -> dict[str, Any]:
    """Build a consistent search response while preserving legacy keys.

    Args:
        entity_key (str): Legacy entity key (for example ``tools``).
        entity_type (str): Canonical entity type label.
        items (list[dict[str, Any]]): Serialized entity items.
        query (str): Normalized free-text query.
        tags (str): Normalized tag expression.
        tag_groups (list[list[str]]): Parsed tag groups.

    Returns:
        dict[str, Any]: Unified search payload with legacy and standard keys.
    """
    filters_applied = {"q": query, "tags": tags, "tag_groups": tag_groups}
    return {
        entity_key: items,  # legacy key for backward compatibility
        "items": items,
        "count": len(items),
        "entity_type": entity_type,
        "query": query,
        "filters_applied": filters_applied,
    }


def get_user_id(user: Union[str, dict[str, Any], object] = None) -> str:
    """Return the user ID from a JWT payload, user object, or string.

    Args:
        user (Union[str, dict, object], optional): User object from JWT token
            (from get_current_user_with_permissions). Can be:
            - dict: representing JWT payload with 'id', 'user_id', or 'sub'
            - object: with an `id` attribute
            - str: a user ID string
            - None: will return "unknown"
            Defaults to None.

    Returns:
        str: User ID, or "unknown" if no ID can be determined.
             - If `user` is a dict, returns `id` if present, else `user_id`, else `sub`, else email as fallback, else "unknown".
             - If `user` has an `id` attribute, returns that.
             - If `user` is a string, returns it.
             - If `user` is None, returns "unknown".
             - Otherwise, returns str(user).

    Examples:
        >>> get_user_id({'id': '123'})
        '123'
        >>> get_user_id({'user_id': '456'})
        '456'
        >>> get_user_id({'sub': 'alice@example.com'})
        'alice@example.com'
        >>> get_user_id({'email': 'bob@company.com'})
        'bob@company.com'
        >>> class MockUser:
        ...     def __init__(self, user_id):
        ...         self.id = user_id
        >>> get_user_id(MockUser('789'))
        '789'
        >>> get_user_id(None)
        'unknown'
        >>> get_user_id('user-xyz')
        'user-xyz'
        >>> get_user_id({})
        'unknown'
    """
    if isinstance(user, dict):
        # Try multiple possible ID fields in order of preference.
        # Email is the primary key in the model, so that's our mostly likely result.
        return user.get("id") or user.get("user_id") or get_user_email(user)

    return "unknown" if user is None else str(getattr(user, "id", user))
