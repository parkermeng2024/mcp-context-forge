# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/visibility.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI visibility rules: section-to-permission mappings, menu hiding, and UI action permission checks.
"""

# Standard
import inspect
import logging
import os
from typing import Any, Dict, List, Optional

# Third-Party
from fastapi import Request
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.common.validators import SecurityValidator
from mcpgateway.config import settings, UI_HIDABLE_HEADER_ITEMS, UI_HIDABLE_SECTIONS, UI_HIDE_SECTION_ALIASES
from mcpgateway.services.permission_service import PermissionService

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")


UI_SECTION_TO_TABS: Dict[str, tuple[str, ...]] = {
    "overview": ("overview",),
    "servers": ("catalog",),
    "gateways": ("gateways",),
    "tools": ("tools", "tool-ops"),
    "prompts": ("prompts",),
    "resources": ("resources",),
    "roots": ("roots",),
    "mcp-registry": ("mcp-registry",),
    "metrics": ("metrics",),
    "plugins": ("plugins",),
    "export-import": ("export-import",),
    "logs": ("logs",),
    "version-info": ("version-info",),
    "maintenance": ("maintenance",),
    "teams": ("teams",),
    "users": ("users",),
    "agents": ("a2a-agents",),
    "grpc-services": ("grpc-services",),
    "tokens": ("tokens",),
    "settings": ("llm-settings",),
}

# Section-to-permission mapping for menu visibility
# Maps UI section names to required RBAC permissions
# NOTE: This mapping must be kept in sync with @require_permission decorators on admin routes.
# The validate_section_permissions() function (called at startup) verifies consistency.
SECTION_PERMISSIONS: Dict[str, Optional[str]] = {
    # Admin-only sections
    "users": "admin.user_management",
    "maintenance": "admin.system_config",
    "logs": "admin.system_config",
    "export-import": "admin.system_config",
    "plugins": "admin.plugins",
    "metrics": "admin.system_config",
    "version-info": "admin.system_config",
    "settings": "admin.system_config",
    "llm-providers": "admin.system_config",
    "llm-models": "admin.system_config",
    "llm-api-info": "admin.system_config",
    # Core sections (accessible to developers and above)
    "tools": "tools.read",
    "servers": "servers.read",
    "resources": "resources.read",
    "prompts": "prompts.read",
    "gateways": "gateways.read",
    # Team management sections
    "teams": "teams.read",
    "tokens": "tokens.read",
    # A2A agents
    "agents": "a2a.read",
    # gRPC services (separate from A2A - requires admin.grpc)
    "grpc-services": "admin.grpc",
    # Overview and roots
    "overview": "admin.overview",  # Requires admin permission
    "roots": "admin.system_config",  # Roots routes use admin.system_config
    "mcp-registry": "servers.read",  # Catalog is part of servers
}

# Section-to-route-path mapping for validation
# NOTE: Only includes routes that exist on admin_router itself.
# Routes on other routers (version.py, llm_admin_router, etc.) are excluded
# from validation since they're mounted separately and have their own decorators.
_SECTION_TO_ROUTE_PATH: Dict[str, str] = {
    "users": "/admin/users/partial",
    "maintenance": "/admin/maintenance/partial",
    "logs": "/admin/logs",
    "export-import": "/admin/export/configuration",
    "plugins": "/admin/plugins/partial",
    "metrics": "/admin/metrics",
    # "version-info": "/admin/version",  # Route is on version.py router, not admin_router
    # "settings": "/admin/llm-settings",  # No such route exists
    # "llm-providers": "/admin/llm/providers/html",  # Route is on llm_admin_router
    # "llm-models": "/admin/llm/models/html",  # Route is on llm_admin_router
    # "llm-api-info": "/admin/llm/api-info/html",  # Route is on llm_admin_router
    "tools": "/admin/tools/partial",
    "servers": "/admin/servers/partial",
    "resources": "/admin/resources/partial",
    "prompts": "/admin/prompts/partial",
    "gateways": "/admin/gateways/partial",
    "teams": "/admin/teams/partial",
    "tokens": "/admin/tokens/partial",
    "agents": "/admin/a2a/partial",
    "overview": "/admin/overview/partial",
    # "roots": "/admin/roots/partial",  # No such route exists on admin_router
    "mcp-registry": "/admin/servers/partial",
}


def _extract_permission_from_route(route) -> Optional[str]:
    """Extract the required permission from a route's @require_permission decorator.

    This function reads the permission metadata set by the decorator as a function attribute.
    This approach is more robust than closure introspection and immune to decorator
    implementation changes.

    Args:
        route: FastAPI route object

    Returns:
        Permission string if found (e.g., "tools.read"), None otherwise
    """
    try:
        if not hasattr(route, "endpoint"):
            return None

        endpoint = route.endpoint

        # Simply read the metadata attribute set by @require_permission decorator
        return getattr(endpoint, "_required_permission", None)

    except Exception as e:
        LOGGER.debug(f"Error extracting permission from route {getattr(route, 'path', 'unknown')}: {e}")

    return None


def validate_section_permissions(router) -> None:
    """Validate that SECTION_PERMISSIONS matches actual route decorators.

    This function is called at application startup to ensure the hardcoded
    SECTION_PERMISSIONS mapping is consistent with the @require_permission
    decorators on admin routes. Logs warnings for any mismatches.

    In test/CI environments, raises ValueError on mismatches to fail fast.
    In production, logs warnings only to avoid breaking deployments.

    Args:
        router: FastAPI APIRouter instance (admin_router)

    Raises:
        ValueError: In test/CI environments when mismatches are found
    """
    mismatches = []

    for section, expected_perm in SECTION_PERMISSIONS.items():
        route_path = _SECTION_TO_ROUTE_PATH.get(section)

        if route_path is None:
            # Section's route located on a different sub-router, skipping validation
            continue

        # Find matching route
        actual_perm = None
        for route in router.routes:
            if hasattr(route, "path") and route.path == route_path:
                actual_perm = _extract_permission_from_route(route)
                break

        # Compare expected vs actual
        if expected_perm != actual_perm:
            mismatches.append({"section": section, "route": route_path, "expected": expected_perm, "actual": actual_perm})

    if mismatches:
        error_msg = f"SECTION_PERMISSIONS validation found {len(mismatches)} mismatches with route decorators:"
        for m in mismatches:
            error_msg += f"\n  Section '{m['section']}' (route: {m['route']}): expected '{m['expected']}', found '{m['actual']}'"

        # Detect test/CI environment
        is_test_env = (
            os.getenv("PYTEST_CURRENT_TEST") is not None  # pytest is running
            or os.getenv("CI") is not None  # CI environment (GitHub Actions, GitLab CI, etc.)
            or os.getenv("GITHUB_ACTIONS") is not None  # GitHub Actions specifically
        )

        if is_test_env:
            # Hard error in test/CI to fail fast
            raise ValueError(error_msg)
        # Warning only in production to avoid breaking deployments
        LOGGER.warning(error_msg)
        LOGGER.warning("This may indicate the mapping needs updating.")
    else:
        validated_count = len(_SECTION_TO_ROUTE_PATH)
        LOGGER.info(f"SECTION_PERMISSIONS validation passed: all {validated_count} mapped sections verified (skipped {len(SECTION_PERMISSIONS) - validated_count} sections on other routers)")


UI_EMBEDDED_DEFAULT_HIDDEN_HEADER_ITEMS: frozenset[str] = frozenset({"logout", "team_selector"})
UI_HIDE_SECTIONS_COOKIE_NAME = "mcpgateway_ui_hide_sections"
UI_HIDE_SECTIONS_COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # 30 days


def _normalize_ui_hide_values(raw: Any, valid_values: frozenset[str], aliases: Optional[Dict[str, str]] = None) -> set[str]:
    """Normalize UI hide values from CSV/list input into a validated set.

    Args:
        raw: Source value (CSV string, iterable, or ``None``).
        valid_values: Allowed normalized values.
        aliases: Optional alias mapping to canonical values.

    Returns:
        set[str]: Lowercase validated values with aliases resolved.
    """
    if raw is None:
        return set()

    tokens: list[str] = []
    if isinstance(raw, str):
        tokens = [item.strip() for item in raw.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        tokens = [str(item).strip() for item in raw]
    else:
        return set()

    normalized: set[str] = set()
    for token in tokens:
        if not token:
            continue
        item = token.lower()
        if aliases:
            item = aliases.get(item, item)
        if item in valid_values:
            normalized.add(item)
    return normalized


def get_ui_visibility_config(request: Request, is_admin: bool = False) -> Dict[str, Any]:
    """Build final UI visibility settings for the current admin request.

    Args:
        request: Incoming FastAPI request.
        is_admin: Whether the current user is an admin. Admins use separate
            hide lists and are not affected by embedded-mode defaults.

    Returns:
        Dict[str, Any]: Hidden sections/header items/tabs plus cookie update intent.
    """
    if is_admin:
        hidden_sections = _normalize_ui_hide_values(getattr(settings, "mcpgateway_ui_hide_sections_admin", []), UI_HIDABLE_SECTIONS, UI_HIDE_SECTION_ALIASES)
        hidden_header_items = _normalize_ui_hide_values(getattr(settings, "mcpgateway_ui_hide_header_items_admin", []), UI_HIDABLE_HEADER_ITEMS)
    else:
        hidden_sections = _normalize_ui_hide_values(getattr(settings, "mcpgateway_ui_hide_sections", []), UI_HIDABLE_SECTIONS, UI_HIDE_SECTION_ALIASES)
        hidden_header_items = _normalize_ui_hide_values(getattr(settings, "mcpgateway_ui_hide_header_items", []), UI_HIDABLE_HEADER_ITEMS)

        if bool(getattr(settings, "mcpgateway_ui_embedded", False)):
            hidden_header_items.update(UI_EMBEDDED_DEFAULT_HIDDEN_HEADER_ITEMS)

    query_ui_hide_raw = request.query_params.get("ui_hide")
    query_ui_hide_values = _normalize_ui_hide_values(query_ui_hide_raw, UI_HIDABLE_SECTIONS, UI_HIDE_SECTION_ALIASES) if query_ui_hide_raw is not None else set()

    if query_ui_hide_raw is not None:
        # Query override is additive and also becomes the persisted session value.
        hidden_sections.update(query_ui_hide_values)
    else:
        cookie_ui_hide_raw = request.cookies.get(UI_HIDE_SECTIONS_COOKIE_NAME)
        hidden_sections.update(_normalize_ui_hide_values(cookie_ui_hide_raw, UI_HIDABLE_SECTIONS, UI_HIDE_SECTION_ALIASES))

    hidden_tabs: set[str] = set()
    for section in hidden_sections:
        hidden_tabs.update(UI_SECTION_TO_TABS.get(section, ()))

    cookie_action: Optional[str] = None
    cookie_value: Optional[str] = None
    if query_ui_hide_raw is not None:
        # Empty query clears persisted overrides.
        if query_ui_hide_values:
            cookie_action = "set"
            cookie_value = ",".join(sorted(query_ui_hide_values))
        else:
            cookie_action = "delete"

    return {
        "hidden_sections": sorted(hidden_sections),
        "hidden_header_items": sorted(hidden_header_items),
        "hidden_tabs": sorted(hidden_tabs),
        "cookie_action": cookie_action,
        "cookie_value": cookie_value,
    }


async def get_hidden_sections_for_user(
    db: Session,
    user_email: str,
    is_admin: bool,
    token_teams: Optional[List[str]],
    static_hidden: set[str],
) -> set[str]:
    """Determine which menu sections should be hidden based on user permissions.

    This function implements permission-based menu hiding by checking if the user
    has the required permission for each section. Sections without required permissions
    are added to the hidden set.

    Args:
        db: Database session
        user_email: Email of the authenticated user
        is_admin: Whether the user is a platform admin
        token_teams: Normalized token team scope (None for unrestricted admin, [] for public-only)
        static_hidden: Sections already hidden by static configuration (UI_HIDDEN_SECTIONS)

    Returns:
        set[str]: Complete set of sections to hide (static + permission-based)

    Examples:
        >>> import asyncio
        >>> from unittest.mock import Mock
        >>> db = Mock()
        >>> # Platform admin with unrestricted token sees all sections
        >>> result = asyncio.run(get_hidden_sections_for_user(db, "admin@example.com", True, None, set()))
        >>> isinstance(result, set)
        True
    """
    # Start with static hidden sections (always hidden regardless of permissions)
    hidden = set(static_hidden)

    # Platform admins with unrestricted tokens (token_teams=None) bypass permission checks
    if is_admin and token_teams is None:
        return hidden

    # Initialize permission service
    permission_service = PermissionService(db, audit_enabled=False)

    # Batch-fetch all permissions for the user (single DB query) when the real
    # permission service is available. Some tests patch only check_permission(),
    # so fall back to per-section checks if get_user_permissions() is absent or
    # not awaitable on the patched object.
    user_permissions: Optional[set[str]] = None
    try:
        maybe_permissions = permission_service.get_user_permissions(
            user_email=user_email,
            team_id=None,  # Check across all teams
            include_all_teams=True,  # Include all team-scoped roles
            token_teams=token_teams,  # SECURITY: Respect token narrowing for menu visibility
        )
        if inspect.isawaitable(maybe_permissions):
            user_permissions = await maybe_permissions
        else:
            LOGGER.debug(f"Falling back to per-section permission checks for user {user_email}: get_user_permissions() is not awaitable")
    except Exception as e:
        LOGGER.debug(f"Falling back to per-section permission checks for user {user_email}: {e}")

    for section, required_permission in SECTION_PERMISSIONS.items():
        # Skip if already hidden by static config
        if section in hidden:
            continue

        # Skip sections with no permission requirement (defensive check for future sections)
        if required_permission is None:
            continue

        if user_permissions is not None:
            # SECURITY: Mirror check_permission() behavior — public-only tokens
            # (token_teams=[]) must never satisfy admin.* permissions.
            if required_permission.startswith("admin.") and token_teams is not None and len(token_teams) == 0:
                has_permission = False
            else:
                # In-memory check after a single batched permission fetch.
                has_permission = required_permission in user_permissions or "*" in user_permissions
        else:
            try:
                has_permission = await permission_service.check_permission(
                    user_email=user_email,
                    permission=required_permission,
                    token_teams=token_teams,
                    allow_admin_bypass=False,
                    check_any_team=True,
                )
            except Exception as e:
                LOGGER.warning(
                    "Error checking permission %s for user %s: %s",
                    SecurityValidator.sanitize_log_message(required_permission),
                    SecurityValidator.sanitize_log_message(user_email),
                    SecurityValidator.sanitize_log_message(str(e)),
                )
                has_permission = False

        # Hide section if user doesn't have permission
        if not has_permission:
            hidden.add(section)
            LOGGER.debug(
                "Hiding section '%s' for user %s: missing permission '%s'",
                SecurityValidator.sanitize_log_message(section),
                SecurityValidator.sanitize_log_message(user_email),
                SecurityValidator.sanitize_log_message(required_permission),
            )

    return hidden


# UI Action Permissions Mapping
# Maps UI permission flags to required RBAC permissions
UI_ACTION_PERMISSIONS = {
    # Create actions
    "can_create_team": "teams.create",
    "can_create_server": "servers.create",
    "can_create_tool": "tools.create",
    "can_create_resource": "resources.create",
    "can_create_prompt": "prompts.create",
    "can_create_gateway": "gateways.create",
    "can_create_user": "admin.user_management",
    "can_create_token": "tokens.read",  # Token creation uses tokens.read, setting nosec cause this is false positive as router uses this permission key.  # nosec B105
    "can_create_agent": "a2a.create",
}


async def get_user_action_permissions(
    db: Session,
    user_email: str,
    is_admin: bool,
    token_teams: Optional[List[str]],
) -> Dict[str, bool]:
    """Batch-check all UI action permissions for a user.

    Returns a dictionary mapping permission flags to boolean values.
    Platform admins with unrestricted tokens get all permissions.

    Args:
        db: Database session
        user_email: User's email
        is_admin: Whether user is platform admin
        token_teams: Normalized token team scope (None for unrestricted admin, [] for public-only)

    Returns:
        Dict mapping permission flags (e.g., "can_create_team") to bool

    Examples:
        >>> import asyncio
        >>> from unittest.mock import Mock
        >>> db = Mock()
        >>> # Platform admin with unrestricted token gets all permissions
        >>> result = asyncio.run(get_user_action_permissions(db, "admin@example.com", True, None))
        >>> result["can_create_team"]
        True
        >>> result["can_create_server"]
        True
    """
    # Platform admins with unrestricted tokens bypass all checks
    if is_admin and token_teams is None:
        return {flag: True for flag in UI_ACTION_PERMISSIONS}

    # Initialize permission service
    permission_service = PermissionService(db, audit_enabled=False)

    # Batch check all permissions
    result = {}
    for flag, permission in UI_ACTION_PERMISSIONS.items():
        try:
            has_permission = await permission_service.check_permission(
                user_email=user_email,
                permission=permission,
                token_teams=token_teams,
                allow_admin_bypass=False,  # UI visibility matches team-scoped permissions (no admin bypass)
                check_any_team=True,
            )
            result[flag] = has_permission
        except Exception as e:
            # Fail-closed: deny permission on error
            LOGGER.warning("Error checking %s for %s: %s", SecurityValidator.sanitize_log_message(permission), SecurityValidator.sanitize_log_message(user_email), e)
            result[flag] = False

    return result
