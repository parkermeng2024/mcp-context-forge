# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/admin/test_routes.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Baseline route snapshot for the Admin UI router.

Captures the exact set of (method, path) pairs registered on
``mcpgateway.admin.admin_router`` so that the admin monolith split
(package conversion and submodule extraction) fails loudly if any
extraction step drops or alters a route.
"""

# First-Party
from mcpgateway.admin import admin_router

EXPECTED_ROUTE_COUNT = 208

EXPECTED_ROUTES = frozenset(
    {
        ("DELETE", "/admin/gateways/{gateway_id}"),
        ("DELETE", "/admin/observability/queries/{query_id}"),
        ("DELETE", "/admin/teams/{team_id}"),
        ("DELETE", "/admin/teams/{team_id}/join-request/{request_id}"),
        ("DELETE", "/admin/tokens/{token_id}"),
        ("DELETE", "/admin/users/{user_email}"),
        ("GET", "/admin/"),
        ("GET", "/admin/a2a"),
        ("GET", "/admin/a2a/ids"),
        ("GET", "/admin/a2a/partial"),
        ("GET", "/admin/a2a/plugin-bindings/partial"),
        ("GET", "/admin/a2a/search"),
        ("GET", "/admin/a2a/{agent_id}"),
        ("GET", "/admin/cache/a2a-stats/stats"),
        ("GET", "/admin/change-password-required"),
        ("GET", "/admin/config/passthrough-headers"),
        ("GET", "/admin/config/passthrough-headers/cache-stats"),
        ("GET", "/admin/config/settings"),
        ("GET", "/admin/events"),
        ("GET", "/admin/export/configuration"),
        ("GET", "/admin/forgot-password"),
        ("GET", "/admin/gateways"),
        ("GET", "/admin/gateways/ids"),
        ("GET", "/admin/gateways/partial"),
        ("GET", "/admin/gateways/search"),
        ("GET", "/admin/gateways/{gateway_id}"),
        ("GET", "/admin/grpc"),
        ("GET", "/admin/grpc/{service_id}"),
        ("GET", "/admin/grpc/{service_id}/methods"),
        ("GET", "/admin/import/status"),
        ("GET", "/admin/import/status/{import_id}"),
        ("GET", "/admin/login"),
        ("GET", "/admin/logout"),
        ("GET", "/admin/logs"),
        ("GET", "/admin/logs/export"),
        ("GET", "/admin/logs/file"),
        ("GET", "/admin/logs/stream"),
        ("GET", "/admin/maintenance/partial"),
        ("GET", "/admin/mcp-registry/partial"),
        ("GET", "/admin/mcp-registry/servers"),
        ("GET", "/admin/mcp-registry/{server_id}/status"),
        ("GET", "/admin/metrics"),
        ("GET", "/admin/metrics/partial"),
        ("GET", "/admin/observability/metrics/heatmap"),
        ("GET", "/admin/observability/metrics/partial"),
        ("GET", "/admin/observability/metrics/percentiles"),
        ("GET", "/admin/observability/metrics/timeseries"),
        ("GET", "/admin/observability/metrics/top-errors"),
        ("GET", "/admin/observability/metrics/top-slow"),
        ("GET", "/admin/observability/metrics/top-volume"),
        ("GET", "/admin/observability/partial"),
        ("GET", "/admin/observability/prompts/errors"),
        ("GET", "/admin/observability/prompts/partial"),
        ("GET", "/admin/observability/prompts/performance"),
        ("GET", "/admin/observability/prompts/usage"),
        ("GET", "/admin/observability/queries"),
        ("GET", "/admin/observability/queries/{query_id}"),
        ("GET", "/admin/observability/resources/errors"),
        ("GET", "/admin/observability/resources/partial"),
        ("GET", "/admin/observability/resources/performance"),
        ("GET", "/admin/observability/resources/usage"),
        ("GET", "/admin/observability/stats"),
        ("GET", "/admin/observability/tools/chains"),
        ("GET", "/admin/observability/tools/errors"),
        ("GET", "/admin/observability/tools/partial"),
        ("GET", "/admin/observability/tools/performance"),
        ("GET", "/admin/observability/tools/usage"),
        ("GET", "/admin/observability/trace/{trace_id}"),
        ("GET", "/admin/observability/traces"),
        ("GET", "/admin/overview/partial"),
        ("GET", "/admin/performance/cache"),
        ("GET", "/admin/performance/history"),
        ("GET", "/admin/performance/requests"),
        ("GET", "/admin/performance/stats"),
        ("GET", "/admin/performance/system"),
        ("GET", "/admin/performance/workers"),
        ("GET", "/admin/plugins"),
        ("GET", "/admin/plugins/partial"),
        ("GET", "/admin/plugins/stats"),
        ("GET", "/admin/plugins/{name}"),
        ("GET", "/admin/prompts"),
        ("GET", "/admin/prompts/ids"),
        ("GET", "/admin/prompts/partial"),
        ("GET", "/admin/prompts/search"),
        ("GET", "/admin/prompts/{prompt_id}"),
        ("GET", "/admin/reset-password/{token}"),
        ("GET", "/admin/resources"),
        ("GET", "/admin/resources/ids"),
        ("GET", "/admin/resources/partial"),
        ("GET", "/admin/resources/search"),
        ("GET", "/admin/resources/test/{resource_uri:path}"),
        ("GET", "/admin/resources/{resource_id}"),
        ("GET", "/admin/roots/export"),
        ("GET", "/admin/roots/search"),
        ("GET", "/admin/roots/{uri:path}"),
        ("GET", "/admin/search"),
        ("GET", "/admin/sections/gateways"),
        ("GET", "/admin/sections/prompts"),
        ("GET", "/admin/sections/resources"),
        ("GET", "/admin/sections/servers"),
        ("GET", "/admin/servers"),
        ("GET", "/admin/servers/ids"),
        ("GET", "/admin/servers/partial"),
        ("GET", "/admin/servers/search"),
        ("GET", "/admin/servers/{server_id}"),
        ("GET", "/admin/support-bundle/generate"),
        ("GET", "/admin/system/stats"),
        ("GET", "/admin/tags"),
        ("GET", "/admin/teams"),
        ("GET", "/admin/teams/ids"),
        ("GET", "/admin/teams/partial"),
        ("GET", "/admin/teams/search"),
        ("GET", "/admin/teams/{team_id}/edit"),
        ("GET", "/admin/teams/{team_id}/join-requests"),
        ("GET", "/admin/teams/{team_id}/members"),
        ("GET", "/admin/teams/{team_id}/members/add"),
        ("GET", "/admin/teams/{team_id}/members/partial"),
        ("GET", "/admin/teams/{team_id}/non-members/partial"),
        ("GET", "/admin/tokens/partial"),
        ("GET", "/admin/tokens/search"),
        ("GET", "/admin/tool-ops/partial"),
        ("GET", "/admin/tools"),
        ("GET", "/admin/tools/ids"),
        ("GET", "/admin/tools/partial"),
        ("GET", "/admin/tools/search"),
        ("GET", "/admin/tools/{tool_id}"),
        ("GET", "/admin/users"),
        ("GET", "/admin/users/partial"),
        ("GET", "/admin/users/search"),
        ("GET", "/admin/users/{user_email}/edit"),
        ("POST", "/admin/a2a"),
        ("POST", "/admin/a2a/plugin-bindings"),
        ("POST", "/admin/a2a/plugin-bindings/{binding_id}/delete"),
        ("POST", "/admin/a2a/{agent_id}/delete"),
        ("POST", "/admin/a2a/{agent_id}/edit"),
        ("POST", "/admin/a2a/{agent_id}/state"),
        ("POST", "/admin/a2a/{agent_id}/test"),
        ("POST", "/admin/cache/a2a-stats/invalidate"),
        ("POST", "/admin/change-password-required"),
        ("POST", "/admin/config/passthrough-headers/invalidate-cache"),
        ("POST", "/admin/export/selective"),
        ("POST", "/admin/forgot-password"),
        ("POST", "/admin/gateways"),
        ("POST", "/admin/gateways/discover-oauth"),
        ("POST", "/admin/gateways/test"),
        ("POST", "/admin/gateways/{gateway_id}/delete"),
        ("POST", "/admin/gateways/{gateway_id}/edit"),
        ("POST", "/admin/gateways/{gateway_id}/state"),
        ("POST", "/admin/gateways/{gateway_id}/transfer-ownership"),
        ("POST", "/admin/grpc"),
        ("POST", "/admin/grpc/{service_id}/delete"),
        ("POST", "/admin/grpc/{service_id}/reflect"),
        ("POST", "/admin/grpc/{service_id}/state"),
        ("POST", "/admin/import/configuration"),
        ("POST", "/admin/import/preview"),
        ("POST", "/admin/login"),
        ("POST", "/admin/logout"),
        ("POST", "/admin/mcp-registry/bulk-register"),
        ("POST", "/admin/mcp-registry/{server_id}/register"),
        ("POST", "/admin/metrics/reset"),
        ("POST", "/admin/observability/queries"),
        ("POST", "/admin/observability/queries/{query_id}/use"),
        ("POST", "/admin/prompts"),
        ("POST", "/admin/prompts/{prompt_id}/delete"),
        ("POST", "/admin/prompts/{prompt_id}/edit"),
        ("POST", "/admin/prompts/{prompt_id}/state"),
        ("POST", "/admin/reset-password/{token}"),
        ("POST", "/admin/resources"),
        ("POST", "/admin/resources/{resource_id}/delete"),
        ("POST", "/admin/resources/{resource_id}/edit"),
        ("POST", "/admin/resources/{resource_id}/state"),
        ("POST", "/admin/roots"),
        ("POST", "/admin/roots/{uri:path}/delete"),
        ("POST", "/admin/roots/{uri:path}/update"),
        ("POST", "/admin/servers"),
        ("POST", "/admin/servers/{server_id}/delete"),
        ("POST", "/admin/servers/{server_id}/edit"),
        ("POST", "/admin/servers/{server_id}/state"),
        ("POST", "/admin/teams"),
        ("POST", "/admin/teams/{team_id}/add-member"),
        ("POST", "/admin/teams/{team_id}/join-request"),
        ("POST", "/admin/teams/{team_id}/join-requests/{request_id}/approve"),
        ("POST", "/admin/teams/{team_id}/join-requests/{request_id}/reject"),
        ("POST", "/admin/teams/{team_id}/leave"),
        ("POST", "/admin/teams/{team_id}/remove-member"),
        ("POST", "/admin/teams/{team_id}/update"),
        ("POST", "/admin/teams/{team_id}/update-member-role"),
        ("POST", "/admin/tools"),
        ("POST", "/admin/tools/"),
        ("POST", "/admin/tools/generate-schemas-from-openapi"),
        ("POST", "/admin/tools/import"),
        ("POST", "/admin/tools/import/"),
        ("POST", "/admin/tools/{tool_id}/delete"),
        ("POST", "/admin/tools/{tool_id}/edit"),
        ("POST", "/admin/tools/{tool_id}/edit/"),
        ("POST", "/admin/tools/{tool_id}/state"),
        ("POST", "/admin/users"),
        ("POST", "/admin/users/{user_email}/activate"),
        ("POST", "/admin/users/{user_email}/deactivate"),
        ("POST", "/admin/users/{user_email}/force-password-change"),
        ("POST", "/admin/users/{user_email}/unlock"),
        ("POST", "/admin/users/{user_email}/update"),
        ("PUT", "/admin/config/passthrough-headers"),
        ("PUT", "/admin/gateways/{gateway_id}"),
        ("PUT", "/admin/grpc/{service_id}"),
        ("PUT", "/admin/observability/queries/{query_id}"),
        ("PUT", "/admin/plugins"),
        ("PUT", "/admin/plugins/{name}"),
    }
)

CRITICAL_ENDPOINT_NAMES = frozenset(
    {
        "admin_home",
        "admin_login_page",
        "admin_login_handler",
        "admin_logout_get",
        "admin_logout_post",
        "admin_list_tools",
        "admin_add_tool",
        "admin_unified_search",
    }
)


def _actual_route_pairs() -> set:
    """Collect (method, path) pairs from the live router, skipping HEAD/OPTIONS."""
    pairs = set()
    for route in admin_router.routes:
        for method in getattr(route, "methods", None) or ():
            if method in ("HEAD", "OPTIONS"):
                continue
            pairs.add((method, route.path))
    return pairs


def test_admin_router_route_count():
    """The router registers exactly the snapshotted number of route objects."""
    assert len(admin_router.routes) == EXPECTED_ROUTE_COUNT


def test_admin_router_route_snapshot():
    """The (method, path) set on the router matches the snapshot exactly."""
    actual = _actual_route_pairs()
    missing = EXPECTED_ROUTES - actual
    added = actual - EXPECTED_ROUTES
    assert not missing and not added, f"admin_router route drift:\n  missing: {sorted(missing)}\n  added: {sorted(added)}"


def test_admin_router_one_method_per_route():
    """Every route object contributes exactly one non-HEAD/OPTIONS method."""
    assert len(_actual_route_pairs()) == len(admin_router.routes)


def test_admin_router_critical_endpoint_names():
    """Spot-check that critical endpoint names survive on the router."""
    names = {route.name for route in admin_router.routes}
    missing = CRITICAL_ENDPOINT_NAMES - names
    assert not missing, f"admin_router missing endpoint names: {sorted(missing)}"
