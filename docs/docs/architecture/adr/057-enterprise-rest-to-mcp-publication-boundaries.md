# ADR-0057: Enterprise REST-to-MCP Publication Boundaries

- *Status:* Proposed
- *Date:* 2026-10-04
- *Deciders:* Core Engineering Team
- *Related:* [Enterprise REST API to MCP proposal](../../development/enterprise-rest-api-to-mcp-proposal.md)

## Context

A proposal adds an enterprise API directory, an OpenAPI-to-tool converter, and a publication workflow to the Admin UI. An engineering review, a design review, and two independent external reviewers found decisions that must hold before implementation. Each decision constrains existing code, so it belongs here and not only in the proposal.

The findings that drive the decisions:

- `tool_service.invoke_tool` merges mapped query parameters into the JSON body for POST, PUT, PATCH, and DELETE. One REST tool cannot send query parameters and a JSON body at the same time.
- `openapi_service._do_fetch` sends no authentication header. A catalog that requires a key or token cannot be synchronized.
- `ServerService.register_server` defaults visibility to `"public"`. `ToolCreate.visibility` defaults to `None`.
- The `allowlist` and `expose_passthrough` tool columns are written but never read on the invocation path.

## Decision

1. **Per-location parameter mapping.** The converter emits an explicit location for every parameter: path, query, header, or body. Extending the REST invocation path to honor locations is a Phase 0 gate. Phase 1 does not start until a combined query-plus-body operation round-trips.
2. **Database-enforced publication idempotency.** `ApiPublication` carries a unique index on `(scope, idempotency_key)`. The workflow claims the key with an insert and treats a constraint conflict as the replay path. Cleanup deletes by recorded resource ID, never by generated name.
3. **On-demand source synchronization.** The first release syncs a source only when an administrator triggers it. The gateway adds no scheduler.
4. **Explicit private visibility.** Every creation call passes `visibility="private"`. Code does not rely on a default.
5. **No reliance on inert fields.** Egress control comes from `SecurityValidator.validate_url_for_connection_pinning`. The `allowlist` and `expose_passthrough` columns are not an enforcement boundary until the invocation path reads them.
6. **Reuse over new services.** The converter extends `mcpgateway/services/openapi_service.py` and the directory mirrors `CatalogService`. The plan does not add three parallel services.

## Consequences

- ✅ Published tools preserve REST semantics for mixed-location operations.
- ✅ Concurrent retries cannot double-publish.
- ✅ Private-by-default holds even when a caller omits visibility.
- 🔄 The REST invocation path changes, which touches existing REST tool behavior. Phase 0 proves the change on representative documents before UI work starts.
- 🔄 On-demand sync means directory metadata goes stale until an administrator triggers a sync.
- 🔍 `allowlist` and `expose_passthrough` remain unused. Remove them or implement enforcement in a separate change.

## Alternatives Considered

| Option | Why Not |
|------------------------------------------|--------------------------------------------------------------------------|
| Application-level idempotency check | Races under concurrent retries; a database constraint is the only reliable guard |
| Cleanup by generated tool name | Deletes the first attempt's tools when a retry fails |
| New independent converter service | Duplicates the existing fetch, SSRF, and schema-extraction path |
| Periodic in-process sync | Adds scheduler and coordination work that Phase 1 does not need |
| Rely on `register_server` defaults | Publishes public when a caller omits visibility |

## Status

Proposed. Not implemented. The proposal is untracked and the review findings remain open.
