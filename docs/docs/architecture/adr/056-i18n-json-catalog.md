# ADR-056: English/Chinese i18n with Shared JSON Catalogs

- *Status:* Accepted
- *Date:* 2026-09-30
- *Deciders:* Platform Team

## Context

The Admin UI, the MCP Prompts pages, and the transactional email templates render English copy only. A user cannot read the interface in another language.

The Admin UI mixes two rendering paths. Jinja renders page shells and HTMX fragments on the server. A Vite bundle (`mcpgateway/admin_ui/*.js`) renders lists, modals, and toasts in the browser. A translation mechanism must serve both paths, or every string needs two sources of truth.

The gateway stores no locale for a user account. A first implementation must not require a database migration.

## Decision

Store every translatable string in a pair of JSON catalogs under `mcpgateway/i18n/locales/`:

- `en.json` holds the source strings.
- `zh-CN.json` holds the Chinese translations.

Both files carry the same key set. A flat dotted key names the surface, for example `tools.form.name` or `common.actions.save`. A value can hold `{name}` placeholders.

### Locale resolution

`mcpgateway/middleware/locale_middleware.py` resolves the locale for each request and stores it in a `ContextVar`. Resolution order:

1. The `mcpgateway_locale` cookie.
2. The `Accept-Language` header.
3. The default locale, `en`.

The middleware runs outermost. The locale therefore covers every later middleware and handler. The middleware resets the `ContextVar` in a `finally` block.

### One catalog, two renderers

`mcpgateway/main.py` registers five Jinja globals:

| Global | Purpose |
|---|---|
| `t` | Translate a key for the active locale. |
| `current_locale` | Return the active locale tag. |
| `supported_locales` | Map locale tags to display names. |
| `i18n_catalog` | Return the catalog for the active locale. |
| `i18n_ns` | Translate a key under a namespace prefix. |

`templates/_i18n_config.html` embeds the catalog for the active locale into `window.__I18N__`. `mcpgateway/admin_ui/i18n.js` reads that object and exports the same `t` function to the bundle. The bundle never passes through Jinja, so both renderers read one catalog.

`AuthEmailNotificationService` builds its own Jinja environment. It registers `t` and `current_locale` explicitly, because the globals on the application environment do not reach it.

### Locale persistence

`templates/_locale_switcher.html` writes the `mcpgateway_locale` cookie and reloads the page. The cookie is the only persisted state. No database column and no migration are required.

## Consequences

- A new translatable string needs an entry in both catalogs. `t()` returns the key when an entry is missing, so a gap is visible in the interface.
- A duplicate key in a catalog is silent at parse time. The later entry wins and produces wrong text. Check both catalogs for duplicate keys before each commit.
- The bundle cannot contain Jinja syntax. A literal `{{ t("key") }}` in `mcpgateway/admin_ui/*.js` reaches the browser unchanged. Use `${t("key")}` inside a template literal.
- A `t()` call at module scope is safe, because `_i18n_config.html` emits `window.__I18N__` before the bundle script tag.
- Backend API error messages stay in English. They are machine-readable contracts for clients, and a client can render its own message.
- A locale for a user account remains future work. The cookie covers the browser, not the API.

## Alternatives Considered

**A Python gettext catalog (`.po`/`.mo`).** The `msgfmt` toolchain covers the server, but not the browser bundle. The bundle would need a second mechanism or a build step that emits JavaScript.

**A per-string database table.** The table needs a migration, a cache, and an admin surface for edits. The cookie covers the requirement without that cost.

## References

- `mcpgateway/i18n/catalog.py` — resolution, lookup, and cache.
- `mcpgateway/i18n/__init__.py` — request-scoped locale and the `t()` function.
- `mcpgateway/middleware/locale_middleware.py` — locale middleware.
- `mcpgateway/admin_ui/i18n.js` — browser runtime.
- `docs/docs/development/i18n-glossary.md` — terminology and the non-translation list.
