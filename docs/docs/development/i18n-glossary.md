# i18n Glossary and Non-Translation List

This page fixes the Chinese terminology for the Admin UI and lists the strings that stay in English on purpose.

See [ADR-056](../architecture/adr/056-i18n-json-catalog.md) for the catalog design and the locale resolution order.

## Terminology

Use these translations. A new catalog entry that names one of these concepts must reuse the term.

| English | Chinese | Notes |
|---|---|---|
| Tool | 工具 | |
| Resource | 资源 | |
| Prompt | 提示词 | The MCP Prompts feature. |
| Server | 服务器 | A virtual server. |
| Virtual server | 虚拟服务器 | |
| Gateway | 网关 | |
| Root | 根目录 | MCP roots. |
| Team | 团队 | |
| User | 用户 | |
| Token | 令牌 | A JWT token. Never 代币. |
| API token | API 令牌 | |
| Session | 会话 | |
| Plugin | 插件 | |
| Hook | 钩子 | A plugin hook point. |
| Binding | 绑定 | A plugin binding. |
| Role | 角色 | An RBAC role. |
| Permission | 权限 | |
| Visibility | 可见性 | |
| Public | 公开 | Platform-public scope. |
| Private | 私有 | |
| Owner | 所有者 | |
| Metrics | 指标 | |
| Observability | 可观测性 | |
| Trace | 链路追踪 | |
| Span | 跨度 | |
| Log | 日志 | |
| Catalog | 目录 | An i18n catalog, or the MCP catalog. Read the context. |
| Schema | Schema | Keep the Latin form. |
| Cache | 缓存 | |
| Rate limit | 速率限制 | |
| Federation | 联邦 | |
| Configuration | 配置 | |
| Description | 描述 | |
| Version | 版本 | |
| Priority | 优先级 | |
| Deprecated | 已弃用 | |
| Disabled | 已禁用 | |
| Enabled | 已启用 | |
| Active | 启用 | A record state. |
| Inactive | 停用 | A record state. |
| Refresh | 刷新 | |
| Retry | 重试 | |
| Save | 保存 | |
| Cancel | 取消 | |
| Close | 关闭 | |
| Copy | 复制 | |
| Delete | 删除 | |
| Edit | 编辑 | |
| Search | 搜索 | |
| Filter | 筛选 | |
| Loading | 加载中 | |

## Punctuation

- Use the full-width comma `，`, the full-width period `。`, and the full-width colon `：`.
- Use the curly quotes `“…”` in Chinese values.
- Keep the ASCII hyphen inside a range that mixes Latin text, for example `显示第 1 - 10 条`.
- Use `…` for a trailing ellipsis, not three periods.

## Non-Translation List

Keep these strings in English in both catalogs. A translation would break a contract or confuse a reader.

### Protocol and product names

`MCP`, `A2A`, `REST`, `gRPC`, `SSE`, `WebSocket`, `stdio`, `HTTP`, `HTTPS`, `JSON`, `JSON-RPC`, `OAuth`, `JWT`, `RBAC`, `SSO`, `OTEL`, `CSV`, `UAID`, `UUID`, `Azure OpenAI`, `OpenAI`, `Anthropic`, `Ollama`, `Gemini`.

### Identifiers and technical names

- HTTP header names: `Authorization`, `X-Tenant-Id`, `X-Trace-Id`, `Content-Type`, `Cache-Control`, `X-CSRF-Token`.
- MIME types: `application/json`, `text/plain`.
- Environment variables: `DB_POOL_SIZE`, `JWT_SECRET_KEY`, `MCP_REQUIRE_AUTH`, and every other name from `mcpgateway/config.py`.
- Function names and code identifiers that appear in the interface: `normalize_token_teams()`, `repo read:user`.
- Log level and component names: `DEBUG`, `INFO`, `HTTP Gateway`.
- Catalog values that are CSS classes, DOM ids, or `data-*` values.

### Values that code compares

- `"Failed to fetch"` — compared against a browser `TypeError` message.
- `"Value must be an object"` — compared against a server message.
- `"Select All"` — a mode sentinel in the tools table.
- `"All Teams"` — a team sentinel in `mcpgateway/admin_ui/utils.js`.
- `"Unable to complete the operation. Please try again."` — compared against a server 409 body in `mcpgateway/admin_ui/tokens.js`.

A translated copy of any of these strings breaks the comparison. Translate the display label instead, and leave the compared value alone.

### Developer-facing text

- `console.log`, `console.warn`, and `console.error` arguments.
- Internal `throw new Error("...")` markers that no user reads.
- Code comments and docstrings.
- Test fixtures and assertions.

### Backend API error messages

`detail` values from the FastAPI layer stay in English. They are machine-readable contracts for API clients. The Admin UI renders its own message for a failed request.

## Adding a Translation

1. Add the key to `mcpgateway/i18n/locales/en.json` and to `mcpgateway/i18n/locales/zh-CN.json`.
2. Keep the key set identical in both files.
3. Keep every `{placeholder}` name identical in both values.
4. Check both catalogs for duplicate keys. A duplicate is silent at parse time and the later entry wins.
5. Use `t("key")` in a Jinja template, and `t("key")` or `${t("key")}` in `mcpgateway/admin_ui/*.js`. Never write Jinja syntax in a JavaScript file.
