import { getAuthHeaders } from "./auth.js";
import { t } from "./i18n.js";
import {
  escapeHtml,
  logRestrictedContext,
  parseErrorResponse,
} from "./security.js";
import {
  buildTableUrl,
  copyToClipboard,
  fetchWithTimeout,
  getCookie,
  getCurrentTeamId,
  getCurrentTeamName,
  getPaginationParams,
  safeGetElement,
  showNotification,
} from "./utils.js";

/**
 * Load tokens list from API.
 * @param {boolean} resetToFirstPage - If true, forces page 1 (use after create/revoke).
 */
export async function loadTokensList(resetToFirstPage) {
  const tokensTable = document.getElementById("tokens-table");
  if (!tokensTable) {
    return;
  }

  const teamId =
    typeof getCurrentTeamId === "function" ? getCurrentTeamId() : "";
  const includeInactive =
    document.getElementById("show-inactive-tokens")?.checked ?? false;
  const params = { include_inactive: includeInactive.toString() };
  if (teamId) {
    params.team_id = teamId;
  }

  let url;
  if (resetToFirstPage) {
    const baseUrl = new URL(
      `${window.ROOT_PATH}/admin/tokens/partial`,
      window.location.origin
    );
    baseUrl.searchParams.set("page", "1");
    baseUrl.searchParams.set(
      "per_page",
      String(getPaginationParams("tokens").perPage || 10)
    );
    Object.entries(params).forEach(function (entry) {
      if (entry[1] !== null && entry[1] !== undefined && entry[1] !== "") {
        baseUrl.searchParams.set(entry[0], entry[1]);
      }
    });
    url = baseUrl.pathname + baseUrl.search;
  } else {
    url = buildTableUrl(
      "tokens",
      `${window.ROOT_PATH}/admin/tokens/partial`,
      params
    );
  }

  // Update hx-get on the element and trigger an element-based HTMX request.
  // This ensures OOB swaps (pagination controls) are properly processed,
  // unlike htmx.ajax() which can silently skip OOB handling.
  tokensTable.setAttribute("hx-get", url);
  window.htmx.process(tokensTable);
  window.htmx.trigger(tokensTable, "refreshTokens");
}

/**
 * Debounced server-side token search
 * @param {string} searchTerm - The search query
 */
let tokenSearchDebounceTimer = null;
export const debouncedServerSideTokenSearch = function (searchTerm) {
  if (tokenSearchDebounceTimer) {
    clearTimeout(tokenSearchDebounceTimer);
  }
  tokenSearchDebounceTimer = setTimeout(() => {
    performTokenSearch(searchTerm);
  }, 300);
};

/**
 * Actually perform the token search after debounce
 * @param {string} searchTerm - The search query
 */
export const performTokenSearch = async function (searchTerm) {
  const tokensTable = document.getElementById("tokens-table");
  if (!tokensTable) {
    console.error("tokens-table container not found");
    return;
  }
  // Get current parameters
  const teamId =
    typeof getCurrentTeamId === "function" ? getCurrentTeamId() : "";
  const includeInactive =
    document.getElementById("show-inactive-tokens")?.checked ?? false;
  // Build URL with search query
  const params = new URLSearchParams();
  params.set("page", "1");
  params.set("per_page", String(getPaginationParams("tokens").perPage || 10));
  params.set("include_inactive", includeInactive.toString());
  if (teamId) {
    params.set("team_id", teamId);
  }
  if (searchTerm && searchTerm.trim() !== "") {
    params.set("q", searchTerm.trim());
  }
  const url = `${window.ROOT_PATH}/admin/tokens/partial?${params.toString()}`;
  console.log(`[Token Search] Searching tokens with URL: ${url}`);

  try {
    // Update hx-get on the element and trigger an element-based HTMX request
    tokensTable.setAttribute("hx-get", url);
    window.htmx.process(tokensTable);
    window.htmx.trigger(tokensTable, "refreshTokens");
  } catch (error) {
    console.error("Error searching tokens:", error);
  }
};

/**
 * Set up event handlers for token list buttons using event delegation.
 * This avoids inline onclick handlers and associated XSS risks.
 * Attaches to the persistent tokens-panel parent so handlers survive
 * HTMX swaps of the tokens-table content.
 * @param {HTMLElement} [container] - Optional container; defaults to tokens-panel
 */
export const setupTokenListEventHandlers = function (container) {
  // Prefer the persistent parent panel so delegation survives HTMX swaps
  const panel = document.getElementById("tokens-panel") || container;
  if (!panel) {
    return;
  }

  // Guard against duplicate handlers on repeated renders
  if (panel.dataset.tokenHandlersAttached === "true") {
    return;
  }
  panel.dataset.tokenHandlersAttached = "true";

  panel.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) {
      return;
    }

    const action = button.dataset.action;

    if (action === "token-details") {
      const tokenData = button.dataset.token;
      if (tokenData) {
        try {
          let token;
          try {
            token = JSON.parse(decodeURIComponent(tokenData));
          } catch (_) {
            token = JSON.parse(tokenData);
          }
          showTokenDetailsModal(token);
        } catch (e) {
          console.error("Failed to parse token data:", e);
        }
      }
    } else if (action === "token-usage") {
      const tokenId = button.dataset.tokenId;
      if (tokenId) {
        viewTokenUsage(tokenId);
      }
    } else if (action === "token-revoke") {
      const tokenId = button.dataset.tokenId;
      const tokenName = button.dataset.tokenName;
      if (tokenId) {
        revokeToken(tokenId, tokenName || "");
      }
    }
  });
};

/**
 * Update the team scoping warning/info visibility based on team selection
 */
export const updateTeamScopingWarning = function () {
  const warningDiv = safeGetElement("team-scoping-warning");
  const infoDiv = safeGetElement("team-scoping-info");
  const teamNameSpan = safeGetElement("selected-team-name");

  if (!warningDiv || !infoDiv) {
    return;
  }

  const currentTeamId = getCurrentTeamId();

  if (!currentTeamId) {
    // Show warning when "All Teams" is selected
    warningDiv.classList.remove("hidden");
    infoDiv.classList.add("hidden");
  } else {
    // Hide warning and show info when a specific team is selected
    warningDiv.classList.add("hidden");
    infoDiv.classList.remove("hidden");

    // Get team name to display
    const teamName = getCurrentTeamName() || currentTeamId;
    if (teamNameSpan) {
      teamNameSpan.textContent = teamName;
    }
  }

  // Keep the permission picker in sync with the global team selector
  syncPermissionPickerWithTeam();
};

/**
 * Monitor team selection changes using Alpine.js watcher
 */
export const initializeTeamScopingMonitor = function () {
  // Use Alpine.js $watch to monitor team selection changes
  document.addEventListener("alpine:init", () => {
    const teamSelector = document.querySelector('[x-data*="selectedTeam"]');
    if (teamSelector && window.Alpine) {
      // The Alpine component will notify us of changes
      const checkInterval = setInterval(() => {
        updateTeamScopingWarning();
      }, 500); // Check every 500ms

      // Store interval ID for cleanup if needed
      window.Admin._teamMonitorInterval = checkInterval;
    }
  });

  // Also update when tokens tab is shown
  document.addEventListener("DOMContentLoaded", () => {
    const tokensTab = document.querySelector('a[href="#tokens"]');
    if (tokensTab) {
      tokensTab.addEventListener("click", () => {
        setTimeout(updateTeamScopingWarning, 100);
      });
    }
  });
};

/**
 * Set up create token form handling
 */
export const setupCreateTokenForm = function () {
  const form = safeGetElement("create-token-form");
  if (!form) {
    return;
  }

  // Update team scoping warning/info display
  updateTeamScopingWarning();

  // Wire permission-mode radios (lazy-loads buckets on "selected")
  setupPermissionModeToggle(form);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    // User can create all-teams tokens in that context// User can create public-only tokens in that context
    await createToken(form);
  });

  // Attach HTMX error handlers to the tokens panel so that a transient backend
  // failure (e.g. DB pool exhaustion / idle transaction timeout) shows an
  // actionable error with a retry button instead of leaving the table stale.
  const tokensPanel = document.getElementById("tokens-panel");
  if (tokensPanel && !tokensPanel.dataset.htmxErrorHandlerAttached) {
    tokensPanel.dataset.htmxErrorHandlerAttached = "true";
    tokensPanel.addEventListener("htmx:responseError", function (evt) {
      const tokensTable = document.getElementById("tokens-table");
      if (tokensTable) {
        const status =
          evt.detail && evt.detail.xhr ? evt.detail.xhr.status : "error";
        tokensTable.innerHTML =
          '<div class="bg-red-50 border border-red-300 text-red-700 px-4 py-3 rounded dark:bg-red-900 dark:border-red-600 dark:text-red-200">' +
          `<strong>${t("tokens.error.loadFailedTitle")}</strong> ${t("tokens.error.backendUnavailable")} (HTTP ` +
          status +
          "). " +
          `<button type="button" data-action="retry-tokens" class="underline font-medium">${t("tokens.actions.retry")}</button></div>`;
        const retryBtn = tokensTable.querySelector(
          '[data-action="retry-tokens"]',
        );
        if (retryBtn) {
          retryBtn.addEventListener("click", () =>
            loadTokensList(true),
          );
        }
      }
    });
    tokensPanel.addEventListener("htmx:sendError", function () {
      const tokensTable = document.getElementById("tokens-table");
      if (tokensTable) {
        tokensTable.innerHTML =
          '<div class="bg-red-50 border border-red-300 text-red-700 px-4 py-3 rounded dark:bg-red-900 dark:border-red-600 dark:text-red-200">' +
          `<strong>${t("tokens.error.loadFailedTitle")}</strong> ${t("tokens.error.networkCheck")} ` +
          `<button type="button" data-action="retry-tokens" class="underline font-medium">${t("tokens.actions.retry")}</button>.</div>`;
        const retryBtn = tokensTable.querySelector(
          '[data-action="retry-tokens"]',
        );
        if (retryBtn) {
          retryBtn.addEventListener("click", () =>
            loadTokensList(true),
          );
        }
      }
    });
  }
};

/**
 * Validate an IP address or CIDR notation string.
 * @param {string} value - The IP/CIDR string to validate
 * @returns {boolean} True if valid IPv4/IPv6 address or CIDR notation
 */
const isValidIpOrCidr = function (value) {
  if (!value || typeof value !== "string") {
    return false;
  }

  const trimmed = value.trim();

  // IPv4 with optional CIDR (e.g., 192.168.1.0/24 or 192.168.1.1)
  const ipv4Segment = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
  const ipv4Pattern = new RegExp(
    `^(?:${ipv4Segment}\\.){3}${ipv4Segment}(?:\\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$`
  );

  // IPv6 with optional CIDR (supports compressed forms and IPv4-embedded)
  const ipv6Segment = "[0-9A-Fa-f]{1,4}";
  const ipv4Embedded = `(?:${ipv4Segment}\\.){3}${ipv4Segment}`;
  const ipv6Pattern = new RegExp(
    "^(?:" +
      `(?:${ipv6Segment}:){7}${ipv6Segment}|` +
      `(?:${ipv6Segment}:){1,7}:|` +
      `(?:${ipv6Segment}:){1,6}:${ipv6Segment}|` +
      `(?:${ipv6Segment}:){1,5}(?::${ipv6Segment}){1,2}|` +
      `(?:${ipv6Segment}:){1,4}(?::${ipv6Segment}){1,3}|` +
      `(?:${ipv6Segment}:){1,3}(?::${ipv6Segment}){1,4}|` +
      `(?:${ipv6Segment}:){1,2}(?::${ipv6Segment}){1,5}|` +
      `${ipv6Segment}:(?::${ipv6Segment}){1,6}|` +
      `:(?::${ipv6Segment}){1,7}|` +
      "::|" +
      `(?:${ipv6Segment}:){1,4}:${ipv4Embedded}|` +
      `::(?:ffff(?::0{1,4}){0,1}:)?${ipv4Embedded}` +
      ")(?:\\/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$"
  );

  return ipv4Pattern.test(trimmed) || ipv6Pattern.test(trimmed);
};

/**
 * Server-side auto-grant: injected into token scope whenever tools./resources./prompts.
 * permissions are present. Displayed as a chip under "invoke" but never submitted.
 */
const AUTO_GRANTED_SERVER_PERMISSION = "servers.use";

/**
 * Permission bucket definitions in fixed display order.
 * Membership is by scope suffix; `extras` lists additional scopes shown as chips.
 */
const PERMISSION_BUCKET_DEFS = [
  { key: "read", labelKey: "tokens.form.bucketRead", suffixes: [".read"] },
  {
    key: "invoke",
    labelKey: "tokens.form.bucketInvoke",
    suffixes: [".execute", ".invoke"],
    extras: [AUTO_GRANTED_SERVER_PERMISSION],
  },
  { key: "create", labelKey: "tokens.form.bucketCreate", suffixes: [".create"] },
  { key: "update", labelKey: "tokens.form.bucketUpdate", suffixes: [".update"] },
  { key: "delete", labelKey: "tokens.form.bucketDelete", suffixes: [".delete"] },
];

/**
 * Check whether a permission string is a concrete single-dot resource.action scope.
 * Rejects "*", category wildcards like "tools.*", and colon-form entries.
 * @param {string} perm - Permission string to check
 * @returns {boolean} True for concrete "resource.action" scopes
 */
const isConcretePermission = function (perm) {
  return (
    typeof perm === "string" &&
    /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/i.test(perm)
  );
};

/**
 * Derive the permission buckets grantable by the current caller.
 * Intersects the system catalog with the caller's effective permissions
 * (caller "*" grants everything), keeps only concrete resource.action scopes,
 * and groups them into the fixed buckets. Empty buckets are omitted.
 * @param {string[]} catalogPermissions - All permissions known to the system
 * @param {string[]} callerPermissions - Caller's effective permissions
 * @returns {Array<{key: string, labelKey: string, scopes: string[]}>} Non-empty buckets in fixed order
 */
export const derivePermissionBuckets = function (
  catalogPermissions,
  callerPermissions
) {
  const catalog = Array.isArray(catalogPermissions) ? catalogPermissions : [];
  const caller = Array.isArray(callerPermissions) ? callerPermissions : [];
  const callerGrantsAll = caller.includes("*");
  const callerSet = new Set(caller);

  const grantable = catalog.filter(
    (perm) =>
      isConcretePermission(perm) && (callerGrantsAll || callerSet.has(perm))
  );
  const grantableSet = new Set(grantable);

  return PERMISSION_BUCKET_DEFS.map((def) => {
    const scopes = grantable.filter((perm) =>
      def.suffixes.some((suffix) => perm.endsWith(suffix))
    );
    (def.extras || []).forEach((extra) => {
      if (grantableSet.has(extra)) {
        scopes.push(extra);
      }
    });
    return { key: def.key, labelKey: def.labelKey, scopes };
  }).filter((bucket) => bucket.scopes.length > 0);
};

/**
 * Collect the deduplicated concrete scopes of the checked buckets.
 * The server-side auto-grant (servers.use) is never included.
 * @param {Array<{key: string, scopes: string[]}>} buckets - Buckets from derivePermissionBuckets
 * @param {string[]} checkedKeys - Bucket keys currently checked
 * @returns {string[]} Deduplicated permission scopes to submit
 */
export const collectCheckedPermissions = function (buckets, checkedKeys) {
  const wanted = new Set(checkedKeys);
  const scopes = [];
  (Array.isArray(buckets) ? buckets : []).forEach((bucket) => {
    if (!wanted.has(bucket.key)) {
      return;
    }
    bucket.scopes.forEach((scope) => {
      if (
        scope !== AUTO_GRANTED_SERVER_PERMISSION &&
        !scopes.includes(scope)
      ) {
        scopes.push(scope);
      }
    });
  });
  return scopes;
};

/**
 * Parse a comma-separated tags input into a tags array.
 * @param {string} value - Raw input value
 * @returns {string[]} Trimmed, non-empty tags
 */
export const parseTagsInput = function (value) {
  if (!value) {
    return [];
  }
  return String(value)
    .split(",")
    .map((tag) => tag.trim())
    .filter((tag) => tag.length > 0);
};

/**
 * Build the time_restrictions object from form data.
 * Returns null when no restriction is checked so the key can be omitted.
 * @param {FormData} formData - The create-token form data
 * @returns {Object|null} time_restrictions payload or null
 */
export const buildTimeRestrictions = function (formData) {
  const restrictions = {};
  if (formData.get("business_hours_only")) {
    restrictions.business_hours_only = true;
  }
  if (formData.get("weekdays_only")) {
    restrictions.weekdays_only = true;
  }
  return Object.keys(restrictions).length > 0 ? restrictions : null;
};

/**
 * Mutable state for the permission picker (lazy-loaded per team context).
 */
const permissionPickerState = {
  loadedForTeam: undefined,
  buckets: [],
  loading: false,
};

/**
 * Read the selected permission mode from the form ("all" or "selected").
 * @param {HTMLFormElement} form - The create-token form
 * @returns {string} The active permission mode
 */
const getPermissionMode = function (form) {
  const checked = form.querySelector('input[name="permission_mode"]:checked');
  return checked ? checked.value : "all";
};

/**
 * Fetch the permission catalog and the caller's effective permissions for the
 * current team context, then derive the grantable buckets.
 * @returns {Promise<Array<{key: string, labelKey: string, scopes: string[]}>>} Grantable buckets
 */
const fetchGrantablePermissionBuckets = async function () {
  const teamId =
    typeof getCurrentTeamId === "function" ? getCurrentTeamId() : "";
  const myPermissionsUrl = teamId
    ? `${window.ROOT_PATH}/rbac/my/permissions?team_id=${encodeURIComponent(teamId)}`
    : `${window.ROOT_PATH}/rbac/my/permissions`;
  const headers = { Authorization: `Bearer ${await getAuthToken()}` };

  const [availableResponse, mineResponse] = await Promise.all([
    fetchWithTimeout(`${window.ROOT_PATH}/rbac/permissions/available`, {
      headers,
    }),
    fetchWithTimeout(myPermissionsUrl, { headers }),
  ]);

  if (!availableResponse.ok || !mineResponse.ok) {
    throw new Error(
      `Failed to load permissions (${availableResponse.status}/${mineResponse.status})`
    );
  }

  const available = await availableResponse.json();
  const mine = await mineResponse.json();
  return derivePermissionBuckets(available.all_permissions, mine);
};

/**
 * Render the bucket checkbox rows with their concrete scope chips.
 * Previously checked buckets that still exist stay checked.
 * @param {Array<{key: string, labelKey: string, scopes: string[]}>} buckets - Buckets to render
 */
const renderPermissionBuckets = function (buckets) {
  const container = document.getElementById("token-permission-buckets");
  if (!container) {
    return;
  }

  const previouslyChecked = new Set(
    Array.from(
      container.querySelectorAll('input[name="permission_bucket"]:checked')
    ).map((el) => el.value)
  );

  container.innerHTML = buckets
    .map((bucket) => {
      const checkedAttr = previouslyChecked.has(bucket.key) ? " checked" : "";
      const chips = bucket.scopes
        .map(
          (scope) =>
            `<span class="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 text-xs rounded font-mono">${escapeHtml(scope)}</span>`
        )
        .join("");
      return (
        "<div>" +
        '<label class="flex items-center text-sm font-medium text-gray-700 dark:text-gray-300">' +
        `<input type="checkbox" name="permission_bucket" value="${escapeHtml(bucket.key)}" class="mr-2"${checkedAttr} />` +
        escapeHtml(t(bucket.labelKey)) +
        `<span class="ml-2 text-xs text-gray-500 dark:text-gray-400">(${bucket.scopes.length})</span>` +
        "</label>" +
        `<div class="mt-1 ml-6 flex flex-wrap gap-1">${chips}</div>` +
        "</div>"
      );
    })
    .join("");
};

/**
 * Load (or reload) the permission buckets for the current team context and
 * render the picker status and bucket rows.
 */
const refreshPermissionPicker = async function () {
  const status = document.getElementById("token-permission-picker-status");
  const container = document.getElementById("token-permission-buckets");
  if (!status || !container) {
    return;
  }

  const teamId =
    (typeof getCurrentTeamId === "function" ? getCurrentTeamId() : "") || "";
  permissionPickerState.loading = true;
  status.classList.remove("hidden");
  status.textContent = t("tokens.form.permissionsLoading");
  container.innerHTML = "";

  try {
    const buckets = await fetchGrantablePermissionBuckets();
    permissionPickerState.buckets = buckets;
    permissionPickerState.loadedForTeam = teamId;
    if (buckets.length === 0) {
      status.textContent = t("tokens.form.permissionsEmpty");
    } else {
      status.classList.add("hidden");
      renderPermissionBuckets(buckets);
    }
  } catch (error) {
    console.error("Error loading permissions:", error);
    permissionPickerState.buckets = [];
    permissionPickerState.loadedForTeam = undefined;
    status.textContent = t("tokens.form.permissionsLoadFailed");
  } finally {
    permissionPickerState.loading = false;
  }
};

/**
 * Re-fetch the permission buckets when the picker is visible and the global
 * team context changed since the last load. Called from the same team-monitor
 * cadence that drives updateTeamScopingWarning.
 */
const syncPermissionPickerWithTeam = function () {
  const picker = document.getElementById("token-permission-picker");
  if (!picker || picker.classList.contains("hidden")) {
    return;
  }
  const teamId =
    (typeof getCurrentTeamId === "function" ? getCurrentTeamId() : "") || "";
  if (
    permissionPickerState.loadedForTeam !== teamId &&
    !permissionPickerState.loading
  ) {
    refreshPermissionPicker();
  }
};

/**
 * Wire the permission-mode radios: show the picker and lazy-load buckets when
 * "selected" mode is activated, hide it otherwise.
 * @param {HTMLFormElement} form - The create-token form
 */
const setupPermissionModeToggle = function (form) {
  form
    .querySelectorAll('input[name="permission_mode"]')
    .forEach((radio) => {
      radio.addEventListener("change", () => {
        const picker = document.getElementById("token-permission-picker");
        if (!picker) {
          return;
        }
        if (getPermissionMode(form) === "selected") {
          picker.classList.remove("hidden");
          syncPermissionPickerWithTeam();
        } else {
          picker.classList.add("hidden");
        }
      });
    });
};

/**
 * Create a new API token
 */
// Create a new API token
const createToken = async function (form) {
  const formData = new FormData(form);
  const submitButton = form.querySelector('button[type="submit"]');
  const originalText = submitButton.textContent;

  try {
    submitButton.textContent = t("tokens.actions.creating");
    submitButton.disabled = true;

    // Get current team ID (null means "All Teams" — admin bypass for admins, public-only for non-admins)
    const currentTeamId = getCurrentTeamId();

    // Build request payload
    const payload = {
      name: formData.get("name"),
      description: formData.get("description") || null,
      expires_in_days: formData.get("expires_in_days")
        ? parseInt(formData.get("expires_in_days"), 10)
        : null,
      tags: parseTagsInput(formData.get("tags")),
      team_id: currentTeamId || null, // null = all teams (admin bypass for admins, public-only for non-admins)
    };

    // Add scoping if provided
    const scope = {};

    if (formData.get("server_id")) {
      scope.server_id = formData.get("server_id");
    }

    // Parse and validate IP restrictions
    if (formData.get("ip_restrictions")) {
      const ipRestrictions = formData.get("ip_restrictions").trim();
      if (ipRestrictions) {
        const ipList = ipRestrictions
          .split(",")
          .map((ip) => ip.trim())
          .filter((ip) => ip.length > 0);

        // Validate each IP/CIDR
        const invalidIps = ipList.filter((ip) => !isValidIpOrCidr(ip));
        if (invalidIps.length > 0) {
          throw new Error(
            t("tokens.error.invalidIp", { entries: invalidIps.join(", ") })
          );
        }
        scope.ip_restrictions = ipList;
      } else {
        scope.ip_restrictions = [];
      }
    } else {
      scope.ip_restrictions = [];
    }

    // Permission scope: "all" mode inherits the caller's RBAC at runtime
    // (no permissions key); "selected" mode submits the checked buckets.
    if (getPermissionMode(form) === "selected") {
      const checkedKeys = Array.from(
        form.querySelectorAll('input[name="permission_bucket"]:checked')
      ).map((el) => el.value);
      const selectedPermissions = collectCheckedPermissions(
        permissionPickerState.buckets,
        checkedKeys
      );
      if (selectedPermissions.length === 0) {
        throw new Error(t("tokens.error.noPermissionsSelected"));
      }
      scope.permissions = selectedPermissions;
    }

    const timeRestrictions = buildTimeRestrictions(formData);
    if (timeRestrictions) {
      scope.time_restrictions = timeRestrictions;
    }

    payload.scope = scope;

    const response = await fetchWithTimeout(`${window.ROOT_PATH}/tokens`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await getAuthToken()}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      let errorMsg = await parseErrorResponse(
        response,
        `Failed to create token (${response.status})`
      );

      // Common conflict path: duplicate token name (same user + same team scope).
      const genericCreateTokenError =
        "Unable to complete the operation. Please try again.";
      if (response.status === 409 && errorMsg === genericCreateTokenError) {
        const scopeLabel = currentTeamId
          ? t("tokens.scope.selectedTeam")
          : t("common.allTeams");
        errorMsg = t("tokens.error.nameExists", { scope: scopeLabel });
      }
      if (
        response.status === 400 &&
        typeof errorMsg === "string" &&
        errorMsg.startsWith("Team not found:")
      ) {
        errorMsg =
        errorMsg = t("tokens.error.teamUnavailable");
      }
      throw new Error(errorMsg);
    }

    const result = await response.json();
    showTokenCreatedModal(result);
    form.reset();

    // Collapse the permission picker back to its default hidden state
    const picker = document.getElementById("token-permission-picker");
    if (picker) {
      picker.classList.add("hidden");
    }

    // Clear any lingering inline error
    const inlineMessagesSuccess = document.getElementById(
      "token-creation-messages",
    );
    if (inlineMessagesSuccess) {
      inlineMessagesSuccess.innerHTML = "";
    }

    // Show appropriate success message
    const tokenType = currentTeamId ? "team-scoped" : "all-teams";
    showNotification(`${tokenType} token created successfully!`, "success");
  } catch (error) {
    console.error("Error creating token:", error);
    showNotification(`Error creating token: ${error.message}`, "error");
    // Also show inline near the form — the toast may be missed if the user scrolled
    const inlineMessages = document.getElementById(
      "token-creation-messages",
    );
    if (inlineMessages) {
      inlineMessages.innerHTML =
        '<div class="bg-red-50 border border-red-300 text-red-700 px-4 py-3 rounded dark:bg-red-900 dark:border-red-600 dark:text-red-200">' +
        `<strong>${t("tokens.error.createFailed")}</strong> ` +
        escapeHtml(error.message) +
        "</div>";
      setTimeout(function () {
        inlineMessages.innerHTML = "";
      }, 15000);
    }
  } finally {
    submitButton.textContent = originalText;
    submitButton.disabled = false;
  }
};

/**
 * Show modal with new token (one-time display)
 */
const showTokenCreatedModal = function (tokenData) {
  const modal = document.createElement("div");
  modal.className =
    "fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-40";
  modal.innerHTML = `
            <div class="relative top-20 mx-auto p-5 border w-11/12 max-w-lg shadow-lg rounded-md bg-white dark:bg-gray-800">
                <div class="mt-3">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-medium text-gray-900 dark:text-white">${t("tokens.created.title")}</h3>
                        <button data-dismiss-token-modal class="text-gray-400 hover:text-gray-600">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>

                    <div class="bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-md p-4 mb-4">
                        <div class="flex">
                            <div class="flex-shrink-0">
                                <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                                </svg>
                            </div>
                            <div class="ml-3">
                                <h3 class="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                                    ${t("tokens.created.important")}
                                </h3>
                                <div class="mt-2 text-sm text-yellow-700 dark:text-yellow-300">
                                    ${t("tokens.created.saveWarning")}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            ${t("tokens.created.yourToken")}
                        </label>
                        <div class="flex">
                            <input
                                type="text"
                                value="${tokenData.access_token}"
                                readonly
                                class="flex-1 p-2 border border-gray-300 dark:border-gray-600 rounded-l-md bg-gray-50 dark:bg-gray-700 text-sm font-mono"
                                id="new-token-value"
                            />
                            <button
                                data-copy-token-target="new-token-value"
                                class="px-3 py-2 bg-indigo-600 text-white text-sm rounded-r-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                            >
                                ${t("common.actions.copy")}
                            </button>
                        </div>
                    </div>

                    <div class="text-sm text-gray-600 dark:text-gray-400 mb-4">
                        <strong>${t("tokens.created.name")}</strong> ${escapeHtml(tokenData.token.name || t("tokens.unnamed"))}<br/>
                        <strong>${t("tokens.detail.expires")}</strong> ${tokenData.token.expires_at ? new Date(tokenData.token.expires_at).toLocaleDateString() : t("common.never")}
                    </div>

                    <div class="flex justify-end">
                        <button
                            data-dismiss-token-modal
                            class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        >
                            ${t("tokens.created.saved")}
                        </button>
                    </div>
                </div>
            </div>
        `;

  document.body.appendChild(modal);

  // Close handlers: remove modal then refresh the token list
  modal.querySelectorAll("[data-dismiss-token-modal]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      modal.remove();
      loadTokensList(true);
    });
  });

  // Bind copy action without relying on inline handlers
  const copyTokenButton = modal.querySelector("[data-copy-token-target]");
  if (copyTokenButton) {
    copyTokenButton.addEventListener("click", function (event) {
      event.preventDefault();
      const elementId = event.currentTarget.getAttribute(
        "data-copy-token-target"
      );
      if (elementId) {
        copyToClipboard(elementId).catch((error) => {
          console.warn("Copy token action failed", error);
        });
      }
    });
  }

  // Focus the token input for easy selection
  const tokenInput = modal.querySelector("#new-token-value");
  tokenInput.focus();
  tokenInput.select();
};

/**
 * Revoke a token
 */
const revokeToken = async function (tokenId, tokenName) {
  if (
    !confirm(
      t("tokens.confirmRevoke", { name: tokenName })
    )
  ) {
    return;
  }

  try {
    const requestHeaders = await getAuthHeaders(true);
    const response = await fetchWithTimeout(
      `${window.ROOT_PATH}/admin/tokens/${tokenId}`,
      {
        method: "DELETE",
        headers: requestHeaders,
        body: JSON.stringify({
          reason: t("tokens.revoke.reason"),
        }),
      }
    );

    if (!response.ok) {
      const errorMsg = await parseErrorResponse(
        response,
        `Failed to revoke token: ${response.status}`
      );
      throw new Error(errorMsg);
    }

    showNotification(t("tokens.revoke.success"), "success");
    loadTokensList(true);
  } catch (error) {
    console.error("Error revoking token:", error);
    showNotification(`Error revoking token: ${error.message}`, "error");
  }
};

/**
 * View token usage statistics
 */
const viewTokenUsage = async function (tokenId) {
  try {
    const requestHeaders = await getAuthHeaders(true);
    const response = await fetchWithTimeout(
      `${window.ROOT_PATH}/tokens/${tokenId}/usage`,
      {
        headers: requestHeaders,
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to load usage stats: ${response.status}`);
    }

    const stats = await response.json();
    showUsageStatsModal(stats);
  } catch (error) {
    console.error("Error loading usage stats:", error);
    showNotification(`Error loading usage stats: ${error.message}`, "error");
  }
};

/**
 * Show usage statistics modal
 */
export const showUsageStatsModal = function (stats) {
  const modal = document.createElement("div");
  modal.className =
    "fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-40";
  modal.innerHTML = `
            <div class="relative top-20 mx-auto p-5 border w-11/12 max-w-2xl shadow-lg rounded-md bg-white dark:bg-gray-800">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white">${t("tokens.usage.title", { days: stats.period_days })}</h3>
                    <button data-action="close-stats-modal" class="text-gray-400 hover:text-gray-600">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                    <div class="bg-blue-50 dark:bg-blue-900 p-4 rounded-lg">
                        <div class="text-2xl font-bold text-blue-600 dark:text-blue-300">${stats.total_requests}</div>
                        <div class="text-sm text-blue-600 dark:text-blue-400">${t("tokens.usage.totalRequests")}</div>
                    </div>
                    <div class="bg-green-50 dark:bg-green-900 p-4 rounded-lg">
                        <div class="text-2xl font-bold text-green-600 dark:text-green-300">${stats.successful_requests}</div>
                        <div class="text-sm text-green-600 dark:text-green-400">${t("tokens.usage.successful")}</div>
                    </div>
                    <div class="bg-red-50 dark:bg-red-900 p-4 rounded-lg">
                        <div class="text-2xl font-bold text-red-600 dark:text-red-300">${stats.blocked_requests}</div>
                        <div class="text-sm text-red-600 dark:text-red-400">${t("tokens.usage.blocked")}</div>
                    </div>
                    <div class="bg-purple-50 dark:bg-purple-900 p-4 rounded-lg">
                        <div class="text-2xl font-bold text-purple-600 dark:text-purple-300">${Math.round(stats.success_rate * 100)}%</div>
                        <div class="text-sm text-purple-600 dark:text-purple-400">${t("tokens.usage.successRate")}</div>
                    </div>
                </div>

                <div class="mb-4">
                    <h4 class="text-md font-medium text-gray-900 dark:text-white mb-2">${t("metrics.executions.avgResponseTime")}</h4>
                    <div class="text-lg text-gray-700 dark:text-gray-300">${stats.average_response_time_ms}ms</div>
                </div>

                ${
  stats.top_endpoints && stats.top_endpoints.length > 0
    ? `
                    <div class="mb-4">
                        <h4 class="text-md font-medium text-gray-900 dark:text-white mb-2">${t("tokens.usage.topEndpoints")}</h4>
                        <div class="space-y-2">
                            ${stats.top_endpoints
    .map(
      ([endpoint, count]) => `
                                <div class="flex justify-between items-center p-2 bg-gray-50 dark:bg-gray-700 rounded">
                                    <span class="font-mono text-sm">${escapeHtml(endpoint)}</span>
                                    <span class="text-sm font-medium">${t("tokens.usage.requests", { count })}</span>
                                </div>
                            `
    )
    .join("")}
                        </div>
                    </div>
                `
    : ""
}

                <div class="flex justify-end">
                    <button
                        data-action="close-stats-modal"
                        class="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    >
                        ${t("common.actions.close")}
                    </button>
                </div>
            </div>
        `;

  // Attach close listeners (inline onclick is stripped by innerHTML sanitizer)
  modal
    .querySelectorAll('[data-action="close-stats-modal"]')
    .forEach((btn) => {
      btn.addEventListener("click", () => modal.remove());
    });

  document.body.appendChild(modal);
};

/**
 * Get team name by team ID from cached team data
 * @param {string} teamId - The team ID to look up
 * @returns {string} Team name or truncated ID if not found
 */
export const getTeamNameById = function (teamId) {
  if (!teamId) {
    return null;
  }

  // Try from window.USERTEAMSDATA (most reliable source)
  if (window.USERTEAMSDATA && Array.isArray(window.USERTEAMSDATA)) {
    const teamObj = window.USERTEAMSDATA.find((t) => t.id === teamId);
    if (teamObj) {
      return teamObj.name;
    }
  }

  // Try from Alpine.js component
  const teamSelector = document.querySelector('[x-data*="selectedTeam"]');
  if (
    teamSelector &&
    teamSelector._x_dataStack &&
    teamSelector._x_dataStack[0]
  ) {
    const alpineData = teamSelector._x_dataStack[0];
    if (alpineData.teams && Array.isArray(alpineData.teams)) {
      const teamObj = alpineData.teams.find((t) => t.id === teamId);
      if (teamObj) {
        return teamObj.name;
      }
    }
  }

  // Fallback: return truncated ID
  return teamId.substring(0, 8) + "...";
};

/**
 * Show token details modal with full token information
 * @param {Object} token - The token object with all fields
 */
export const showTokenDetailsModal = function (token) {
  const formatDate = (dateStr) => {
    if (!dateStr) {
      return t("common.never");
    }
    return new Date(dateStr).toLocaleString();
  };

  const formatList = (list) => {
    if (!list || list.length === 0) {
      return t("common.none");
    }
    return list
      .map((item) => `<li class="ml-4">• ${escapeHtml(item)}</li>`)
      .join("");
  };

  const formatJson = (obj) => {
    if (!obj || Object.keys(obj).length === 0) {
      return t("common.none");
    }
    return `<pre class="bg-gray-100 dark:bg-gray-700 p-2 rounded text-xs overflow-x-auto">${escapeHtml(JSON.stringify(obj, null, 2))}</pre>`;
  };

  const teamName = token.team_id ? getTeamNameById(token.team_id) : null;
  const statusClass = token.is_active
    ? "bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100"
    : "bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100";
  const statusText = token.is_active ? t("common.active") : t("common.inactive");

  const modal = document.createElement("div");
  modal.className =
    "fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-40";
  modal.innerHTML = `
            <div class="relative top-10 mx-auto p-5 border w-11/12 max-w-2xl shadow-lg rounded-md bg-white dark:bg-gray-800 mb-10">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white">${t("tokens.detail.title")}</h3>
                    <button data-action="close-modal" class="text-gray-400 hover:text-gray-600">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>

                <!-- Basic Information -->
                <div class="mb-6">
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3 border-b border-gray-200 dark:border-gray-600 pb-2">${t("tokens.detail.basicInfo")}</h4>
                    <div class="grid grid-cols-1 gap-2 text-sm">
                        <div class="flex items-center">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.id")}</span>
                            <code class="bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded text-xs flex-1 overflow-hidden text-ellipsis">${escapeHtml(token.id)}</code>
                            <button data-action="copy-id" data-copy-value="${escapeHtml(token.id)}"
                                    class="ml-2 px-2 py-0.5 text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 border border-blue-300 dark:border-blue-600 rounded">
                                ${t("common.actions.copy")}
                            </button>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.name")}</span>
                            <span class="text-gray-900 dark:text-white">${escapeHtml(token.name)}</span>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.description")}</span>
                            <span class="text-gray-600 dark:text-gray-400">${token.description ? escapeHtml(token.description) : t("common.none")}</span>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.createdBy")}</span>
                            <span class="text-gray-900 dark:text-white">${escapeHtml(token.user_email || t("common.unknown"))}</span>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.team")}</span>
                            <span class="text-gray-900 dark:text-white">${teamName ? `${escapeHtml(teamName)} <code class="text-xs text-gray-500">(${escapeHtml(token.team_id.substring(0, 8))}...)</code>` : t("common.allTeams")}</span>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.created")}</span>
                            <span class="text-gray-600 dark:text-gray-400">${formatDate(token.created_at)}</span>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.expires")}</span>
                            <span class="text-gray-600 dark:text-gray-400">${formatDate(token.expires_at)}</span>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.lastUsed")}</span>
                            <span class="text-gray-600 dark:text-gray-400">${formatDate(token.last_used)}</span>
                        </div>
                        <div class="flex items-center">
                            <span class="font-medium text-gray-700 dark:text-gray-300 w-28">${t("tokens.detail.status")}</span>
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusClass}">${statusText}</span>
                        </div>
                    </div>
                </div>

                <!-- Scope & Restrictions -->
                <div class="mb-6">
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3 border-b border-gray-200 dark:border-gray-600 pb-2">${t("tokens.detail.scopeRestrictions")}</h4>
                    <div class="grid grid-cols-1 gap-3 text-sm">
                        <div>
                            <span class="font-medium text-gray-700 dark:text-gray-300">${t("tokens.detail.server")}</span>
                            <span class="ml-2 text-gray-600 dark:text-gray-400">${token.server_id ? escapeHtml(token.server_id) : t("tokens.detail.allServers")}</span>
                        </div>
                        <div>
                            <span class="font-medium text-gray-700 dark:text-gray-300">${t("tokens.detail.permissions")}</span>
                            ${
  token.resource_scopes &&
                              token.resource_scopes.length > 0
    ? `<ul class="mt-1 text-gray-600 dark:text-gray-400">${formatList(token.resource_scopes)}</ul>`
    : `<span class="ml-2 text-gray-600 dark:text-gray-400">${t("tokens.detail.allNoRestrictions")}</span>`
}
                        </div>
                        <div>
                            <span class="font-medium text-gray-700 dark:text-gray-300">${t("tokens.detail.ipRestrictions")}</span>
                            ${
  token.ip_restrictions &&
                              token.ip_restrictions.length > 0
    ? `<ul class="mt-1 text-gray-600 dark:text-gray-400">${formatList(token.ip_restrictions)}</ul>`
    : `<span class="ml-2 text-gray-600 dark:text-gray-400">${t("common.none")}</span>`
}
                        </div>
                        <div>
                            <span class="font-medium text-gray-700 dark:text-gray-300">${t("tokens.detail.timeRestrictions")}</span>
                            <div class="mt-1">${formatJson(token.time_restrictions)}</div>
                        </div>
                        <div>
                            <span class="font-medium text-gray-700 dark:text-gray-300">${t("tokens.detail.usageLimits")}</span>
                            <div class="mt-1">${formatJson(token.usage_limits)}</div>
                        </div>
                    </div>
                </div>

                <!-- Tags -->
                ${
  token.tags && token.tags.length > 0
    ? `
                <div class="mb-6">
                    <h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3 border-b border-gray-200 dark:border-gray-600 pb-2">${t("tokens.detail.tags")}</h4>
                    <div class="flex flex-wrap gap-2">
                        ${token.tags
    .map((tag) => {
      const raw =
                              typeof tag === "object" && tag !== null
                                ? tag.id || tag.label || JSON.stringify(tag)
                                : tag;
      return `<span class="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs rounded">${escapeHtml(raw)}</span>`;
    })
    .join("")}
                    </div>
                </div>
                `
    : ""
}

                <!-- Revocation Details (if revoked) -->
                ${
  token.is_revoked
    ? `
                <div class="mb-6">
                    <h4 class="text-md font-semibold text-red-600 dark:text-red-400 mb-3 border-b border-red-200 dark:border-red-600 pb-2">${t("tokens.detail.revocationDetails")}</h4>
                    <div class="grid grid-cols-1 gap-2 text-sm bg-red-50 dark:bg-red-900/20 p-3 rounded">
                        <div class="flex">
                            <span class="font-medium text-red-700 dark:text-red-300 w-28">${t("tokens.detail.revokedAt")}</span>
                            <span class="text-red-600 dark:text-red-400">${formatDate(token.revoked_at)}</span>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-red-700 dark:text-red-300 w-28">${t("tokens.detail.revokedBy")}</span>
                            <span class="text-red-600 dark:text-red-400">${token.revoked_by ? escapeHtml(token.revoked_by) : t("common.unknown")}</span>
                        </div>
                        <div class="flex">
                            <span class="font-medium text-red-700 dark:text-red-300 w-28">${t("tokens.detail.reason")}</span>
                            <span class="text-red-600 dark:text-red-400">${token.revocation_reason ? escapeHtml(token.revocation_reason) : t("tokens.detail.noReason")}</span>
                        </div>
                    </div>
                </div>
                `
    : ""
}

                <div class="flex justify-end">
                    <button
                        data-action="close-modal"
                        class="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    >
                        ${t("common.actions.close")}
                    </button>
                </div>
            </div>
        `;

  document.body.appendChild(modal);
  // Attach event handlers (avoids inline JS and XSS risks)
  modal.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) {
      return;
    }

    const action = button.dataset.action;

    if (action === "close-modal") {
      modal.remove();
    } else if (action === "copy-id") {
      const value = button.dataset.copyValue;
      if (value) {
        navigator.clipboard.writeText(value).then(() => {
          button.textContent = t("common.actions.copied");
          setTimeout(() => {
            button.textContent = t("common.actions.copy");
          }, 1500);
        });
      }
    }
  });
};

/**
 * Get auth token from storage or user input
 */
export const getAuthToken = async function () {
  // Use the same authentication method as the rest of the admin interface
  let token = getCookie("jwt_token");

  // Try alternative cookie names if primary not found
  if (!token) {
    token = getCookie("token");
  }

  // Fallback to localStorage for compatibility
  if (!token) {
    try {
      token = localStorage.getItem("auth_token");
    } catch (e) {
      logRestrictedContext(e);
    }
  }
  return token || "";
};

/**
 * Fetch helper that always includes auth context.
 * Ensures HTTP-only cookies are sent even when JS cannot read them.
 */
export const fetchWithAuth = async function (url, options = {}) {
  const opts = { ...options };
  // Always send same-origin cookies unless caller overrides explicitly
  opts.credentials = options.credentials || "same-origin";

  // Clone headers to avoid mutating caller-provided object
  const headers = new Headers(options.headers || {});
  const token = await getAuthToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  opts.headers = headers;

  return fetch(url, opts);
};
