/**
 * ====================================================================
 * SERVER WIZARD - Two-step create-virtual-server wizard (catalog tab)
 * ====================================================================
 *
 * Step 1 collects server details. Step 2 offers a gateway source table
 * (fetched from GET /gateways) plus the existing granular component
 * selectors. Submit aggregates every component of each selected gateway
 * via cursor-paginated API calls, unions them with the granular
 * selections, and POSTs an embedded body to /servers.
 *
 * The pure helpers (validation, pagination, payload assembly) are
 * exported for Vitest; the DOM glue is registered on window.Admin in
 * admin.js and driven from the template via data-action-click.
 */

import { AppState } from "./appState.js";
import { getAuthHeaders } from "./auth.js";
import { escapeHtml, validateInputName } from "./security.js";
import { getEditSelections } from "./servers.js";
import {
  getCurrentTeamId,
  safeGetElement,
  showSuccessMessage,
} from "./utils.js";
import { t } from "./i18n.js";

export const WIZARD_NAME_MAX_LENGTH = 100;
export const WIZARD_DESCRIPTION_MAX_LENGTH = 500;
export const WIZARD_COMPONENTS = ["tools", "resources", "prompts"];

const WIZARD_PAGE_LIMIT = 100;
const GRANULAR_CONTAINER_IDS = {
  tools: "associatedTools",
  resources: "associatedResources",
  prompts: "associatedPrompts",
};

// ===================================================================
// Pure helpers
// ===================================================================

/**
 * Parse a comma-separated tag input into a trimmed tag list.
 *
 * @param {string} raw - Raw tag input value.
 * @returns {string[]} Trimmed, non-empty tags.
 */
export function parseTagsInput(raw) {
  if (!raw || typeof raw !== "string") {
    return [];
  }
  return raw
    .split(",")
    .map((tag) => tag.trim())
    .filter((tag) => tag.length > 0);
}

/**
 * Validate the step 1 details. Blocks advancing without a valid name.
 *
 * @param {Object} details - Wizard details from the step 1 fields.
 * @returns {{valid: boolean, error: string|null}} Validation result.
 */
export function validateServerWizardDetails(details) {
  const name = (details.name || "").trim();
  if (!name) {
    return { valid: false, error: t("servers.form.nameRequired") };
  }
  if (name.length > WIZARD_NAME_MAX_LENGTH) {
    return {
      valid: false,
      error: t("servers.wizard.nameTooLong", { max: WIZARD_NAME_MAX_LENGTH }),
    };
  }
  const nameValidation = validateInputName(name, "server");
  if (!nameValidation.valid) {
    return { valid: false, error: nameValidation.error };
  }
  const description = details.description || "";
  if (description.length > WIZARD_DESCRIPTION_MAX_LENGTH) {
    return {
      valid: false,
      error: t("servers.wizard.descriptionTooLong", {
        max: WIZARD_DESCRIPTION_MAX_LENGTH,
      }),
    };
  }
  return { valid: true, error: null };
}

/**
 * Read the next-page cursor from a paginated API response body.
 * Accepts both the camelCase alias and the snake_case field name.
 *
 * @param {Object} body - Parsed response body.
 * @returns {string|null} Cursor for the next page, or null when exhausted.
 */
export function extractNextCursor(body) {
  if (!body || typeof body !== "object") {
    return null;
  }
  return body.nextCursor ?? body.next_cursor ?? null;
}

/**
 * Read the item list from a list endpoint response body.
 * Handles both the bare-array shape and the paginated envelope.
 *
 * @param {Object|Array} body - Parsed response body.
 * @param {string} key - Envelope item key ("tools", "resources", "prompts").
 * @returns {Array} Items on this page.
 */
export function extractPageItems(body, key) {
  if (Array.isArray(body)) {
    return body;
  }
  if (body && Array.isArray(body[key])) {
    return body[key];
  }
  return [];
}

/**
 * Fetch every component ID for one gateway, following the cursor
 * until the paginated endpoint is exhausted.
 *
 * @param {string} gatewayId - Gateway to aggregate components for.
 * @param {string} component - One of "tools", "resources", "prompts".
 * @param {Object} [options] - fetchImpl/rootPath/headers overrides (tests).
 * @returns {Promise<string[]>} All component IDs for the gateway.
 */
export async function fetchAllComponentIdsForGateway(
  gatewayId,
  component,
  options = {},
) {
  const fetchImpl = options.fetchImpl || fetch;
  const rootPath = options.rootPath ?? window.ROOT_PATH ?? "";
  const headers = options.headers || {};
  const ids = [];
  let cursor = null;

  do {
    const params = new URLSearchParams({
      gateway_id: gatewayId,
      limit: String(WIZARD_PAGE_LIMIT),
      include_inactive: "true",
      include_pagination: "true",
    });
    if (cursor) {
      params.set("cursor", cursor);
    }
    const response = await fetchImpl(
      `${rootPath}/${component}?${params.toString()}`,
      { credentials: "include", headers },
    );
    if (!response.ok) {
      throw new Error(
        t("servers.wizard.aggregateFailed", { component, gatewayId }),
      );
    }
    const body = await response.json();
    extractPageItems(body, component).forEach((item) => {
      if (item && item.id !== undefined && item.id !== null) {
        ids.push(String(item.id));
      }
    });
    cursor = extractNextCursor(body);
  } while (cursor);

  return ids;
}

/**
 * Aggregate all tool/resource/prompt IDs for each selected gateway.
 *
 * @param {string[]} gatewayIds - Selected gateway IDs.
 * @param {Object} [options] - Forwarded to fetchAllComponentIdsForGateway.
 * @returns {Promise<{tools: string[], resources: string[], prompts: string[]}>}
 */
export async function aggregateGatewayComponentIds(gatewayIds, options = {}) {
  const result = { tools: [], resources: [], prompts: [] };
  for (const gatewayId of gatewayIds) {
    for (const component of WIZARD_COMPONENTS) {
      const ids = await fetchAllComponentIdsForGateway(
        gatewayId,
        component,
        options,
      );
      result[component].push(...ids);
    }
  }
  return result;
}

/**
 * Union ID lists into a deduplicated string array.
 *
 * @param {...Array} lists - ID lists to union.
 * @returns {string[]} Deduplicated IDs.
 */
export function unionIds(...lists) {
  return Array.from(
    new Set(
      lists
        .flat()
        .filter((id) => id !== null && id !== undefined && id !== "")
        .map(String),
    ),
  );
}

/**
 * Assemble the POST /servers body. The route takes an embedded body:
 * the ServerCreate payload under "server", plus top-level visibility
 * and team_id.
 *
 * @param {Object} args - Assembly inputs.
 * @param {Object} args.details - Step 1 details.
 * @param {Object} [args.gatewayComponents] - Aggregated gateway component IDs.
 * @param {Object} [args.granular] - Granular selector selections.
 * @param {string|null} [args.teamId] - Current team ID (null for All Teams).
 * @param {boolean} [args.skip] - Skip flow: empty associations.
 * @returns {Object} Request body for POST /servers.
 */
export function buildServerWizardPayload({
  details,
  gatewayComponents = {},
  granular = {},
  teamId = null,
  skip = false,
}) {
  const visibility = details.visibility || "public";
  const tags = Array.isArray(details.tags)
    ? details.tags
    : parseTagsInput(details.tags);

  const server = {
    name: (details.name || "").trim(),
    description: (details.description || "").trim() || null,
    tags,
    associated_tools: skip
      ? []
      : unionIds(gatewayComponents.tools || [], granular.tools || []),
    associated_resources: skip
      ? []
      : unionIds(gatewayComponents.resources || [], granular.resources || []),
    associated_prompts: skip
      ? []
      : unionIds(gatewayComponents.prompts || [], granular.prompts || []),
    associated_a2a_agents: [],
    visibility,
    oauth_enabled: Boolean(details.oauthEnabled),
    team_id: teamId,
  };

  if (details.id && details.id.trim()) {
    server.id = details.id.trim();
  }
  if (details.icon && details.icon.trim()) {
    server.icon = details.icon.trim();
  }

  if (server.oauth_enabled) {
    const authorizationServer = (details.oauthAuthorizationServer || "").trim();
    if (authorizationServer) {
      const oauthConfig = { authorization_servers: [authorizationServer] };
      const scopes = (details.oauthScopes || "").split(/\s+/).filter(Boolean);
      if (scopes.length > 0) {
        oauthConfig.scopes_supported = scopes;
      }
      const tokenEndpoint = (details.oauthTokenEndpoint || "").trim();
      if (tokenEndpoint) {
        oauthConfig.token_endpoint = tokenEndpoint;
      }
      server.oauth_config = oauthConfig;
    } else {
      // Mirror the admin form handler: OAuth without an authorization
      // server is disabled to avoid an inconsistent state.
      server.oauth_enabled = false;
    }
  }

  return { server, visibility, team_id: teamId };
}

/**
 * Extract a human-readable error message from an API error body.
 *
 * @param {Object} body - Parsed error response body.
 * @returns {string} Error detail, or empty string when none found.
 */
export function extractApiErrorMessage(body) {
  if (!body || typeof body !== "object") {
    return "";
  }
  if (typeof body.detail === "string") {
    return body.detail;
  }
  if (Array.isArray(body.detail)) {
    return body.detail
      .map((entry) => entry?.msg || String(entry))
      .join("; ");
  }
  if (typeof body.message === "string") {
    return body.message;
  }
  return "";
}

// ===================================================================
// DOM glue
// ===================================================================

const STEP_ELEMENT_IDS = {
  1: "server-wizard-step-1",
  2: "server-wizard-step-2",
};

function setWizardError(message) {
  const errorEl = safeGetElement("server-wizard-error");
  if (errorEl) {
    errorEl.textContent = message || "";
    errorEl.classList.toggle("hidden", !message);
  }
}

function setWizardStatus(message) {
  const statusEl = safeGetElement("server-wizard-status");
  if (statusEl) {
    statusEl.textContent = message || "";
    statusEl.classList.toggle("hidden", !message);
  }
}

function setWizardBusy(busy) {
  ["server-wizard-create-btn", "server-wizard-skip-btn"].forEach((id) => {
    const button = safeGetElement(id);
    if (button) {
      button.disabled = busy;
      button.classList.toggle("opacity-50", busy);
      button.classList.toggle("cursor-not-allowed", busy);
    }
  });
}

/**
 * Show one wizard step and hide the other. Loads the gateway table the
 * first time step 2 is shown.
 *
 * @param {number} step - Step number (1 or 2).
 */
export function showServerWizardStep(step) {
  Object.entries(STEP_ELEMENT_IDS).forEach(([stepNumber, elementId]) => {
    const el = safeGetElement(elementId);
    if (el) {
      el.classList.toggle("hidden", Number(stepNumber) !== step);
    }
  });

  const indicator = safeGetElement("server-wizard-step-indicator");
  if (indicator) {
    indicator.textContent = t("servers.wizard.stepIndicator", { step });
  }

  if (step === 2) {
    const tbody = safeGetElement("server-wizard-gateways-body");
    if (tbody && !tbody.dataset.loaded) {
      loadServerWizardGateways();
    }
  }
}

/**
 * Read the step 1 fields into a details object.
 *
 * @returns {Object} Wizard details.
 */
export function readWizardDetailsFromDom() {
  const fieldValue = (id) => safeGetElement(id)?.value ?? "";
  const visibility =
    document.querySelector('input[name="server-wizard-visibility"]:checked')
      ?.value || "public";
  return {
    id: fieldValue("server-wizard-id"),
    name: fieldValue("server-wizard-name"),
    description: fieldValue("server-wizard-description"),
    icon: fieldValue("server-wizard-icon"),
    tags: fieldValue("server-wizard-tags"),
    visibility,
    oauthEnabled: safeGetElement("server-wizard-oauth-enabled")?.checked || false,
    oauthAuthorizationServer: fieldValue(
      "server-wizard-oauth-authorization-server",
    ),
    oauthScopes: fieldValue("server-wizard-oauth-scopes"),
    oauthTokenEndpoint: fieldValue("server-wizard-oauth-token-endpoint"),
  };
}

/**
 * Read the gateway IDs checked in the step 2 gateway table.
 *
 * @returns {string[]} Selected gateway IDs.
 */
export function readSelectedWizardGatewayIds() {
  const container = document.getElementById("associatedGateways");
  if (!container) {
    return [];
  }
  return Array.from(
    container.querySelectorAll('input[name="associatedGateways"]:checked'),
  )
    .map((cb) => String(cb.value))
    .filter(Boolean);
}

/**
 * Read the granular selector selections (persistent store plus any
 * currently visible checked boxes).
 *
 * @returns {{tools: string[], resources: string[], prompts: string[]}}
 */
export function readGranularSelections() {
  const result = {};
  Object.entries(GRANULAR_CONTAINER_IDS).forEach(([component, containerId]) => {
    const selections = getEditSelections(containerId);
    const container = document.getElementById(containerId);
    if (container) {
      container
        .querySelectorAll(`input[name="${containerId}"]`)
        .forEach((cb) => {
          if (cb.checked) {
            selections.add(String(cb.value));
          }
        });
    }
    result[component] = Array.from(selections);
  });
  return result;
}

/**
 * Render the step 2 gateway table rows.
 *
 * @param {HTMLElement} tbody - Table body element.
 * @param {Array} gateways - Gateways from GET /gateways.
 */
export function renderServerWizardGateways(tbody, gateways) {
  if (!Array.isArray(gateways) || gateways.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-sm text-center text-gray-500 dark:text-gray-400">${escapeHtml(t("servers.wizard.gatewaysEmpty"))}</td></tr>`;
    return;
  }

  tbody.innerHTML = gateways
    .map((gateway) => {
      const id = String(gateway.id ?? "");
      const name = String(gateway.name ?? id);
      const toolCount = gateway.toolCount ?? gateway.tool_count ?? 0;
      const resourceCount =
        gateway.resourceCount ?? gateway.resource_count ?? 0;
      const promptCount = gateway.promptCount ?? gateway.prompt_count ?? 0;
      const reachable = gateway.reachable !== false;
      const statusKey = reachable
        ? "common.states.online"
        : "common.states.offline";
      const statusClasses = reachable
        ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300"
        : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300";
      return `<tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
        <td class="px-4 py-2">
          <label class="inline-flex items-center">
            <input type="checkbox" name="associatedGateways" value="${escapeHtml(id)}" class="form-checkbox h-4 w-4 text-indigo-600 dark:bg-gray-800 dark:border-gray-600" />
            <span class="sr-only">${escapeHtml(name)}</span>
          </label>
        </td>
        <td class="px-4 py-2 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(name)}</td>
        <td class="px-4 py-2 text-sm text-center text-gray-700 dark:text-gray-300">${toolCount}</td>
        <td class="px-4 py-2 text-sm text-center text-gray-700 dark:text-gray-300">${resourceCount}</td>
        <td class="px-4 py-2 text-sm text-center text-gray-700 dark:text-gray-300">${promptCount}</td>
        <td class="px-4 py-2"><span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusClasses}">${escapeHtml(t(statusKey))}</span></td>
      </tr>`;
    })
    .join("");

  const selectAll = safeGetElement("server-wizard-select-all-gateways");
  if (selectAll) {
    selectAll.checked = false;
  }
}

/**
 * Fetch the registered gateways (including inactive) and render the
 * step 2 source table.
 */
export async function loadServerWizardGateways() {
  const tbody = safeGetElement("server-wizard-gateways-body");
  if (!tbody) {
    return;
  }
  tbody.dataset.loaded = "";
  tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-sm text-center text-gray-500 dark:text-gray-400">${escapeHtml(t("servers.wizard.gatewaysLoading"))}</td></tr>`;

  try {
    const headers = await getAuthHeaders(false);
    const response = await fetch(
      `${window.ROOT_PATH}/gateways?include_inactive=true`,
      { credentials: "include", headers },
    );
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const gateways = await response.json();
    renderServerWizardGateways(tbody, gateways);
    tbody.dataset.loaded = "true";
  } catch (error) {
    console.error("Failed to load gateways for server wizard:", error);
    tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-sm text-center text-red-600 dark:text-red-400">${escapeHtml(t("servers.wizard.gatewaysError"))}</td></tr>`;
  }
}

/**
 * Step 1 → step 2. Blocks advancing when the details are invalid and
 * surfaces the error inline.
 */
export function serverWizardNext() {
  const validation = validateServerWizardDetails(readWizardDetailsFromDom());
  if (!validation.valid) {
    setWizardError(validation.error);
    return;
  }
  setWizardError("");
  showServerWizardStep(2);
}

/**
 * Step 2 → step 1. Step 2 requires nothing, so this never blocks.
 */
export function serverWizardBack() {
  setWizardError("");
  showServerWizardStep(1);
}

/**
 * Create the virtual server from step 2.
 *
 * @param {boolean} skip - Skip flow: create with empty associations.
 */
export async function serverWizardSubmit(skip = false) {
  const validation = validateServerWizardDetails(readWizardDetailsFromDom());
  if (!validation.valid) {
    showServerWizardStep(1);
    setWizardError(validation.error);
    return;
  }

  setWizardError("");
  setWizardBusy(true);

  try {
    const details = readWizardDetailsFromDom();
    const teamId = getCurrentTeamId();

    let gatewayComponents = { tools: [], resources: [], prompts: [] };
    let granular = { tools: [], resources: [], prompts: [] };

    if (!skip) {
      const gatewayIds = readSelectedWizardGatewayIds();
      if (gatewayIds.length > 0) {
        setWizardStatus(t("servers.wizard.aggregating"));
        const headers = await getAuthHeaders(false);
        gatewayComponents = await aggregateGatewayComponentIds(gatewayIds, {
          headers,
        });
      }
      granular = readGranularSelections();
    }

    setWizardStatus(t("servers.wizard.creating"));
    const payload = buildServerWizardPayload({
      details,
      gatewayComponents,
      granular,
      teamId,
      skip,
    });

    const headers = await getAuthHeaders(true);
    const response = await fetch(`${window.ROOT_PATH}/servers`, {
      method: "POST",
      credentials: "include",
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new Error(
        extractApiErrorMessage(body) || t("servers.wizard.createFailed"),
      );
    }

    showSuccessMessage(t("servers.wizard.createSuccess"));
    reloadServersTable();
    resetServerWizard();
  } catch (error) {
    console.error("Server wizard submit failed:", error);
    setWizardError(error.message || t("servers.wizard.createFailed"));
  } finally {
    setWizardStatus("");
    setWizardBusy(false);
  }
}

/**
 * Skip flow entry point: create the virtual server with empty
 * associations.
 */
export function serverWizardSkip() {
  return serverWizardSubmit(true);
}

/**
 * Create flow entry point: aggregate selected sources and create.
 */
export function serverWizardCreate() {
  return serverWizardSubmit(false);
}

/**
 * Reload the servers table through HTMX, matching how filters re-fetch
 * table partials.
 */
function reloadServersTable() {
  const table = document.getElementById("servers-table");
  if (table && window.htmx && window.htmx.trigger) {
    window.htmx.process(table);
    window.htmx.trigger(table, "load");
  }
}

/**
 * Reset the wizard to step 1 with cleared fields and selections.
 */
export function resetServerWizard() {
  [
    "server-wizard-id",
    "server-wizard-name",
    "server-wizard-description",
    "server-wizard-icon",
    "server-wizard-tags",
    "server-wizard-oauth-authorization-server",
    "server-wizard-oauth-scopes",
    "server-wizard-oauth-token-endpoint",
  ].forEach((id) => {
    const el = safeGetElement(id);
    if (el) {
      el.value = "";
    }
  });

  const publicRadio = safeGetElement("server-wizard-visibility-public");
  if (publicRadio) {
    publicRadio.checked = true;
  }

  const oauthToggle = safeGetElement("server-wizard-oauth-enabled");
  if (oauthToggle) {
    oauthToggle.checked = false;
  }
  const oauthSection = safeGetElement("server-wizard-oauth-config-section");
  if (oauthSection) {
    oauthSection.classList.add("hidden");
  }

  const gatewayContainer = document.getElementById("associatedGateways");
  if (gatewayContainer) {
    gatewayContainer
      .querySelectorAll('input[type="checkbox"]')
      .forEach((cb) => {
        cb.checked = false;
      });
  }
  const selectAll = safeGetElement("server-wizard-select-all-gateways");
  if (selectAll) {
    selectAll.checked = false;
  }

  Object.values(GRANULAR_CONTAINER_IDS).forEach((containerId) => {
    delete AppState.editServerSelections[containerId];
    const container = document.getElementById(containerId);
    if (container) {
      container
        .querySelectorAll('input[type="checkbox"]')
        .forEach((cb) => {
          cb.checked = false;
        });
    }
  });

  setWizardError("");
  setWizardStatus("");
  showServerWizardStep(1);
}

/**
 * Wire wizard event listeners that are not covered by data-action
 * delegation. Called once on DOMContentLoaded.
 */
export function initServerWizard() {
  const wizard = document.getElementById("server-wizard");
  if (!wizard || wizard.dataset.initialized === "true") {
    return;
  }
  wizard.dataset.initialized = "true";

  const selectAll = safeGetElement("server-wizard-select-all-gateways");
  if (selectAll) {
    selectAll.addEventListener("change", () => {
      const container = document.getElementById("associatedGateways");
      if (!container) {
        return;
      }
      const boxes = container.querySelectorAll(
        'input[name="associatedGateways"]',
      );
      boxes.forEach((cb) => {
        cb.checked = selectAll.checked;
      });
      // Surface the bulk toggle to the gateway-select wiring (pills,
      // granular selector filtering) through a single change event.
      if (boxes.length > 0) {
        boxes[0].dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  }

  showServerWizardStep(1);
}
