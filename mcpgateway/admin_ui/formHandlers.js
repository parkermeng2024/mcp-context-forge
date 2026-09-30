import { PANEL_SEARCH_CONFIG, TOGGLE_FRAGMENT_MAP } from "./constants.js";
import { t } from "./i18n.js";
import { navigateAdmin } from "./navigation.js";
import { buildTableUrl, getCookie, isInactiveChecked } from "./utils.js";

// ===================================================================
// ENTITY TYPE DISPLAY NAMES
// ===================================================================
// Maps entity type keys (plural/kebab-case) to the catalog key that holds the
// lowercase singular noun for UI messages.
const ENTITY_DISPLAY_NAMES = {
  tools: "common.entityLower.tool",
  resources: "common.entityLower.resource",
  prompts: "common.entityLower.prompt",
  gateways: "common.entityLower.gateway",
  catalog: "common.entityLower.server",
  "a2a-agents": "common.entityLower.agent",
  agent: "common.entityLower.agent",
  servers: "common.entityLower.server",
  teams: "common.entityLower.team",
  users: "common.entityLower.user",
  roots: "common.entityLower.root",
};

// ===================================================================
// FORM SUBMISSION AND REFRESH HANDLING
// ===================================================================
// Handles form submission (toggle/delete operations) and refreshes the table
// via HTMX. Used by both handleSubmitWithConfirmation and handleDeleteSubmit.
export const handleFormSubmitAndRefresh = async function (event, type) {
  event.preventDefault();

  const isInactiveCheckedBool = isInactiveChecked(type);
  const form = event.target;
  const teamId = new URL(window.location.href).searchParams.get("team_id");

  // Build FormData from current form state (captures any fields already
  // appended by handleDeleteSubmit such as purge_metrics).
  const formData = new FormData(form);
  formData.set("is_inactive_checked", String(isInactiveCheckedBool));
  if (teamId && !formData.has("team_id")) {
    formData.set("team_id", teamId);
  }
  const csrfToken =
    typeof getCookie === "function"
      ? getCookie("mcpgateway_csrf_token") || ""
      : "";
  if (csrfToken) {
    formData.set("csrf_token", csrfToken);
  }

  let panelConfig = null;

  try {
    // Validate PANEL_SEARCH_CONFIG registration before proceeding
    panelConfig = PANEL_SEARCH_CONFIG[type];
    if (!panelConfig) {
      throw new Error(
        `No PANEL_SEARCH_CONFIG found for type: ${type}. All entity types must be registered in PANEL_SEARCH_CONFIG (constants.js) with partialPath and targetSelector.`
      );
    }

    // Use redirect:'manual' so the browser does not follow the 303
    // redirect to the backend-direct URL (which bypasses the proxy).
    const response = await fetch(form.action, {
      method: "POST",
      body: formData,
      credentials: "include", // pragma: allowlist secret
      redirect: "manual",
    });
    if (!response.ok && response.status !== 0) {
      // status === 0 can occur with opaque redirected responses
      throw new Error(`Submit failed: ${response.status}`);
    }

    // Use HTMX to refresh the table instead of full page reload
    const fragment = TOGGLE_FRAGMENT_MAP[type] || type;

    // Build refresh params preserving search, tags, pagination, and filters
    const refreshParams = {
      include_inactive: isInactiveCheckedBool.toString(),
    };

    // Read current search query from DOM
    if (panelConfig.searchInputId) {
      const searchInput = document.getElementById(panelConfig.searchInputId);
      if (searchInput?.value) {
        refreshParams.q = searchInput.value;
      }
    }

    // Read current tag filter from DOM
    if (panelConfig.tagInputId) {
      const tagInput = document.getElementById(panelConfig.tagInputId);
      if (tagInput?.value) {
        refreshParams.tags = tagInput.value;
      }
    }

    // Add team_id if present
    if (teamId) {
      refreshParams.team_id = teamId;
    }

    // Trigger HTMX request to refresh the table using PANEL_SEARCH_CONFIG
    const partialPath = panelConfig.partialPath;
    const targetSelector = panelConfig.targetSelector;
    const tableName = panelConfig.tableName;

    // Use buildTableUrl to preserve pagination state
    const partialUrl = buildTableUrl(
      tableName,
      `${window.ROOT_PATH}/admin/${partialPath}`,
      refreshParams
    );

    // Build fallback params preserving state for non-HTMX or error paths
    const fallbackParams = new URLSearchParams();
    for (const [key, value] of Object.entries(refreshParams)) {
      fallbackParams.set(key, value);
    }

    if (panelConfig.fallbackOnly || !window.htmx) {
      // Fallback to full reload for entities without HTMX partial support
      navigateAdmin(fragment, fallbackParams);
    } else {
      window.htmx.ajax('GET', partialUrl, {
        target: targetSelector,
        swap: 'outerHTML'
      });
    }
  } catch (error) {
    // Network error or missing config — notify user and fallback to full reload
    console.error("Form submit error:", error);
    alert("Failed to refresh table. Reloading page...");
    const fragment = TOGGLE_FRAGMENT_MAP[type] || type;
    const params = new URLSearchParams();
    params.set("include_inactive", String(isInactiveCheckedBool));
    if (teamId) {
      params.set("team_id", teamId);
    }
    // Preserve search/tag state when panelConfig is available
    if (panelConfig) {
      if (panelConfig.searchInputId) {
        const searchInput = document.getElementById(panelConfig.searchInputId);
        if (searchInput?.value) {
          params.set("q", searchInput.value);
        }
      }
      if (panelConfig.tagInputId) {
        const tagInput = document.getElementById(panelConfig.tagInputId);
        if (tagInput?.value) {
          params.set("tags", tagInput.value);
        }
      }
    }
    navigateAdmin(fragment, params);
  }
};

// Legacy alias for backward compatibility
export const handleToggleSubmit = handleFormSubmitAndRefresh;

export const handleSubmitWithConfirmation = function (event, type) {
  event.preventDefault();

  const displayName = t(ENTITY_DISPLAY_NAMES[type] || type);
  const confirmationMessage = t("common.confirm.deleteEntity", { entity: displayName });
  const confirmation = confirm(confirmationMessage);
  if (!confirmation) {
    return false;
  }

  return handleFormSubmitAndRefresh(event, type);
};

export const handleDeleteSubmit = function (
  event,
  type,
  name = "",
  inactiveType = ""
) {
  event.preventDefault();

  const displayName = t(ENTITY_DISPLAY_NAMES[type] || type);
  const targetName = name
    ? t("common.confirm.entityQuoted", { entity: displayName, name })
    : t("common.confirm.entityThis", { entity: displayName });
  const confirmationMessage = t("common.confirm.deleteNamed", { target: targetName });
  const confirmation = confirm(confirmationMessage);
  if (!confirmation) {
    return false;
  }

  const purgeConfirmation = confirm(
    t("common.confirm.purgeMetrics", { target: targetName })
  );
  if (purgeConfirmation) {
    const form = event.target;
    const purgeField = document.createElement("input");
    purgeField.type = "hidden";
    purgeField.name = "purge_metrics";
    purgeField.value = "true";
    form.appendChild(purgeField);
  }

  const toggleType = inactiveType || type;
  return handleFormSubmitAndRefresh(event, toggleType);
};
