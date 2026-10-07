/**
 * Team Management Actions
 *
 * Team CRUD helpers, join-request flows, team-context switching, the bulk
 * import sample download, and OAuth endpoint discovery. Extracted from inline
 * scripts in admin.html; registered on window.Admin in admin.js.
 */

import { t } from "./i18n.js";
import { openModal, closeModal } from "./modals.js";
import { escapeHtml } from "./security.js";
import { getCookie, getPaginationParams, getRootPath, showToast } from "./utils.js";

/**
 * Switch the active team context by navigating with an updated team_id query
 * parameter. A full navigation is deliberate: pushState plus DOM replacement
 * caused stack overflows in the past.
 * @param {string} teamId - Team UUID to activate, or empty for all teams
 */
export const updateTeamContext = function (teamId) {
  // Prevent double-invocation if user clicks rapidly
  if (window.__teamSwitchingInProgress) {
    console.log("Team switch already in progress, ignoring");
    return;
  }
  window.__teamSwitchingInProgress = true;

  try {
    const url = new URL(window.location.href);

    if (teamId && teamId !== "") {
      url.searchParams.set("team_id", teamId);
    } else {
      url.searchParams.delete("team_id");
    }

    window.location.assign(url.toString());
  } finally {
    // Navigation should occur immediately; clear the guard if it fails.
    setTimeout(() => {
      window.__teamSwitchingInProgress = false;
    }, 2000);
  }
};

// Read by formFieldHandlers.js, teams.js and components/team-selector.js via
// the global scope; keep the bare global in place for those call sites.
window.updateTeamContext = updateTeamContext;

/**
 * Open the create-team modal and focus the team name field.
 */
export const openCreateTeamModal = function () {
  openModal("create-team-modal");
  setTimeout(() => {
    document.getElementById("team-name").focus();
  }, 100);
};

/**
 * Close the create-team modal and reset its form.
 */
export const closeCreateTeamModal = function () {
  closeModal("create-team-modal");
  document.getElementById("create-team-form").reset();
};

/**
 * Ask to join a team, from a button carrying data-team-id/data-team-name.
 * @param {HTMLElement} button - Triggering button element
 */
export const requestToJoinTeamSafe = function (button) {
  const teamId = button.getAttribute("data-team-id");
  const teamName = button.getAttribute("data-team-name");
  if (confirm(t("teams.confirm.requestJoin", { team: teamName }))) {
    window.htmx
      .ajax("POST", `${getRootPath()}/admin/teams/${teamId}/join-request`, {
        target: button.parentElement,
        swap: "innerHTML",
      })
      .catch(() => {
        showToast(t("teams.toast.joinRequestFailed"), "error");
      });
  }
};

/**
 * Leave a team, from a button carrying data-team-id/data-team-name.
 * The backend HX-Trigger refreshes the list after the DB commit.
 * @param {HTMLElement} button - Triggering button element
 */
export const leaveTeamSafe = function (button) {
  const teamId = button.getAttribute("data-team-id");
  const teamName = button.getAttribute("data-team-name");
  if (confirm(t("teams.confirm.leaveShort", { team: teamName }))) {
    window.htmx.ajax("POST", `${getRootPath()}/admin/teams/${teamId}/leave`, {
      target: "body",
      swap: "none",
    });
  }
};

/**
 * Open the edit-team modal with fresh content loaded over HTMX.
 * Stale content is cleared first to avoid races with the delayed
 * closeTeamEditModal timer.
 * @param {HTMLElement} button - Triggering button element
 */
export const editTeamSafe = function (button) {
  const teamId = button.getAttribute("data-team-id");
  const modalContent = document.getElementById("team-edit-modal-content");
  if (modalContent) {
    modalContent.innerHTML = "";
  }
  window.htmx
    .ajax("GET", `${getRootPath()}/admin/teams/${teamId}/edit`, {
      target: "#team-edit-modal-content",
      swap: "innerHTML",
    })
    .then(() => {
      document.getElementById("team-edit-modal").classList.remove("hidden");
    });
};

/**
 * Open the members view for a team, from a data-team-id button.
 * @param {HTMLElement} button - Triggering button element
 */
export const manageTeamMembersSafe = function (button) {
  const teamId = button.getAttribute("data-team-id");
  loadTeamMembersView(teamId);
};

/**
 * Load the members view of a team into the team edit modal.
 * @param {string} teamId - Team UUID
 */
export const loadTeamMembersView = function (teamId) {
  const modalContent = document.getElementById("team-edit-modal-content");
  if (modalContent) {
    modalContent.innerHTML = "";
  }
  window.htmx
    .ajax("GET", `${getRootPath()}/admin/teams/${teamId}/members`, {
      target: "#team-edit-modal-content",
      swap: "innerHTML",
    })
    .then(() => {
      document.getElementById("team-edit-modal").classList.remove("hidden");
    });
};

/**
 * Delete a team, from a button carrying data-team-id/data-team-name.
 * The backend HX-Trigger refreshes the list after the DB commit.
 * @param {HTMLElement} button - Triggering button element
 */
export const deleteTeamSafe = function (button) {
  const teamId = button.getAttribute("data-team-id");
  const teamName = button.getAttribute("data-team-name");
  if (confirm(t("teams.confirm.deleteTeam", { team: teamName }))) {
    window.htmx.ajax("DELETE", `${getRootPath()}/admin/teams/${teamId}`, {
      target: "body",
      swap: "none",
    });
  }
};

/**
 * Cancel the current user's own pending join request.
 * @param {string} teamId - Team UUID
 * @param {string} requestId - Join request UUID
 */
export const cancelJoinRequest = function (teamId, requestId) {
  if (confirm(t("teams.confirm.cancelJoinRequest"))) {
    window.htmx.ajax(
      "DELETE",
      `${getRootPath()}/admin/teams/${teamId}/join-request/${requestId}`,
      {
        target: "body",
        swap: "none",
      }
    );
  }
};

/**
 * Open the join-requests modal for a team, from a data-team-id button.
 * @param {HTMLElement} button - Triggering button element
 */
export const viewJoinRequestsSafe = function (button) {
  const teamId = button.getAttribute("data-team-id");
  window.htmx
    .ajax("GET", `${getRootPath()}/admin/teams/${teamId}/join-requests`, {
      target: "#team-join-requests-modal-content",
      swap: "innerHTML",
    })
    .then(() => {
      document
        .getElementById("team-join-requests-modal")
        .classList.remove("hidden");
    });
};

/**
 * Build the teams partial URL from the current search/filter/pagination
 * state. Pure helper, split out for testability.
 * @param {string} rootPath - Application root path prefix
 * @param {Object} state - Current UI state
 * @param {number} state.page - Current page number
 * @param {number} state.perPage - Page size
 * @param {string} [state.searchQuery] - Active search text
 * @param {string} [state.relationship] - Active relationship filter
 * @returns {string} Partial URL with query string
 */
export const buildTeamsPartialUrl = function (
  rootPath,
  { page, perPage, searchQuery, relationship }
) {
  const params = new URLSearchParams();
  params.set("page", page);
  params.set("per_page", perPage);
  if (searchQuery) {
    params.set("q", searchQuery);
  }
  if (relationship && relationship !== "all") {
    params.set("relationship", relationship);
  }
  return `${rootPath}/admin/teams/partial?${params.toString()}`;
};

/**
 * Load the teams list via the /teams/partial endpoint, preserving the current
 * search, filter and pagination state.
 *
 * One teams tab click reaches this loader twice: the delegated tab action and
 * the tab module both run showTab, and the panel guard in showTab does not stop
 * the second pass. Collapse those passes into a single request, and let a later
 * click refresh the list.
 * @returns {Promise|null} The pending request, or null when a duplicate call is suppressed
 */
export const initializeTeamManagement = function () {
  const searchInput = document.getElementById("team-search");
  const searchQuery = searchInput ? searchInput.value.trim() : "";
  const activeFilterBtn = document.querySelector(".filter-btn.active");
  const relationship = activeFilterBtn
    ? activeFilterBtn.getAttribute("data-filter")
    : "all";

  const paginationState = getPaginationParams("teams");
  const url = buildTeamsPartialUrl(getRootPath(), {
    page: paginationState.page,
    perPage: paginationState.perPage,
    searchQuery,
    relationship,
  });

  const now = Date.now();
  if (teamsListRequest && teamsListRequestUrl === url) {
    return teamsListRequest;
  }
  if (url === teamsListLastUrl && now - teamsListLastAt < TEAMS_LIST_DEDUPE_MS) {
    return null;
  }

  teamsListLastUrl = url;
  teamsListLastAt = now;
  teamsListRequestUrl = url;

  teamsListRequest = window.htmx.ajax("GET", url, {
    target: "#unified-teams-list",
    swap: "innerHTML",
    indicator: "#teams-loading",
  });
  teamsListRequest
    .catch(() => {
      // Let an immediate retry through after a failed load
      teamsListLastAt = 0;
    })
    .finally(() => {
      teamsListRequest = null;
    });

  return teamsListRequest;
};

// tabs.js reads this bare global when the teams tab is shown.
window.initializeTeamManagement = initializeTeamManagement;

// Dedupe state for the teams list loader. Reads and writes stay in this module
// so the guard applies to every caller.
let teamsListRequest = null;
let teamsListRequestUrl = null;
let teamsListLastUrl = null;
let teamsListLastAt = 0;
const TEAMS_LIST_DEDUPE_MS = 1000;

/**
 * Sample payload offered as a download template for bulk tool import.
 */
export const SAMPLE_TOOLS_DATA = [
  {
    name: "weather-api",
    displayName: "Weather API Tool",
    url: "https://api.openweathermap.org/data/2.5/weather",
    integration_type: "REST",
    request_type: "GET",
    description: "Get current weather data for any location",
    auth_type: "bearer",
    auth_value: "your-openweather-api-key-here", // pragma: allowlist secret
    headers: {
      Accept: "application/json",
      "User-Agent": "AI Gateway/1.0",
    },
    input_schema: {
      type: "object",
      properties: {
        q: {
          type: "string",
          description: "City name, state code and country code divided by comma",
        },
        units: {
          type: "string",
          description: "Temperature units",
          enum: ["standard", "metric", "imperial"],
          default: "metric",
        },
      },
      required: ["q"],
    },
    jsonpath_filter: "$.main",
    tags: ["weather", "api", "external"],
  },
  {
    name: "user-management",
    displayName: "User Management API",
    url: "https://api.mycompany.com/v1/users",
    integration_type: "REST",
    request_type: "POST",
    description: "Create new user accounts in the system",
    auth_type: "basic",
    auth_value: "api-username:api-password", // pragma: allowlist secret
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-API-Version": "1.0",
    },
    input_schema: {
      type: "object",
      properties: {
        email: { type: "string", format: "email", description: "User's email address" },
        firstName: { type: "string", description: "User's first name" },
        lastName: { type: "string", description: "User's last name" },
        role: { type: "string", enum: ["user", "admin"], default: "user" },
        department: { type: "string", description: "User's department" },
      },
      required: ["email", "firstName", "lastName"],
    },
    tags: ["users", "crud", "internal"],
  },
  {
    name: "slack-notify",
    displayName: "Slack Notification Tool",
    url: "https://hooks.slack.com/services/your/webhook/url",
    integration_type: "REST",
    request_type: "POST",
    description: "Send notifications to Slack channels",
    auth_type: "authheaders",
    auth_value: "Authorization: Bearer xoxb-your-slack-token", // pragma: allowlist secret
    headers: {
      "Content-Type": "application/json",
    },
    input_schema: {
      type: "object",
      properties: {
        channel: { type: "string", description: "Slack channel (e.g., #general)" },
        text: { type: "string", description: "Message text" },
        username: { type: "string", description: "Bot username", default: "AI Gateway" },
      },
      required: ["text"],
    },
    tags: ["notifications", "slack", "communication"],
  },
];

/**
 * Download the sample bulk-import JSON payload.
 */
export const downloadSampleJSON = function () {
  const blob = new Blob([JSON.stringify(SAMPLE_TOOLS_DATA, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "bulk-import-sample.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

/**
 * Render a status message into an OAuth discovery status element.
 * @param {HTMLElement} el - Status element
 * @param {string} type - One of info, success, error
 * @param {string} html - HTML content to show
 */
function oauthDiscoverStatus(el, type, html) {
  if (!el) {
    return;
  }
  const colours = {
    info: "text-blue-600",
    success: "text-green-600",
    error: "text-red-600",
  };
  el.className = `oauth-discover-status mt-1 text-sm ${colours[type] || ""}`;
  el.innerHTML = html;
  el.classList.remove("hidden");
}

/**
 * Discover OAuth endpoints for an Issuer URL (RFC 8414 / OIDC Discovery) and
 * populate the surrounding gateway form. Called by the Discover buttons next
 * to each Issuer URL field.
 * @param {HTMLElement} btn - The Discover button element
 */
export const discoverOAuthEndpoints = async function (btn) {
  const section = btn.parentElement.parentElement;
  const statusEl = section.querySelector(".oauth-discover-status");
  const form = btn.closest("form");

  const issuerInput = form
    ? form.querySelector('input[name="oauth_issuer"]')
    : section.querySelector('input[name="oauth_issuer"]');
  const issuer = issuerInput?.value?.trim();

  if (!issuer) {
    oauthDiscoverStatus(statusEl, "error", "Please enter an Issuer URL first.");
    return;
  }

  btn.disabled = true;
  btn.textContent = "⏳ Discovering…";
  oauthDiscoverStatus(statusEl, "info", "Contacting issuer metadata endpoint…");

  try {
    const resp = await fetch(`${getRootPath()}/admin/gateways/discover-oauth`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": getCookie("mcpgateway_csrf_token") || "",
      },
      body: JSON.stringify({ issuer }),
    });
    const data = await resp.json();

    if (!data.success) {
      oauthDiscoverStatus(
        statusEl,
        "error",
        `Discovery failed: ${escapeHtml(data.error || data.message || "Unknown error")}. ` +
          "Please configure Token URL and Authorization URL manually."
      );
      return;
    }

    // Map discovered values to form field names
    const discovered = {
      oauth_token_url: data.token_endpoint,
      oauth_authorization_url: data.authorization_endpoint,
    };

    let populated = 0;
    for (const [name, value] of Object.entries(discovered)) {
      if (!value) {
        continue;
      }
      const el = form
        ? form.querySelector(`input[name="${name}"]`)
        : document.querySelector(`input[name="${name}"]`);
      if (!el) {
        continue;
      }
      el.value = value;
      el.dataset.discovered = "true";
      el.readOnly = true;
      el.title = "Auto-discovered — clear the Issuer URL field to edit manually";
      el.classList.add("bg-gray-50", "text-gray-500", "cursor-not-allowed");
      populated++;
    }

    const dcrBadge = data.dcr_available
      ? '<span class="ml-2 inline-flex items-center px-2 py-0.5 text-xs font-medium bg-green-100 text-green-700 rounded">DCR available</span>'
      : '<span class="ml-2 inline-flex items-center px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-500 rounded">No DCR</span>';

    oauthDiscoverStatus(
      statusEl,
      "success",
      `✅ Discovered ${populated} endpoint${populated !== 1 ? "s" : ""} from ` +
        `<code class="font-mono text-xs">${escapeHtml(issuer)}</code>${dcrBadge}`
    );
  } catch (err) {
    oauthDiscoverStatus(statusEl, "error", `Network error: ${escapeHtml(err.message)}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "🔍 Discover";
  }
};

/**
 * Wire the teams tab and the create-team form to the teams list loader.
 *
 * A tab click reaches the loader twice: tabs.js loads the panel, and this
 * handler refreshes it. The dedupe guard in initializeTeamManagement collapses
 * the pair into one request, and a later click on the active tab still
 * refreshes the list. Landing on the teams tab by URL is handled by
 * initialization.js, which runs showTab.
 */
export const initTeamActions = function () {
  const teamsTab = document.getElementById("tab-teams");
  if (teamsTab) {
    teamsTab.addEventListener("click", () => {
      setTimeout(initializeTeamManagement, 100);
    });
  }

  document.addEventListener("htmx:afterRequest", (evt) => {
    if (
      evt.detail.xhr.status === 201 &&
      evt.detail.elt.id === "create-team-form"
    ) {
      closeCreateTeamModal();
      initializeTeamManagement();
    }
  });
};

document.addEventListener("DOMContentLoaded", initTeamActions);
