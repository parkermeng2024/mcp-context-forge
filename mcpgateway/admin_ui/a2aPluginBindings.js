/**
 * A2A Agent Plugin Bindings
 *
 * Handlers for the a2a_agent_plugin_bindings_partial.html panel: team filter,
 * add-binding modal open/close, and add-binding form validation. Extracted
 * from the partial's inline script; registered on window.Admin in admin.js.
 */

import { t } from "./i18n.js";
import { getRootPath } from "./utils.js";

/**
 * Reload the bindings panel filtered by team.
 * @param {string} teamId - Team UUID to filter by, or empty for all
 */
export const filterBindingsByTeam = function (teamId) {
  const params = new URLSearchParams(window.location.search);
  if (teamId) {
    params.set("team_id", teamId);
  } else {
    params.delete("team_id");
  }
  const url =
    `${getRootPath()}/admin/a2a/plugin-bindings/partial` +
    (params.toString() ? `?${params.toString()}` : "");
  window.htmx.ajax("GET", url, {
    target: "#a2a-plugin-bindings-panel",
    swap: "innerHTML",
  });
};

/**
 * Open the add-binding modal.
 */
export const showAddBindingForm = function () {
  document.getElementById("add-binding-modal").classList.remove("hidden");
};

/**
 * Close the add-binding modal.
 */
export const closeAddBindingForm = function () {
  document.getElementById("add-binding-modal").classList.add("hidden");
};

/**
 * Validate add-binding form values.
 * @param {Object} values - Form values
 * @param {string} values.team - Selected team ID
 * @param {string} values.agent - Selected agent name
 * @param {string} values.plugin - Selected plugin ID
 * @param {string} values.configRaw - Raw JSON config text
 * @returns {{ valid: boolean, error: string|null }} Validation outcome
 */
export const validateBindingValues = function ({ team, agent, plugin, configRaw }) {
  if (!team || !agent || !plugin) {
    return { valid: false, error: t("plugins.bindings.validation.required") };
  }

  try {
    JSON.parse(configRaw || "{}");
  } catch (e) {
    return {
      valid: false,
      error: t("plugins.bindings.validation.invalidJson", { error: e.message }),
    };
  }

  return { valid: true, error: null };
};

/**
 * Delegated submit handler for the add-binding form. On invalid input the
 * event is cancelled and stopped so HTMX never issues the hx-post; on success
 * the modal closes and propagation continues so HTMX submits normally.
 * @param {Event} event - Submit event
 * @returns {boolean} True when the form may submit
 */
export const validateBindingForm = function (event) {
  const outcome = validateBindingValues({
    team: document.getElementById("new-binding-team").value,
    agent: document.getElementById("new-binding-agent").value,
    plugin: document.getElementById("new-binding-plugin").value,
    configRaw: document.getElementById("new-binding-config").value || "{}",
  });

  if (!outcome.valid) {
    alert(outcome.error);
    event.preventDefault();
    event.stopImmediatePropagation();
    return false;
  }

  closeAddBindingForm();
  return true;
};
