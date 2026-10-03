/**
 * Unit tests for a2aPluginBindings.js module
 * Tests: team filtering of the bindings panel, the add-binding modal helpers,
 *        and the add-binding form validation.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  closeAddBindingForm,
  filterBindingsByTeam,
  showAddBindingForm,
  validateBindingForm,
  validateBindingValues,
} from "../../../mcpgateway/admin_ui/a2aPluginBindings.js";

import { t } from "../../../mcpgateway/admin_ui/i18n.js";

beforeEach(() => {
  window.ROOT_PATH = "";
  window.htmx = { ajax: vi.fn() };
  document.body.innerHTML = `
    <div id="add-binding-modal" class="hidden"></div>
    <form id="add-binding-form">
      <select id="new-binding-team"><option value=""></option><option value="team-1" selected>Core</option></select>
      <select id="new-binding-agent"><option value=""></option><option value="agent-1" selected>Agent</option></select>
      <select id="new-binding-plugin"><option value=""></option><option value="plugin-1" selected>Plugin</option></select>
      <textarea id="new-binding-config">{}</textarea>
    </form>
  `;
});

afterEach(() => {
  vi.restoreAllMocks();
  delete window.htmx;
  delete window.ROOT_PATH;
});

describe("filterBindingsByTeam", () => {
  test("reloads the panel with the team filter", () => {
    filterBindingsByTeam("team-1");
    expect(window.htmx.ajax).toHaveBeenCalledWith(
      "GET",
      "/admin/a2a/plugin-bindings/partial?team_id=team-1",
      { target: "#a2a-plugin-bindings-panel", swap: "innerHTML" }
    );
  });

  test("drops the filter when the all-teams option is chosen", () => {
    Object.defineProperty(window, "location", {
      value: { ...window.location, search: "?team_id=team-1" },
      writable: true,
      configurable: true,
    });
    filterBindingsByTeam("");
    expect(window.htmx.ajax.mock.calls[0][1]).toBe(
      "/admin/a2a/plugin-bindings/partial"
    );
    Object.defineProperty(window, "location", {
      value: { ...window.location, search: "" },
      writable: true,
      configurable: true,
    });
  });
});

describe("add-binding modal", () => {
  test("showAddBindingForm reveals the modal", () => {
    showAddBindingForm();
    expect(document.getElementById("add-binding-modal").classList).not.toContain(
      "hidden"
    );
  });

  test("closeAddBindingForm hides the modal", () => {
    document.getElementById("add-binding-modal").classList.remove("hidden");
    closeAddBindingForm();
    expect(document.getElementById("add-binding-modal").classList).toContain(
      "hidden"
    );
  });
});

describe("validateBindingValues", () => {
  test("accepts a complete set of values", () => {
    expect(
      validateBindingValues({
        team: "team-1",
        agent: "agent-1",
        plugin: "plugin-1",
        configRaw: '{"key": "value"}',
      })
    ).toEqual({ valid: true, error: null });
  });

  test("requires team, agent and plugin", () => {
    const outcome = validateBindingValues({
      team: "",
      agent: "agent-1",
      plugin: "plugin-1",
      configRaw: "{}",
    });
    expect(outcome.valid).toBe(false);
    expect(outcome.error).toBe(t("plugins.bindings.validation.required"));
  });

  test("reports a JSON parse failure with the parser message", () => {
    const outcome = validateBindingValues({
      team: "team-1",
      agent: "agent-1",
      plugin: "plugin-1",
      configRaw: "{not json}",
    });
    expect(outcome.valid).toBe(false);
    expect(outcome.error).toContain("JSON");
  });

  test("treats an empty config field as an empty object", () => {
    const outcome = validateBindingValues({
      team: "team-1",
      agent: "agent-1",
      plugin: "plugin-1",
      configRaw: "",
    });
    expect(outcome.valid).toBe(true);
  });
});

describe("validateBindingForm", () => {
  test("cancels the submit and closes the modal only on valid input", () => {
    const modal = document.getElementById("add-binding-modal");
    modal.classList.remove("hidden");

    const event = { preventDefault: vi.fn(), stopImmediatePropagation: vi.fn() };
    expect(validateBindingForm(event)).toBe(true);
    expect(event.preventDefault).not.toHaveBeenCalled();
    expect(modal.classList).toContain("hidden");
  });

  test("stops an invalid submit before HTMX sees it", () => {
    document.getElementById("new-binding-plugin").value = "";
    vi.spyOn(window, "alert").mockImplementation(() => {});

    const event = { preventDefault: vi.fn(), stopImmediatePropagation: vi.fn() };
    expect(validateBindingForm(event)).toBe(false);
    expect(event.preventDefault).toHaveBeenCalled();
    expect(event.stopImmediatePropagation).toHaveBeenCalled();
    expect(window.alert).toHaveBeenCalled();
  });
});
