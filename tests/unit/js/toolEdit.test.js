/**
 * Unit tests for toolEdit.js module
 * Tests: the integration-type change handler and the edit-modal observer that
 *        re-evaluates field enablement whenever the modal opens.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  handleEditIntegrationTypeChange,
  initToolEditModalObserver,
} from "../../../mcpgateway/admin_ui/toolEdit.js";

beforeEach(() => {
  document.body.innerHTML = `
    <div id="tool-edit-modal" class="hidden">
      <select id="edit-tool-type">
        <option value="REST">REST</option>
        <option value="MCP">MCP</option>
      </select>
      <select id="edit-tool-request-type">
        <option value="">none</option>
        <option value="GET">GET</option>
        <option value="POST">POST</option>
      </select>
    </div>
  `;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("handleEditIntegrationTypeChange", () => {
  test("enables the HTTP verb select for REST tools", () => {
    const type = document.getElementById("edit-tool-type");
    const requestType = document.getElementById("edit-tool-request-type");
    type.value = "REST";
    requestType.value = "POST";

    handleEditIntegrationTypeChange();

    expect(requestType.disabled).toBe(false);
    expect(requestType.value).toBe("POST");
  });

  test("disables and clears the HTTP verb select for MCP tools", () => {
    const type = document.getElementById("edit-tool-type");
    const requestType = document.getElementById("edit-tool-request-type");
    type.value = "MCP";
    requestType.value = "POST";

    handleEditIntegrationTypeChange();

    expect(requestType.disabled).toBe(true);
    expect(requestType.value).toBe("");
  });

  test("does nothing when the modal fields are absent", () => {
    document.body.innerHTML = "";
    expect(() => handleEditIntegrationTypeChange()).not.toThrow();
  });
});

describe("initToolEditModalObserver", () => {
  test("re-evaluates the fields when the modal opens", async () => {
    const modal = document.getElementById("tool-edit-modal");
    const type = document.getElementById("edit-tool-type");
    const requestType = document.getElementById("edit-tool-request-type");
    type.value = "MCP";
    requestType.disabled = false;

    initToolEditModalObserver();

    // The handler is deferred one tick, so prefilled values land first.
    modal.classList.remove("hidden");
    await vi.waitFor(() => expect(requestType.disabled).toBe(true));
  });

  test("retargets the fields on every open", async () => {
    const modal = document.getElementById("tool-edit-modal");
    const type = document.getElementById("edit-tool-type");
    const requestType = document.getElementById("edit-tool-request-type");

    initToolEditModalObserver();

    type.value = "MCP";
    modal.classList.remove("hidden");
    await vi.waitFor(() => expect(requestType.disabled).toBe(true));

    type.value = "REST";
    modal.classList.add("hidden");
    modal.classList.remove("hidden");
    await vi.waitFor(() => expect(requestType.disabled).toBe(false));
  });

  test("does nothing when the modal is absent", () => {
    document.body.innerHTML = "";
    expect(() => initToolEditModalObserver()).not.toThrow();
  });
});
