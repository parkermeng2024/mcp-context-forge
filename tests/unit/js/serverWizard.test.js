/**
 * Unit tests for serverWizard.js module
 * Tests: validateServerWizardDetails (step gating), parseTagsInput,
 *        extractNextCursor / extractPageItems, fetchAllComponentIdsForGateway
 *        (cursor handling), aggregateGatewayComponentIds, unionIds,
 *        buildServerWizardPayload (union + dedupe, skip flow, OAuth),
 *        extractApiErrorMessage, serverWizardNext, serverWizardSubmit
 *        (payload assembly, skip flow, error surface)
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  aggregateGatewayComponentIds,
  buildServerWizardPayload,
  extractApiErrorMessage,
  extractNextCursor,
  extractPageItems,
  fetchAllComponentIdsForGateway,
  parseTagsInput,
  readSelectedWizardGatewayIds,
  serverWizardNext,
  serverWizardSubmit,
  unionIds,
  validateServerWizardDetails,
  WIZARD_DESCRIPTION_MAX_LENGTH,
  WIZARD_NAME_MAX_LENGTH,
} from "../../../mcpgateway/admin_ui/serverWizard.js";
import { showSuccessMessage } from "../../../mcpgateway/admin_ui/utils.js";

vi.mock("../../../mcpgateway/admin_ui/auth.js", () => ({
  getAuthHeaders: vi.fn(async () => ({ "X-CSRF-Token": "test-csrf" })),
}));
vi.mock("../../../mcpgateway/admin_ui/security.js", () => ({
  escapeHtml: (s) => String(s),
  validateInputName: (s) => {
    if (!s || String(s).trim() === "") {
      return { valid: false, error: "Name is required" };
    }
    return { valid: true, value: String(s).trim() };
  },
}));
vi.mock("../../../mcpgateway/admin_ui/servers.js", () => ({
  getEditSelections: vi.fn(() => new Set()),
}));
vi.mock("../../../mcpgateway/admin_ui/appState.js", () => ({
  AppState: { editServerSelections: {} },
}));
vi.mock("../../../mcpgateway/admin_ui/utils.js", () => ({
  getCurrentTeamId: vi.fn(() => null),
  safeGetElement: (id) => document.getElementById(id),
  showSuccessMessage: vi.fn(),
}));

function jsonResponse(body, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => body };
}

function setupWizardDom() {
  document.body.innerHTML = `
    <div id="server-wizard">
      <span id="server-wizard-step-indicator"></span>
      <span id="server-wizard-error" class="hidden"></span>
      <div id="server-wizard-status" class="hidden"></div>
      <div id="server-wizard-step-1">
        <input id="server-wizard-id" value="" />
        <input id="server-wizard-name" value="My Server" />
        <textarea id="server-wizard-description">A description</textarea>
        <input id="server-wizard-icon" value="" />
        <input id="server-wizard-tags" value="alpha, beta" />
        <input type="radio" name="server-wizard-visibility" value="public" id="server-wizard-visibility-public" checked />
        <input type="checkbox" id="server-wizard-oauth-enabled" />
        <div id="server-wizard-oauth-config-section" class="hidden">
          <input id="server-wizard-oauth-authorization-server" value="" />
          <input id="server-wizard-oauth-scopes" value="" />
          <input id="server-wizard-oauth-token-endpoint" value="" />
        </div>
      </div>
      <div id="server-wizard-step-2" class="hidden">
        <div id="associatedGateways">
          <input type="checkbox" name="associatedGateways" value="gw1" checked />
          <input type="checkbox" name="associatedGateways" value="gw2" />
        </div>
        <button id="server-wizard-create-btn"></button>
        <button id="server-wizard-skip-btn"></button>
      </div>
    </div>
    <div id="servers-table"></div>
  `;
}

beforeEach(() => {
  window.ROOT_PATH = "";
});

afterEach(() => {
  document.body.innerHTML = "";
  delete window.ROOT_PATH;
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// parseTagsInput
// ---------------------------------------------------------------------------
describe("parseTagsInput", () => {
  test("parses comma-separated tags and trims whitespace", () => {
    expect(parseTagsInput("alpha, beta ,,gamma")).toEqual([
      "alpha",
      "beta",
      "gamma",
    ]);
  });

  test("returns empty array for empty or non-string input", () => {
    expect(parseTagsInput("")).toEqual([]);
    expect(parseTagsInput(null)).toEqual([]);
    expect(parseTagsInput(undefined)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// validateServerWizardDetails (step 1 gating)
// ---------------------------------------------------------------------------
describe("validateServerWizardDetails", () => {
  test("blocks an empty name", () => {
    const result = validateServerWizardDetails({ name: "   " });
    expect(result.valid).toBe(false);
    expect(result.error).toBeTruthy();
  });

  test("blocks a name over the max length", () => {
    const result = validateServerWizardDetails({
      name: "x".repeat(WIZARD_NAME_MAX_LENGTH + 1),
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain(`${WIZARD_NAME_MAX_LENGTH}`);
  });

  test("blocks a description over the max length", () => {
    const result = validateServerWizardDetails({
      name: "ok",
      description: "x".repeat(WIZARD_DESCRIPTION_MAX_LENGTH + 1),
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain(`${WIZARD_DESCRIPTION_MAX_LENGTH}`);
  });

  test("accepts valid details", () => {
    const result = validateServerWizardDetails({
      name: "My Server",
      description: "fine",
    });
    expect(result.valid).toBe(true);
    expect(result.error).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Pagination envelope helpers
// ---------------------------------------------------------------------------
describe("pagination envelope helpers", () => {
  test("extractNextCursor reads the camelCase alias", () => {
    expect(extractNextCursor({ nextCursor: "abc" })).toBe("abc");
  });

  test("extractNextCursor reads the snake_case field", () => {
    expect(extractNextCursor({ next_cursor: "abc" })).toBe("abc");
  });

  test("extractNextCursor returns null when exhausted", () => {
    expect(extractNextCursor({ nextCursor: null })).toBeNull();
    expect(extractNextCursor(null)).toBeNull();
  });

  test("extractPageItems handles envelope and bare arrays", () => {
    expect(extractPageItems({ tools: [{ id: "t1" }] }, "tools")).toEqual([
      { id: "t1" },
    ]);
    expect(extractPageItems([{ id: "t1" }], "tools")).toEqual([{ id: "t1" }]);
    expect(extractPageItems({}, "tools")).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// fetchAllComponentIdsForGateway (cursor handling)
// ---------------------------------------------------------------------------
describe("fetchAllComponentIdsForGateway", () => {
  test("follows the cursor until exhausted and collects IDs", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({ tools: [{ id: "t1" }, { id: "t2" }], nextCursor: "c1" }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ tools: [{ id: "t3" }], nextCursor: null }),
      );

    const ids = await fetchAllComponentIdsForGateway("gw1", "tools", {
      fetchImpl,
      rootPath: "",
    });

    expect(ids).toEqual(["t1", "t2", "t3"]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    const firstUrl = fetchImpl.mock.calls[0][0];
    expect(firstUrl).toContain("/tools?");
    expect(firstUrl).toContain("gateway_id=gw1");
    expect(firstUrl).toContain("limit=100");
    expect(firstUrl).toContain("include_inactive=true");
    expect(firstUrl).toContain("include_pagination=true");
    expect(firstUrl).not.toContain("cursor=");

    const secondUrl = fetchImpl.mock.calls[1][0];
    expect(secondUrl).toContain("cursor=c1");
  });

  test("handles a single-page snake_case response", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(
        jsonResponse({ resources: [{ id: "r1" }], next_cursor: null }),
      );

    const ids = await fetchAllComponentIdsForGateway("gw1", "resources", {
      fetchImpl,
      rootPath: "",
    });

    expect(ids).toEqual(["r1"]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test("throws when a page request fails", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(jsonResponse({}, { ok: false, status: 500 }));

    await expect(
      fetchAllComponentIdsForGateway("gw1", "tools", {
        fetchImpl,
        rootPath: "",
      }),
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// aggregateGatewayComponentIds
// ---------------------------------------------------------------------------
describe("aggregateGatewayComponentIds", () => {
  test("aggregates every component for each selected gateway", async () => {
    const fetchImpl = vi.fn((url) => {
      if (url.includes("/tools")) {
        return Promise.resolve(
          jsonResponse({ tools: [{ id: "t1" }], nextCursor: null }),
        );
      }
      if (url.includes("/resources")) {
        return Promise.resolve(
          jsonResponse({ resources: [{ id: "r1" }], nextCursor: null }),
        );
      }
      return Promise.resolve(
        jsonResponse({ prompts: [{ id: "p1" }], nextCursor: null }),
      );
    });

    const result = await aggregateGatewayComponentIds(["gw1", "gw2"], {
      fetchImpl,
      rootPath: "",
    });

    // 2 gateways x 3 component endpoints
    expect(fetchImpl).toHaveBeenCalledTimes(6);
    expect(result).toEqual({
      tools: ["t1", "t1"],
      resources: ["r1", "r1"],
      prompts: ["p1", "p1"],
    });
  });
});

// ---------------------------------------------------------------------------
// unionIds / buildServerWizardPayload
// ---------------------------------------------------------------------------
describe("buildServerWizardPayload", () => {
  test("unionIds dedupes and drops empty values", () => {
    expect(unionIds(["a", "b"], ["b", "c"], [null, "", "a"])).toEqual([
      "a",
      "b",
      "c",
    ]);
  });

  test("unions gateway components with granular selections and dedupes", () => {
    const payload = buildServerWizardPayload({
      details: {
        name: "My Server",
        description: "desc",
        tags: "alpha, beta",
        visibility: "team",
      },
      gatewayComponents: {
        tools: ["t1", "t2"],
        resources: ["r1"],
        prompts: [],
      },
      granular: { tools: ["t2", "t3"], resources: [], prompts: ["p1"] },
      teamId: "team-1",
    });

    expect(payload.server.associated_tools).toEqual(["t1", "t2", "t3"]);
    expect(payload.server.associated_resources).toEqual(["r1"]);
    expect(payload.server.associated_prompts).toEqual(["p1"]);
    expect(payload.server.associated_a2a_agents).toEqual([]);
    expect(payload.server.tags).toEqual(["alpha", "beta"]);
    expect(payload.server.visibility).toBe("team");
    expect(payload.server.team_id).toBe("team-1");
    expect(payload.server.oauth_enabled).toBe(false);
    expect(payload.visibility).toBe("team");
    expect(payload.team_id).toBe("team-1");
  });

  test("skip flow produces empty associations", () => {
    const payload = buildServerWizardPayload({
      details: { name: "My Server", visibility: "public", tags: [] },
      gatewayComponents: { tools: ["t1"], resources: ["r1"], prompts: ["p1"] },
      granular: { tools: ["t2"], resources: [], prompts: [] },
      teamId: null,
      skip: true,
    });

    expect(payload.server.associated_tools).toEqual([]);
    expect(payload.server.associated_resources).toEqual([]);
    expect(payload.server.associated_prompts).toEqual([]);
    expect(payload.team_id).toBeNull();
  });

  test("assembles oauth_config when OAuth is enabled with an authorization server", () => {
    const payload = buildServerWizardPayload({
      details: {
        name: "My Server",
        visibility: "public",
        tags: [],
        oauthEnabled: true,
        oauthAuthorizationServer: "https://idp.example.com",
        oauthScopes: "openid profile",
        oauthTokenEndpoint: "https://idp.example.com/token",
      },
    });

    expect(payload.server.oauth_enabled).toBe(true);
    expect(payload.server.oauth_config).toEqual({
      authorization_servers: ["https://idp.example.com"],
      scopes_supported: ["openid", "profile"],
      token_endpoint: "https://idp.example.com/token",
    });
  });

  test("disables OAuth when enabled without an authorization server", () => {
    const payload = buildServerWizardPayload({
      details: {
        name: "My Server",
        visibility: "public",
        tags: [],
        oauthEnabled: true,
      },
    });

    expect(payload.server.oauth_enabled).toBe(false);
    expect(payload.server.oauth_config).toBeUndefined();
  });

  test("includes optional id and icon only when set", () => {
    const withOptionals = buildServerWizardPayload({
      details: {
        name: "My Server",
        visibility: "public",
        tags: [],
        id: " 550e8400-e29b-41d4-a716-446655440000 ",
        icon: " https://example.com/icon.png ",
      },
    });
    expect(withOptionals.server.id).toBe("550e8400-e29b-41d4-a716-446655440000");
    expect(withOptionals.server.icon).toBe("https://example.com/icon.png");

    const withoutOptionals = buildServerWizardPayload({
      details: { name: "My Server", visibility: "public", tags: [] },
    });
    expect("id" in withoutOptionals.server).toBe(false);
    expect("icon" in withoutOptionals.server).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// extractApiErrorMessage
// ---------------------------------------------------------------------------
describe("extractApiErrorMessage", () => {
  test("reads string detail", () => {
    expect(extractApiErrorMessage({ detail: "Name conflict" })).toBe(
      "Name conflict",
    );
  });

  test("reads validation detail arrays", () => {
    expect(
      extractApiErrorMessage({ detail: [{ msg: "bad name" }, { msg: "bad tag" }] }),
    ).toBe("bad name; bad tag");
  });

  test("reads message fallback", () => {
    expect(extractApiErrorMessage({ message: "Access issue" })).toBe(
      "Access issue",
    );
    expect(extractApiErrorMessage(null)).toBe("");
  });
});

// ---------------------------------------------------------------------------
// readSelectedWizardGatewayIds
// ---------------------------------------------------------------------------
describe("readSelectedWizardGatewayIds", () => {
  test("reads only checked gateway checkboxes", () => {
    setupWizardDom();
    expect(readSelectedWizardGatewayIds()).toEqual(["gw1"]);
  });

  test("returns empty when the container is absent", () => {
    expect(readSelectedWizardGatewayIds()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// serverWizardNext (step gating)
// ---------------------------------------------------------------------------
describe("serverWizardNext", () => {
  test("blocks advancing without a valid name and shows the error inline", () => {
    setupWizardDom();
    document.getElementById("server-wizard-name").value = "";

    serverWizardNext();

    const errorEl = document.getElementById("server-wizard-error");
    expect(errorEl.textContent).toBeTruthy();
    expect(errorEl.classList.contains("hidden")).toBe(false);
    expect(
      document.getElementById("server-wizard-step-2").classList.contains("hidden"),
    ).toBe(true);
  });

  test("advances to step 2 when details are valid", () => {
    setupWizardDom();
    // Step 2 has no gateways tbody, so no fetch fires on entry.
    serverWizardNext();

    expect(
      document.getElementById("server-wizard-step-2").classList.contains("hidden"),
    ).toBe(false);
    expect(
      document.getElementById("server-wizard-step-1").classList.contains("hidden"),
    ).toBe(true);
    expect(document.getElementById("server-wizard-error").textContent).toBe("");
  });
});

// ---------------------------------------------------------------------------
// serverWizardSubmit
// ---------------------------------------------------------------------------
describe("serverWizardSubmit", () => {
  test("aggregates selected gateway components and posts the embedded payload", async () => {
    setupWizardDom();
    const calls = [];
    const mockFetch = vi.fn((url, options) => {
      calls.push({ url, options });
      if (url.includes("/tools")) {
        return Promise.resolve(
          jsonResponse({ tools: [{ id: "t1" }], nextCursor: null }),
        );
      }
      if (url.includes("/resources")) {
        return Promise.resolve(
          jsonResponse({ resources: [], nextCursor: null }),
        );
      }
      if (url.includes("/prompts")) {
        return Promise.resolve(
          jsonResponse({ prompts: [{ id: "p1" }], nextCursor: null }),
        );
      }
      if (url === "/servers") {
        return Promise.resolve(jsonResponse({ id: "s1" }, { status: 201 }));
      }
      return Promise.reject(new Error(`Unexpected fetch: ${url}`));
    });
    vi.stubGlobal("fetch", mockFetch);

    await serverWizardSubmit(false);

    const post = calls.find((c) => c.url === "/servers");
    expect(post).toBeTruthy();
    expect(post.options.method).toBe("POST");
    const body = JSON.parse(post.options.body);
    expect(body.server.name).toBe("My Server");
    expect(body.server.description).toBe("A description");
    expect(body.server.tags).toEqual(["alpha", "beta"]);
    expect(body.server.associated_tools).toEqual(["t1"]);
    expect(body.server.associated_resources).toEqual([]);
    expect(body.server.associated_prompts).toEqual(["p1"]);
    expect(body.server.associated_a2a_agents).toEqual([]);
    expect(body.server.visibility).toBe("public");
    expect(body.server.team_id).toBeNull();
    expect(body.server.oauth_enabled).toBe(false);
    expect(body.visibility).toBe("public");
    expect(body.team_id).toBeNull();
    expect(post.options.headers["X-CSRF-Token"]).toBe("test-csrf");

    expect(showSuccessMessage).toHaveBeenCalled();
  });

  test("skip flow posts empty associations without component fetches", async () => {
    setupWizardDom();
    const calls = [];
    const mockFetch = vi.fn((url, options) => {
      calls.push({ url, options });
      if (url === "/servers") {
        return Promise.resolve(jsonResponse({ id: "s1" }, { status: 201 }));
      }
      return Promise.reject(new Error(`Unexpected fetch: ${url}`));
    });
    vi.stubGlobal("fetch", mockFetch);

    await serverWizardSubmit(true);

    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0].options.body);
    expect(body.server.associated_tools).toEqual([]);
    expect(body.server.associated_resources).toEqual([]);
    expect(body.server.associated_prompts).toEqual([]);
  });

  test("surfaces the API detail message inline on error", async () => {
    setupWizardDom();
    // Uncheck the gateway so no aggregation fetches are needed.
    document.querySelector('input[name="associatedGateways"]').checked = false;
    const mockFetch = vi.fn((url) => {
      if (url === "/servers") {
        return Promise.resolve(
          jsonResponse({ detail: "Server name already exists" }, { ok: false, status: 409 }),
        );
      }
      return Promise.reject(new Error(`Unexpected fetch: ${url}`));
    });
    vi.stubGlobal("fetch", mockFetch);

    await serverWizardSubmit(false);

    const errorEl = document.getElementById("server-wizard-error");
    expect(errorEl.textContent).toBe("Server name already exists");
    expect(errorEl.classList.contains("hidden")).toBe(false);
    expect(showSuccessMessage).not.toHaveBeenCalled();
  });
});
