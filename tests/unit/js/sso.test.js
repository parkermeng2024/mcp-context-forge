/**
 * Unit tests for sso.js module
 * Tests: list rendering, create payload assembly (trusted_domains split,
 *        JSON field parsing, api_audience validation), edit flow (GET populate
 *        + PUT omits empty secret), enable/disable toggle, delete confirm,
 *        approvals approve/reject, and the 404 -> disabled empty state.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  buildSsoProviderPayload,
  renderSsoProviders,
  renderSsoPendingApprovals,
  loadSsoPanel,
  loadSsoPendingApprovals,
  showSsoProviderCreateModal,
  showSsoProviderEditModal,
  handleSsoProviderSubmit,
  toggleSsoProvider,
  confirmDeleteSsoProvider,
  deleteSsoProvider,
  approveSsoUser,
  showSsoRejectModal,
  handleSsoRejectSubmit,
} from "../../../mcpgateway/admin_ui/sso.js";

import { openModal, closeModal } from "../../../mcpgateway/admin_ui/modals.js";
import {
  showErrorMessage,
  showSuccessMessage,
} from "../../../mcpgateway/admin_ui/utils.js";

// Mock dependencies
vi.mock("../../../mcpgateway/admin_ui/auth.js", () => ({
  getAuthHeaders: vi.fn(async () => ({ Authorization: "Bearer test-token" })),
}));
vi.mock("../../../mcpgateway/admin_ui/modals.js", () => ({
  openModal: vi.fn(),
  closeModal: vi.fn(),
}));
vi.mock("../../../mcpgateway/admin_ui/security.js", () => ({
  escapeHtml: vi.fn((s) => (s != null ? String(s) : "")),
  escapeAttrValue: vi.fn((s) => (s != null ? String(s) : "")),
}));
vi.mock("../../../mcpgateway/admin_ui/utils.js", () => ({
  safeGetElement: vi.fn((id) => document.getElementById(id)),
  showErrorMessage: vi.fn(),
  showSuccessMessage: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const PROVIDER_SUMMARY = {
  id: "corp-okta",
  name: "corp-okta",
  display_name: "Corporate Okta",
  provider_type: "oidc",
  is_enabled: true,
  trusted_domains: ["example.com"],
  auto_create_users: true,
  trusted_for_api_auth: false,
  api_audience: null,
};

const PROVIDER_DETAIL = {
  ...PROVIDER_SUMMARY,
  client_id: "client-123",
  authorization_url: "https://idp.example.com/authorize",
  token_url: "https://idp.example.com/token",
  userinfo_url: "https://idp.example.com/userinfo",
  issuer: "https://idp.example.com",
  jwks_uri: "https://idp.example.com/.well-known/jwks.json",
  scope: "openid profile email",
  team_mapping: { "IdP Admins": "platform-admins" },
  provider_metadata: { groups_claim: "groups" },
};

const PENDING_APPROVAL = {
  id: "approval-1",
  email: "new.user@example.com",
  full_name: "New User",
  auth_provider: "corp-okta",
  requested_at: "2026-09-30T10:00:00",
  expires_at: "2026-10-07T10:00:00",
  status: "pending",
  sso_metadata: null,
};

const mockResponse = (data, { ok = true, status = 200 } = {}) => ({
  ok,
  status,
  json: vi.fn(async () => data),
});

const buildPanelDom = () => {
  document.body.innerHTML = `
    <div id="sso-content"></div>
    <div id="sso-disabled-state" class="hidden"></div>
    <div id="sso-providers-list"></div>
    <div id="sso-pending-approvals-list"></div>
    <div id="sso-delete-message"></div>
    <div id="sso-reject-email"></div>
    <div id="sso-reject-form-error" class="hidden"></div>
    <form id="sso-reject-form">
      <textarea name="reason"></textarea>
      <textarea name="notes"></textarea>
    </form>
  `;
};

const buildProviderFormDom = () => {
  document.body.innerHTML = `
    <h3 id="sso-provider-modal-title"></h3>
    <div id="sso-provider-form-error" class="hidden"></div>
    <form id="sso-provider-form">
      <input name="id" />
      <input name="name" />
      <input name="display_name" />
      <select name="provider_type">
        <option value="oidc">oidc</option>
        <option value="oauth2">oauth2</option>
      </select>
      <input name="client_id" />
      <input name="client_secret" />
      <input name="authorization_url" />
      <input name="token_url" />
      <input name="userinfo_url" />
      <input name="issuer" />
      <input name="jwks_uri" />
      <input name="scope" />
      <input name="trusted_domains" />
      <input type="checkbox" name="auto_create_users" />
      <textarea name="team_mapping"></textarea>
      <textarea name="provider_metadata"></textarea>
      <input type="checkbox" name="trusted_for_api_auth" />
      <input name="api_audience" />
    </form>
  `;
  return document.getElementById("sso-provider-form");
};

const fillProviderForm = (form, overrides = {}) => {
  const values = {
    id: "corp-okta",
    name: "corp-okta",
    display_name: "Corporate Okta",
    provider_type: "oidc",
    client_id: "client-123",
    client_secret: "super-secret",
    authorization_url: "https://idp.example.com/authorize",
    token_url: "https://idp.example.com/token",
    userinfo_url: "https://idp.example.com/userinfo",
    issuer: "",
    jwks_uri: "",
    scope: "openid profile email",
    trusted_domains: "example.com, subsidiary.example",
    team_mapping: '{"IdP Admins": "platform-admins"}',
    provider_metadata: '{"groups_claim": "groups"}',
    api_audience: "",
    ...overrides,
  };
  for (const [name, value] of Object.entries(values)) {
    if (form.elements[name]) {
      form.elements[name].value = value;
    }
  }
};

/**
 * Router-style fetch mock: resolves based on URL substring and method.
 */
const stubFetchRouter = (routes) => {
  const fetchMock = vi.fn(async (url, options = {}) => {
    const method = options.method || "GET";
    for (const route of routes) {
      if (
        url.includes(route.match) &&
        (!route.method || route.method === method)
      ) {
        return route.response;
      }
    }
    throw new Error(`Unexpected fetch: ${method} ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
};

beforeEach(() => {
  vi.clearAllMocks();
  window.ROOT_PATH = "";
});

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

// ---------------------------------------------------------------------------
// renderSsoProviders
// ---------------------------------------------------------------------------
describe("renderSsoProviders", () => {
  beforeEach(buildPanelDom);

  test("renders a table row per provider with row actions", () => {
    renderSsoProviders([
      PROVIDER_SUMMARY,
      { ...PROVIDER_SUMMARY, id: "gh", name: "github", display_name: "GitHub", provider_type: "oauth2", is_enabled: false },
    ]);

    const table = document.getElementById("sso-providers-table");
    expect(table).not.toBeNull();
    const html = table.innerHTML;
    expect(html).toContain("Corporate Okta");
    expect(html).toContain("corp-okta");
    expect(html).toContain("oidc");
    expect(html).toContain("GitHub");
    expect(html).toContain("oauth2");
    expect(html).toContain("Enabled");
    expect(html).toContain("Disabled");

    const editButtons = table.querySelectorAll('[data-action-click="showSsoProviderEditModal"]');
    expect(editButtons).toHaveLength(2);
    expect(editButtons[0].dataset.arg0).toBe("corp-okta");

    const toggleButtons = table.querySelectorAll('[data-action-click="toggleSsoProvider"]');
    expect(toggleButtons[0].dataset.arg1).toBe("true");
    expect(toggleButtons[1].dataset.arg1).toBe("false");

    const deleteButtons = table.querySelectorAll('[data-action-click="confirmDeleteSsoProvider"]');
    expect(deleteButtons[0].dataset.arg0).toBe("corp-okta");
    expect(deleteButtons[0].dataset.arg1).toBe("Corporate Okta");
  });

  test("renders an empty state when no providers exist", () => {
    renderSsoProviders([]);
    expect(document.getElementById("sso-providers-list").textContent).toContain("No SSO providers configured.");
  });
});

// ---------------------------------------------------------------------------
// renderSsoPendingApprovals
// ---------------------------------------------------------------------------
describe("renderSsoPendingApprovals", () => {
  beforeEach(buildPanelDom);

  test("renders pending users with approve/reject actions", () => {
    renderSsoPendingApprovals([PENDING_APPROVAL]);

    const table = document.getElementById("sso-approvals-table");
    expect(table).not.toBeNull();
    expect(table.innerHTML).toContain("new.user@example.com");
    expect(table.innerHTML).toContain("New User");
    expect(table.innerHTML).toContain("corp-okta");

    const approveBtn = table.querySelector('[data-action-click="approveSsoUser"]');
    expect(approveBtn.dataset.arg0).toBe("approval-1");

    const rejectBtn = table.querySelector('[data-action-click="showSsoRejectModal"]');
    expect(rejectBtn.dataset.arg0).toBe("approval-1");
    expect(rejectBtn.dataset.arg1).toBe("new.user@example.com");
  });

  test("renders an empty state when no approvals are pending", () => {
    renderSsoPendingApprovals([]);
    expect(document.getElementById("sso-pending-approvals-list").textContent).toContain("No pending SSO user approvals.");
  });
});

// ---------------------------------------------------------------------------
// loadSsoPanel
// ---------------------------------------------------------------------------
describe("loadSsoPanel", () => {
  beforeEach(buildPanelDom);

  test("renders providers and approvals from the API", async () => {
    const fetchMock = stubFetchRouter([
      { match: "/auth/sso/admin/providers", response: mockResponse([PROVIDER_SUMMARY]) },
      { match: "/auth/sso/pending-approvals", response: mockResponse([PENDING_APPROVAL]) },
    ]);

    await loadSsoPanel();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(document.getElementById("sso-providers-table")).not.toBeNull();
    expect(document.getElementById("sso-approvals-table")).not.toBeNull();
  });

  test("shows the disabled empty state when the API 404s (SSO disabled)", async () => {
    stubFetchRouter([
      { match: "/auth/sso/admin/providers", response: mockResponse({}, { ok: false, status: 404 }) },
    ]);

    await loadSsoPanel();

    const disabledState = document.getElementById("sso-disabled-state");
    const content = document.getElementById("sso-content");
    expect(disabledState.classList.contains("hidden")).toBe(false);
    expect(content.classList.contains("hidden")).toBe(true);
  });

  test("renders an error message when the providers request fails", async () => {
    stubFetchRouter([
      { match: "/auth/sso/admin/providers", response: mockResponse({}, { ok: false, status: 500 }) },
    ]);

    await loadSsoPanel();

    expect(document.getElementById("sso-providers-list").textContent).toContain("Failed to load SSO providers.");
  });
});

// ---------------------------------------------------------------------------
// loadSsoPendingApprovals
// ---------------------------------------------------------------------------
describe("loadSsoPendingApprovals", () => {
  beforeEach(buildPanelDom);

  test("renders an error message when the request fails", async () => {
    stubFetchRouter([
      { match: "/auth/sso/pending-approvals", response: mockResponse({}, { ok: false, status: 500 }) },
    ]);

    await loadSsoPendingApprovals();

    expect(document.getElementById("sso-pending-approvals-list").textContent).toContain("Failed to load pending approvals.");
  });
});

// ---------------------------------------------------------------------------
// buildSsoProviderPayload
// ---------------------------------------------------------------------------
describe("buildSsoProviderPayload", () => {
  test("assembles the create payload: splits domains, parses JSON fields, omits empty optionals", () => {
    const form = buildProviderFormDom();
    fillProviderForm(form);

    const { payload, errors } = buildSsoProviderPayload(form, { isEdit: false });

    expect(errors).toBeUndefined();
    expect(payload).toEqual({
      id: "corp-okta",
      name: "corp-okta",
      display_name: "Corporate Okta",
      provider_type: "oidc",
      client_id: "client-123",
      client_secret: "super-secret",
      authorization_url: "https://idp.example.com/authorize",
      token_url: "https://idp.example.com/token",
      userinfo_url: "https://idp.example.com/userinfo",
      scope: "openid profile email",
      trusted_domains: ["example.com", "subsidiary.example"],
      auto_create_users: false,
      team_mapping: { "IdP Admins": "platform-admins" },
      provider_metadata: { groups_claim: "groups" },
      trusted_for_api_auth: false,
      issuer: undefined,
      jwks_uri: undefined,
      api_audience: undefined,
    });
    expect(payload).not.toHaveProperty("issuer");
    expect(payload).not.toHaveProperty("jwks_uri");
    expect(payload).not.toHaveProperty("api_audience");
  });

  test("create payload sends empty collections and omits scope when blank", () => {
    const form = buildProviderFormDom();
    fillProviderForm(form, {
      trusted_domains: "",
      team_mapping: "",
      provider_metadata: "",
      scope: "",
    });

    const { payload, errors } = buildSsoProviderPayload(form, { isEdit: false });

    expect(errors).toBeUndefined();
    expect(payload.trusted_domains).toEqual([]);
    expect(payload.team_mapping).toEqual({});
    expect(payload.provider_metadata).toEqual({});
    expect(payload).not.toHaveProperty("scope");
  });

  test("blocks submit when trusted_for_api_auth is checked without api_audience", () => {
    const form = buildProviderFormDom();
    fillProviderForm(form, { api_audience: "" });
    form.elements.trusted_for_api_auth.checked = true;

    const { payload, errors } = buildSsoProviderPayload(form, { isEdit: false });

    expect(payload).toBeUndefined();
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("API Audience is required");
  });

  test("accepts trusted_for_api_auth when api_audience is provided", () => {
    const form = buildProviderFormDom();
    fillProviderForm(form, { api_audience: "mcp-gateway" });
    form.elements.trusted_for_api_auth.checked = true;

    const { payload, errors } = buildSsoProviderPayload(form, { isEdit: false });

    expect(errors).toBeUndefined();
    expect(payload.trusted_for_api_auth).toBe(true);
    expect(payload.api_audience).toBe("mcp-gateway");
  });

  test("rejects invalid JSON in team_mapping and provider_metadata", () => {
    const form = buildProviderFormDom();
    fillProviderForm(form, {
      team_mapping: "{not json",
      provider_metadata: '["an", "array"]',
    });

    const { payload, errors } = buildSsoProviderPayload(form, { isEdit: false });

    expect(payload).toBeUndefined();
    expect(errors).toHaveLength(2);
  });

  test("edit payload omits a blank client_secret and keeps empty strings to clear fields", () => {
    const form = buildProviderFormDom();
    fillProviderForm(form, { client_secret: "", issuer: "", trusted_domains: "" });

    const { payload, errors } = buildSsoProviderPayload(form, { isEdit: true });

    expect(errors).toBeUndefined();
    expect(payload).not.toHaveProperty("client_secret");
    expect(payload).not.toHaveProperty("id");
    expect(payload.issuer).toBe("");
    expect(payload.trusted_domains).toEqual([]);
  });

  test("edit payload includes client_secret when a new one is typed", () => {
    const form = buildProviderFormDom();
    fillProviderForm(form, { client_secret: "rotated-secret" });

    const { payload, errors } = buildSsoProviderPayload(form, { isEdit: true });

    expect(errors).toBeUndefined();
    expect(payload.client_secret).toBe("rotated-secret");
  });
});

// ---------------------------------------------------------------------------
// showSsoProviderCreateModal
// ---------------------------------------------------------------------------
describe("showSsoProviderCreateModal", () => {
  test("resets the form, enables id, requires secret, and opens the modal", () => {
    const form = buildProviderFormDom();
    form.elements.id.disabled = true;
    form.elements.client_secret.required = false;

    showSsoProviderCreateModal();

    expect(document.getElementById("sso-provider-modal-title").textContent).toBe("Add SSO Provider");
    expect(form.elements.id.disabled).toBe(false);
    expect(form.elements.client_secret.required).toBe(true);
    expect(openModal).toHaveBeenCalledWith("sso-provider-modal");
  });
});

// ---------------------------------------------------------------------------
// Edit flow: GET populate + PUT
// ---------------------------------------------------------------------------
describe("showSsoProviderEditModal + handleSsoProviderSubmit (edit)", () => {
  test("GETs the provider detail and populates the form", async () => {
    const form = buildProviderFormDom();
    buildPanelDomIntoDocument();

    const fetchMock = stubFetchRouter([
      { match: "/auth/sso/admin/providers/corp-okta", method: "GET", response: mockResponse(PROVIDER_DETAIL) },
    ]);

    await showSsoProviderEditModal("corp-okta");

    expect(fetchMock).toHaveBeenCalledWith(
      "/auth/sso/admin/providers/corp-okta",
      expect.objectContaining({ method: "GET" })
    );
    expect(document.getElementById("sso-provider-modal-title").textContent).toBe("Edit SSO Provider");
    expect(form.elements.id.value).toBe("corp-okta");
    expect(form.elements.id.disabled).toBe(true);
    expect(form.elements.client_id.value).toBe("client-123");
    expect(form.elements.trusted_domains.value).toBe("example.com");
    expect(form.elements.team_mapping.value).toContain("platform-admins");
    expect(form.elements.provider_metadata.value).toContain("groups_claim");
    expect(form.elements.auto_create_users.checked).toBe(true);
    expect(form.elements.trusted_for_api_auth.checked).toBe(false);
    expect(form.elements.client_secret.value).toBe("");
    expect(form.elements.client_secret.required).toBe(false);
    expect(form.elements.client_secret.placeholder).toBe("leave blank to keep current");
    expect(openModal).toHaveBeenCalledWith("sso-provider-modal");
  });

  test("PUTs the update without client_secret when left blank, then reloads", async () => {
    const form = buildProviderFormDom();
    buildPanelDomIntoDocument();

    const fetchMock = stubFetchRouter([
      { match: "/auth/sso/admin/providers/corp-okta", method: "GET", response: mockResponse(PROVIDER_DETAIL) },
      { match: "/auth/sso/admin/providers/corp-okta", method: "PUT", response: mockResponse(PROVIDER_SUMMARY) },
      { match: "/auth/sso/admin/providers", method: "GET", response: mockResponse([PROVIDER_SUMMARY]) },
      { match: "/auth/sso/pending-approvals", response: mockResponse([]) },
    ]);

    await showSsoProviderEditModal("corp-okta");
    await handleSsoProviderSubmit({ target: form });

    const putCall = fetchMock.mock.calls.find(
      ([url, options]) => url.includes("/admin/providers/corp-okta") && options.method === "PUT"
    );
    expect(putCall).toBeDefined();
    const body = JSON.parse(putCall[1].body);
    expect(body).not.toHaveProperty("client_secret");
    expect(body.display_name).toBe("Corporate Okta");
    expect(closeModal).toHaveBeenCalledWith("sso-provider-modal");
    expect(showSuccessMessage).toHaveBeenCalled();
  });
});

/**
 * The edit-flow tests need the panel containers alongside the form because a
 * successful submit triggers loadSsoPanel().
 */
const buildPanelDomIntoDocument = () => {
  document.body.insertAdjacentHTML(
    "beforeend",
    `
    <div id="sso-content"></div>
    <div id="sso-disabled-state" class="hidden"></div>
    <div id="sso-providers-list"></div>
    <div id="sso-pending-approvals-list"></div>
  `
  );
};

// ---------------------------------------------------------------------------
// handleSsoProviderSubmit (create)
// ---------------------------------------------------------------------------
describe("handleSsoProviderSubmit (create)", () => {
  test("POSTs the assembled payload", async () => {
    const form = buildProviderFormDom();
    buildPanelDomIntoDocument();
    showSsoProviderCreateModal();
    fillProviderForm(form);

    const fetchMock = stubFetchRouter([
      { match: "/auth/sso/admin/providers", method: "POST", response: mockResponse(PROVIDER_SUMMARY) },
      { match: "/auth/sso/admin/providers", method: "GET", response: mockResponse([PROVIDER_SUMMARY]) },
      { match: "/auth/sso/pending-approvals", response: mockResponse([]) },
    ]);

    await handleSsoProviderSubmit({ target: form });

    const postCall = fetchMock.mock.calls.find(([, options]) => options.method === "POST");
    expect(postCall).toBeDefined();
    expect(postCall[0]).toBe("/auth/sso/admin/providers");
    const body = JSON.parse(postCall[1].body);
    expect(body.id).toBe("corp-okta");
    expect(body.client_secret).toBe("super-secret");
    expect(body.trusted_domains).toEqual(["example.com", "subsidiary.example"]);
    expect(closeModal).toHaveBeenCalledWith("sso-provider-modal");
  });

  test("shows validation errors and does not fetch when the payload is invalid", async () => {
    const form = buildProviderFormDom();
    showSsoProviderCreateModal();
    fillProviderForm(form, { team_mapping: "{broken" });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await handleSsoProviderSubmit({ target: form });

    expect(fetchMock).not.toHaveBeenCalled();
    const errorBox = document.getElementById("sso-provider-form-error");
    expect(errorBox.classList.contains("hidden")).toBe(false);
    expect(errorBox.textContent).toContain("must be a valid JSON object");
  });
});

// ---------------------------------------------------------------------------
// toggleSsoProvider
// ---------------------------------------------------------------------------
describe("toggleSsoProvider", () => {
  test("PUTs the flipped is_enabled flag", async () => {
    buildPanelDom();
    const fetchMock = stubFetchRouter([
      { match: "/auth/sso/admin/providers/corp-okta", method: "PUT", response: mockResponse(PROVIDER_SUMMARY) },
      { match: "/auth/sso/admin/providers", method: "GET", response: mockResponse([PROVIDER_SUMMARY]) },
      { match: "/auth/sso/pending-approvals", response: mockResponse([]) },
    ]);

    await toggleSsoProvider("corp-okta", true);

    const putCall = fetchMock.mock.calls.find(([, options]) => options.method === "PUT");
    expect(putCall[0]).toBe("/auth/sso/admin/providers/corp-okta");
    expect(JSON.parse(putCall[1].body)).toEqual({ is_enabled: false });
  });

  test("shows an error message when the toggle fails", async () => {
    buildPanelDom();
    stubFetchRouter([
      { match: "/auth/sso/admin/providers/corp-okta", method: "PUT", response: mockResponse({ detail: "nope" }, { ok: false, status: 400 }) },
    ]);

    await toggleSsoProvider("corp-okta", true);

    expect(showErrorMessage).toHaveBeenCalledWith("nope");
  });
});

// ---------------------------------------------------------------------------
// Delete flow
// ---------------------------------------------------------------------------
describe("confirmDeleteSsoProvider + deleteSsoProvider", () => {
  test("opens the confirm modal with the provider name", () => {
    buildPanelDom();

    confirmDeleteSsoProvider("corp-okta", "Corporate Okta");

    expect(document.getElementById("sso-delete-message").textContent).toContain("Corporate Okta");
    expect(openModal).toHaveBeenCalledWith("sso-provider-delete-modal");
  });

  test("DELETEs the provider and reloads on confirm", async () => {
    buildPanelDom();
    const fetchMock = stubFetchRouter([
      { match: "/auth/sso/admin/providers/corp-okta", method: "DELETE", response: mockResponse({ message: "deleted" }) },
      { match: "/auth/sso/admin/providers", method: "GET", response: mockResponse([]) },
      { match: "/auth/sso/pending-approvals", response: mockResponse([]) },
    ]);

    confirmDeleteSsoProvider("corp-okta", "Corporate Okta");
    await deleteSsoProvider();

    const deleteCall = fetchMock.mock.calls.find(([, options]) => options.method === "DELETE");
    expect(deleteCall[0]).toBe("/auth/sso/admin/providers/corp-okta");
    expect(closeModal).toHaveBeenCalledWith("sso-provider-delete-modal");
    expect(showSuccessMessage).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Approvals: approve / reject
// ---------------------------------------------------------------------------
describe("approveSsoUser", () => {
  test("POSTs the approve action and reloads approvals", async () => {
    buildPanelDom();
    const fetchMock = stubFetchRouter([
      { match: "/auth/sso/pending-approvals/approval-1/action", method: "POST", response: mockResponse({ message: "ok" }) },
      { match: "/auth/sso/pending-approvals", method: "GET", response: mockResponse([]) },
    ]);

    await approveSsoUser("approval-1");

    const postCall = fetchMock.mock.calls.find(([, options]) => options.method === "POST");
    expect(postCall[0]).toBe("/auth/sso/pending-approvals/approval-1/action");
    expect(JSON.parse(postCall[1].body)).toEqual({ action: "approve" });
    expect(showSuccessMessage).toHaveBeenCalled();
  });
});

describe("showSsoRejectModal + handleSsoRejectSubmit", () => {
  test("opens the reject modal with the user email", () => {
    buildPanelDom();

    showSsoRejectModal("approval-1", "new.user@example.com");

    expect(document.getElementById("sso-reject-email").textContent).toBe("new.user@example.com");
    expect(openModal).toHaveBeenCalledWith("sso-reject-modal");
  });

  test("blocks submit without a reason", async () => {
    buildPanelDom();
    showSsoRejectModal("approval-1", "new.user@example.com");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await handleSsoRejectSubmit({ target: document.getElementById("sso-reject-form") });

    expect(fetchMock).not.toHaveBeenCalled();
    const errorBox = document.getElementById("sso-reject-form-error");
    expect(errorBox.classList.contains("hidden")).toBe(false);
    expect(errorBox.textContent).toContain("rejection reason is required");
  });

  test("POSTs the reject action with reason and notes", async () => {
    buildPanelDom();
    showSsoRejectModal("approval-1", "new.user@example.com");
    const form = document.getElementById("sso-reject-form");
    form.elements.reason.value = "Not an employee";
    form.elements.notes.value = "Asked to use the contractor flow";

    const fetchMock = stubFetchRouter([
      { match: "/auth/sso/pending-approvals/approval-1/action", method: "POST", response: mockResponse({ message: "ok" }) },
      { match: "/auth/sso/pending-approvals", method: "GET", response: mockResponse([]) },
    ]);

    await handleSsoRejectSubmit({ target: form });

    const postCall = fetchMock.mock.calls.find(([, options]) => options.method === "POST");
    expect(JSON.parse(postCall[1].body)).toEqual({
      action: "reject",
      reason: "Not an employee",
      notes: "Asked to use the contractor flow",
    });
    expect(closeModal).toHaveBeenCalledWith("sso-reject-modal");
    expect(showSuccessMessage).toHaveBeenCalled();
  });
});
