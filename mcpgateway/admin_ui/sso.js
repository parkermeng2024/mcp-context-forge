// ===================================================================
// SSO PROVIDER MANAGEMENT
// Client-rendered SSO tab: provider CRUD plus pending user approvals.
// Backed by the JSON API under {ROOT_PATH}/auth/sso. The API only exists
// when SSO_ENABLED=true, so a 404 renders an informative disabled state.
// ===================================================================

import { getAuthHeaders } from "./auth.js";
import { openModal, closeModal } from "./modals.js";
import { escapeHtml, escapeAttrValue } from "./security.js";
import { safeGetElement, showErrorMessage, showSuccessMessage } from "./utils.js";
import { t } from "./i18n.js";

// Module-local UI state for the provider form, delete confirm, and reject modal.
const ssoState = {
  formMode: "create",
  editingProviderId: null,
  pendingDeleteProviderId: null,
  pendingRejectApprovalId: null,
};

/**
 * Base URL for the SSO admin API.
 * @returns {string} Absolute path prefix for SSO endpoints
 */
const ssoApiBase = function () {
  return `${window.ROOT_PATH || ""}/auth/sso`;
};

/**
 * Best-effort extraction of FastAPI's {"detail": ...} error body.
 * @param {Response} response - Failed fetch response
 * @param {string} fallback - Message used when no detail is available
 * @returns {Promise<string>} Human-readable error message
 */
const readErrorDetail = async function (response, fallback) {
  try {
    const data = await response.json();
    if (data && typeof data.detail === "string" && data.detail) {
      return data.detail;
    }
  } catch (error) {
    console.debug("SSO error response was not JSON:", error);
  }
  return fallback;
};

/**
 * Reveal the provider form error box with a message.
 * @param {string} message - Error text to display
 */
const showSsoFormError = function (message) {
  const errorBox = safeGetElement("sso-provider-form-error");
  if (errorBox) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
  }
};

/**
 * Hide the provider form error box.
 */
const clearSsoFormError = function () {
  const errorBox = safeGetElement("sso-provider-form-error");
  if (errorBox) {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
  }
};

/**
 * Show the "SSO is disabled" empty state and hide the management content.
 */
const showSsoDisabledState = function () {
  const content = safeGetElement("sso-content");
  const disabledState = safeGetElement("sso-disabled-state");
  if (content) {
    content.classList.add("hidden");
  }
  if (disabledState) {
    disabledState.classList.remove("hidden");
  }
};

/**
 * Assemble the create/update payload from the provider form.
 * trusted_domains is split on commas; team_mapping and provider_metadata are
 * parsed as JSON objects; api_audience is required when trusted_for_api_auth
 * is checked. On edit, a blank client_secret is omitted so the server keeps
 * the stored secret.
 * @param {HTMLFormElement} form - The provider form element
 * @param {Object} options - Options
 * @param {boolean} options.isEdit - True when updating an existing provider
 * @returns {{payload?: Object, errors?: string[]}} Payload or validation errors
 */
export const buildSsoProviderPayload = function (form, { isEdit = false } = {}) {
  const getValue = function (name) {
    const field = form.elements[name];
    return field ? String(field.value ?? "").trim() : "";
  };
  const getChecked = function (name) {
    const field = form.elements[name];
    return Boolean(field && field.checked);
  };

  const errors = [];
  const parseJsonObject = function (name, labelKey) {
    const raw = getValue(name);
    if (!raw) {
      return {};
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        errors.push(t("sso.form.invalidJson", { field: t(labelKey) }));
        return undefined;
      }
      return parsed;
    } catch {
      errors.push(t("sso.form.invalidJson", { field: t(labelKey) }));
      return undefined;
    }
  };

  const trustedDomains = getValue("trusted_domains")
    .split(",")
    .map((domain) => domain.trim())
    .filter((domain) => domain.length > 0);

  const teamMapping = parseJsonObject("team_mapping", "sso.form.teamMapping");
  const providerMetadata = parseJsonObject("provider_metadata", "sso.form.providerMetadata");

  const trustedForApiAuth = getChecked("trusted_for_api_auth");
  const apiAudience = getValue("api_audience");
  if (trustedForApiAuth && !apiAudience) {
    errors.push(t("sso.form.apiAudienceRequired"));
  }

  if (errors.length > 0) {
    return { errors };
  }

  const payload = {
    name: getValue("name"),
    display_name: getValue("display_name"),
    provider_type: getValue("provider_type"),
    client_id: getValue("client_id"),
    authorization_url: getValue("authorization_url"),
    token_url: getValue("token_url"),
    userinfo_url: getValue("userinfo_url"),
    issuer: getValue("issuer"),
    jwks_uri: getValue("jwks_uri"),
    scope: getValue("scope"),
    trusted_domains: trustedDomains,
    auto_create_users: getChecked("auto_create_users"),
    team_mapping: teamMapping,
    provider_metadata: providerMetadata,
    trusted_for_api_auth: trustedForApiAuth,
    api_audience: apiAudience,
  };

  const clientSecret = getValue("client_secret");
  if (isEdit) {
    // PUT drops null fields server-side: send "" to clear strings, []/{} for
    // empty collections, and omit client_secret unless a new one was typed.
    if (clientSecret) {
      payload.client_secret = clientSecret;
    }
  } else {
    payload.id = getValue("id");
    payload.client_secret = clientSecret;
    // Let server defaults apply for untouched optional fields on create.
    for (const key of ["issuer", "jwks_uri", "scope", "api_audience"]) {
      if (!payload[key]) {
        delete payload[key];
      }
    }
  }

  return { payload };
};

/**
 * Render the providers table into #sso-providers-list.
 * @param {Array<Object>} providers - Provider summaries from the API
 */
export const renderSsoProviders = function (providers) {
  const container = safeGetElement("sso-providers-list");
  if (!container) {
    return;
  }

  if (!Array.isArray(providers) || providers.length === 0) {
    container.innerHTML = `
      <div class="text-center py-8">
        <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
        <p class="mt-2 text-sm text-gray-500 dark:text-gray-400">${t("sso.providers.empty")}</p>
        <p class="mt-1 text-xs text-gray-400 dark:text-gray-500">${t("sso.providers.emptyHint")}</p>
      </div>`;
    return;
  }

  const rows = providers
    .map((provider) => {
      const enabled = Boolean(provider.is_enabled);
      const statusBadge = enabled
        ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">${t("sso.status.enabled")}</span>`
        : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">${t("sso.status.disabled")}</span>`;
      const providerId = escapeAttrValue(String(provider.id ?? ""));
      const providerName = escapeAttrValue(String(provider.display_name || provider.name || ""));
      return `
        <tr>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">${escapeHtml(provider.display_name)}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">${escapeHtml(provider.name)}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">${escapeHtml(provider.provider_type)}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm">${statusBadge}</td>
          <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
            <button type="button" class="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 mr-3" data-action-click="showSsoProviderEditModal" data-arg0="${providerId}">${t("common.actions.edit")}</button>
            <button type="button" class="text-yellow-600 hover:text-yellow-900 dark:text-yellow-400 dark:hover:text-yellow-300 mr-3" data-action-click="toggleSsoProvider" data-arg0="${providerId}" data-arg1="${enabled}">${enabled ? t("sso.actions.disable") : t("sso.actions.enable")}</button>
            <button type="button" class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300" data-action-click="confirmDeleteSsoProvider" data-arg0="${providerId}" data-arg1="${providerName}">${t("common.actions.delete")}</button>
          </td>
        </tr>`;
    })
    .join("");

  container.innerHTML = `
    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700" id="sso-providers-table">
        <thead class="bg-gray-50 dark:bg-gray-900">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("sso.table.displayName")}</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("common.table.name")}</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("sso.table.type")}</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("common.table.status")}</th>
            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("common.table.actions")}</th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200 dark:bg-gray-800 dark:divide-gray-700">
          ${rows}
        </tbody>
      </table>
    </div>`;
};

/**
 * Render the pending approvals table into #sso-pending-approvals-list.
 * @param {Array<Object>} approvals - Pending approval records from the API
 */
export const renderSsoPendingApprovals = function (approvals) {
  const container = safeGetElement("sso-pending-approvals-list");
  if (!container) {
    return;
  }

  if (!Array.isArray(approvals) || approvals.length === 0) {
    container.innerHTML = `
      <div class="text-center py-8">
        <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p class="mt-2 text-sm text-gray-500 dark:text-gray-400">${t("sso.approvals.empty")}</p>
        <p class="mt-1 text-xs text-gray-400 dark:text-gray-500">${t("sso.approvals.emptyHint")}</p>
      </div>`;
    return;
  }

  const rows = approvals
    .map((approval) => {
      const approvalId = escapeAttrValue(String(approval.id ?? ""));
      const approvalEmail = escapeAttrValue(String(approval.email ?? ""));
      return `
        <tr>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">${escapeHtml(approval.email)}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">${escapeHtml(approval.full_name)}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">${escapeHtml(approval.auth_provider)}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">${escapeHtml(approval.requested_at)}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">${escapeHtml(approval.expires_at)}</td>
          <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
            <button type="button" class="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300 mr-3" data-action-click="approveSsoUser" data-arg0="${approvalId}">${t("sso.actions.approve")}</button>
            <button type="button" class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300" data-action-click="showSsoRejectModal" data-arg0="${approvalId}" data-arg1="${approvalEmail}">${t("sso.actions.reject")}</button>
          </td>
        </tr>`;
    })
    .join("");

  container.innerHTML = `
    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700" id="sso-approvals-table">
        <thead class="bg-gray-50 dark:bg-gray-900">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("sso.approvals.email")}</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("sso.approvals.fullName")}</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("sso.approvals.provider")}</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("sso.approvals.requestedAt")}</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("sso.approvals.expiresAt")}</th>
            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">${t("common.table.actions")}</th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200 dark:bg-gray-800 dark:divide-gray-700">
          ${rows}
        </tbody>
      </table>
    </div>`;
};

/**
 * Fetch and render the pending SSO user approvals.
 */
export const loadSsoPendingApprovals = async function () {
  const container = safeGetElement("sso-pending-approvals-list");
  if (!container) {
    return;
  }
  try {
    const headers = await getAuthHeaders();
    const response = await fetch(`${ssoApiBase()}/pending-approvals`, {
      method: "GET",
      headers,
      credentials: "same-origin", // pragma: allowlist secret
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const approvals = await response.json();
    renderSsoPendingApprovals(approvals);
  } catch (error) {
    console.error("Failed to load SSO pending approvals:", error);
    container.innerHTML = `<div class="text-center py-4 text-red-600 dark:text-red-400">${t("sso.approvals.loadFailed")}</div>`;
  }
};

/**
 * Fetch and render the SSO providers list, then the pending approvals.
 * A 404 means the SSO feature is disabled: render the informative empty state.
 */
export const loadSsoPanel = async function () {
  const listContainer = safeGetElement("sso-providers-list");
  if (!listContainer) {
    return;
  }

  const content = safeGetElement("sso-content");
  const disabledState = safeGetElement("sso-disabled-state");
  if (content) {
    content.classList.remove("hidden");
  }
  if (disabledState) {
    disabledState.classList.add("hidden");
  }
  listContainer.innerHTML = `<div class="text-center py-4 text-gray-500 dark:text-gray-400">${t("sso.providers.loading")}</div>`;

  try {
    const headers = await getAuthHeaders();
    const response = await fetch(`${ssoApiBase()}/admin/providers`, {
      method: "GET",
      headers,
      credentials: "same-origin", // pragma: allowlist secret
    });
    if (response.status === 404) {
      showSsoDisabledState();
      return;
    }
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const providers = await response.json();
    renderSsoProviders(providers);
  } catch (error) {
    console.error("Failed to load SSO providers:", error);
    listContainer.innerHTML = `<div class="text-center py-4 text-red-600 dark:text-red-400">${t("sso.providers.loadFailed")}</div>`;
    return;
  }

  await loadSsoPendingApprovals();
};

/**
 * Reset and open the provider form modal in create mode.
 */
export const showSsoProviderCreateModal = function () {
  const form = safeGetElement("sso-provider-form");
  if (!form) {
    return;
  }
  form.reset();
  clearSsoFormError();
  ssoState.formMode = "create";
  ssoState.editingProviderId = null;

  const title = safeGetElement("sso-provider-modal-title");
  if (title) {
    title.textContent = t("sso.form.createTitle");
  }
  const idField = form.elements.id;
  if (idField) {
    idField.disabled = false;
  }
  const secretField = form.elements.client_secret;
  if (secretField) {
    secretField.required = true;
    secretField.placeholder = "";
  }
  const scopeField = form.elements.scope;
  if (scopeField && !scopeField.value) {
    scopeField.value = "openid profile email";
  }
  openModal("sso-provider-modal");
};

/**
 * Fetch a provider's full detail and open the form modal in edit mode.
 * @param {string} providerId - Provider identifier
 */
export const showSsoProviderEditModal = async function (providerId) {
  const form = safeGetElement("sso-provider-form");
  if (!form || !providerId) {
    return;
  }

  try {
    const headers = await getAuthHeaders();
    const response = await fetch(`${ssoApiBase()}/admin/providers/${encodeURIComponent(providerId)}`, {
      method: "GET",
      headers,
      credentials: "same-origin", // pragma: allowlist secret
    });
    if (!response.ok) {
      throw new Error(await readErrorDetail(response, t("sso.providers.loadFailed")));
    }
    const provider = await response.json();

    form.reset();
    clearSsoFormError();
    ssoState.formMode = "edit";
    ssoState.editingProviderId = provider.id;

    const title = safeGetElement("sso-provider-modal-title");
    if (title) {
      title.textContent = t("sso.form.editTitle");
    }

    const setValue = function (name, value) {
      const field = form.elements[name];
      if (field) {
        field.value = value ?? "";
      }
    };
    setValue("id", provider.id);
    setValue("name", provider.name);
    setValue("display_name", provider.display_name);
    setValue("provider_type", provider.provider_type);
    setValue("client_id", provider.client_id);
    setValue("authorization_url", provider.authorization_url);
    setValue("token_url", provider.token_url);
    setValue("userinfo_url", provider.userinfo_url);
    setValue("issuer", provider.issuer);
    setValue("jwks_uri", provider.jwks_uri);
    setValue("scope", provider.scope);
    setValue("trusted_domains", Array.isArray(provider.trusted_domains) ? provider.trusted_domains.join(", ") : "");
    setValue("team_mapping", provider.team_mapping && Object.keys(provider.team_mapping).length > 0 ? JSON.stringify(provider.team_mapping, null, 2) : "");
    setValue("provider_metadata", provider.provider_metadata && Object.keys(provider.provider_metadata).length > 0 ? JSON.stringify(provider.provider_metadata, null, 2) : "");
    setValue("api_audience", provider.api_audience);

    const idField = form.elements.id;
    if (idField) {
      idField.disabled = true;
    }
    const secretField = form.elements.client_secret;
    if (secretField) {
      secretField.value = "";
      secretField.required = false;
      secretField.placeholder = t("sso.form.clientSecretEditPlaceholder");
    }
    const autoCreateField = form.elements.auto_create_users;
    if (autoCreateField) {
      autoCreateField.checked = Boolean(provider.auto_create_users);
    }
    const trustedField = form.elements.trusted_for_api_auth;
    if (trustedField) {
      trustedField.checked = Boolean(provider.trusted_for_api_auth);
    }

    openModal("sso-provider-modal");
  } catch (error) {
    console.error("Failed to load SSO provider detail:", error);
    showErrorMessage(error.message || t("sso.providers.loadFailed"));
  }
};

/**
 * Submit handler for the provider form (create POST or edit PUT).
 * @param {Event} event - The form submit event
 */
export const handleSsoProviderSubmit = async function (event) {
  const form = event.target;
  const isEdit = ssoState.formMode === "edit";
  const { payload, errors } = buildSsoProviderPayload(form, { isEdit });

  if (errors) {
    showSsoFormError(errors.join(" "));
    return;
  }

  const url = isEdit
    ? `${ssoApiBase()}/admin/providers/${encodeURIComponent(ssoState.editingProviderId)}`
    : `${ssoApiBase()}/admin/providers`;

  try {
    const headers = await getAuthHeaders(true);
    const response = await fetch(url, {
      method: isEdit ? "PUT" : "POST",
      headers,
      credentials: "same-origin", // pragma: allowlist secret
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(await readErrorDetail(response, t("sso.form.saveFailed")));
    }
    closeModal("sso-provider-modal");
    showSuccessMessage(t("sso.form.saved"));
    await loadSsoPanel();
  } catch (error) {
    console.error("Failed to save SSO provider:", error);
    showSsoFormError(error.message || t("sso.form.saveFailed"));
  }
};

/**
 * Enable or disable a provider via a partial PUT.
 * @param {string} providerId - Provider identifier
 * @param {boolean} isEnabled - Current enabled state (will be flipped)
 */
export const toggleSsoProvider = async function (providerId, isEnabled) {
  try {
    const headers = await getAuthHeaders(true);
    const response = await fetch(`${ssoApiBase()}/admin/providers/${encodeURIComponent(providerId)}`, {
      method: "PUT",
      headers,
      credentials: "same-origin", // pragma: allowlist secret
      body: JSON.stringify({ is_enabled: !isEnabled }),
    });
    if (!response.ok) {
      throw new Error(await readErrorDetail(response, t("sso.toggle.failed")));
    }
    await loadSsoPanel();
  } catch (error) {
    console.error("Failed to toggle SSO provider:", error);
    showErrorMessage(error.message || t("sso.toggle.failed"));
  }
};

/**
 * Open the delete confirmation modal for a provider.
 * @param {string} providerId - Provider identifier
 * @param {string} displayName - Provider display name shown in the prompt
 */
export const confirmDeleteSsoProvider = function (providerId, displayName) {
  ssoState.pendingDeleteProviderId = providerId;
  const message = safeGetElement("sso-delete-message");
  if (message) {
    message.textContent = t("sso.delete.confirm", { name: displayName || providerId });
  }
  openModal("sso-provider-delete-modal");
};

/**
 * Execute the pending provider deletion.
 */
export const deleteSsoProvider = async function () {
  const providerId = ssoState.pendingDeleteProviderId;
  if (!providerId) {
    return;
  }
  try {
    const headers = await getAuthHeaders();
    const response = await fetch(`${ssoApiBase()}/admin/providers/${encodeURIComponent(providerId)}`, {
      method: "DELETE",
      headers,
      credentials: "same-origin", // pragma: allowlist secret
    });
    if (!response.ok) {
      throw new Error(await readErrorDetail(response, t("sso.delete.failed")));
    }
    ssoState.pendingDeleteProviderId = null;
    closeModal("sso-provider-delete-modal");
    showSuccessMessage(t("sso.delete.success"));
    await loadSsoPanel();
  } catch (error) {
    console.error("Failed to delete SSO provider:", error);
    closeModal("sso-provider-delete-modal");
    showErrorMessage(error.message || t("sso.delete.failed"));
  }
};

/**
 * Approve a pending SSO user.
 * @param {string} approvalId - Approval request identifier
 */
export const approveSsoUser = async function (approvalId) {
  try {
    const headers = await getAuthHeaders(true);
    const response = await fetch(`${ssoApiBase()}/pending-approvals/${encodeURIComponent(approvalId)}/action`, {
      method: "POST",
      headers,
      credentials: "same-origin", // pragma: allowlist secret
      body: JSON.stringify({ action: "approve" }),
    });
    if (!response.ok) {
      throw new Error(await readErrorDetail(response, t("sso.approvals.actionFailed")));
    }
    showSuccessMessage(t("sso.approvals.approved"));
    await loadSsoPendingApprovals();
  } catch (error) {
    console.error("Failed to approve SSO user:", error);
    showErrorMessage(error.message || t("sso.approvals.actionFailed"));
  }
};

/**
 * Open the reject modal for a pending SSO user.
 * @param {string} approvalId - Approval request identifier
 * @param {string} email - Email shown in the modal for context
 */
export const showSsoRejectModal = function (approvalId, email) {
  const form = safeGetElement("sso-reject-form");
  if (form) {
    form.reset();
  }
  const errorBox = safeGetElement("sso-reject-form-error");
  if (errorBox) {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
  }
  ssoState.pendingRejectApprovalId = approvalId;
  const emailEl = safeGetElement("sso-reject-email");
  if (emailEl) {
    emailEl.textContent = email || "";
  }
  openModal("sso-reject-modal");
};

/**
 * Submit handler for the reject form. A reason is required by the API.
 * @param {Event} event - The form submit event
 */
export const handleSsoRejectSubmit = async function (event) {
  const form = event.target;
  const approvalId = ssoState.pendingRejectApprovalId;
  if (!approvalId) {
    return;
  }

  const reason = form.elements.reason ? String(form.elements.reason.value).trim() : "";
  const notes = form.elements.notes ? String(form.elements.notes.value).trim() : "";

  if (!reason) {
    const errorBox = safeGetElement("sso-reject-form-error");
    if (errorBox) {
      errorBox.textContent = t("sso.reject.reasonRequired");
      errorBox.classList.remove("hidden");
    }
    return;
  }

  const body = { action: "reject", reason };
  if (notes) {
    body.notes = notes;
  }

  try {
    const headers = await getAuthHeaders(true);
    const response = await fetch(`${ssoApiBase()}/pending-approvals/${encodeURIComponent(approvalId)}/action`, {
      method: "POST",
      headers,
      credentials: "same-origin", // pragma: allowlist secret
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(await readErrorDetail(response, t("sso.approvals.actionFailed")));
    }
    ssoState.pendingRejectApprovalId = null;
    closeModal("sso-reject-modal");
    showSuccessMessage(t("sso.approvals.rejected"));
    await loadSsoPendingApprovals();
  } catch (error) {
    console.error("Failed to reject SSO user:", error);
    const errorBox = safeGetElement("sso-reject-form-error");
    if (errorBox) {
      errorBox.textContent = error.message || t("sso.approvals.actionFailed");
      errorBox.classList.remove("hidden");
    }
  }
};
