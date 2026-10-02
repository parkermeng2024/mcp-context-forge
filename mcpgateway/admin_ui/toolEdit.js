/**
 * Tool Edit Modal Helpers
 *
 * Integration-type dependent field handling for the edit-tool modal.
 * Extracted from an inline script in admin.html; registered on window.Admin
 * in admin.js.
 */

/**
 * Enable the HTTP verb select only for REST tools; for MCP tools, disable and
 * clear it to avoid submitting bad values.
 */
export const handleEditIntegrationTypeChange = function () {
  const typeSel = document.getElementById("edit-tool-type");
  const reqSel = document.getElementById("edit-tool-request-type");
  if (!typeSel || !reqSel) {
    return;
  }

  const isREST = typeSel.value === "REST";
  reqSel.disabled = !isREST;
  if (!isREST) {
    reqSel.value = "";
  }
};

/**
 * Watch the edit-tool modal and re-evaluate field enablement whenever it is
 * shown. The evaluation is deferred one tick so prefilled values land first.
 */
export const initToolEditModalObserver = function () {
  const modal = document.getElementById("tool-edit-modal");
  if (!modal) {
    return;
  }

  const observer = new MutationObserver(() => {
    const isOpen = !modal.classList.contains("hidden");
    if (isOpen) {
      setTimeout(handleEditIntegrationTypeChange, 0);
    }
  });
  observer.observe(modal, {
    attributes: true,
    attributeFilter: ["class"],
  });
};
