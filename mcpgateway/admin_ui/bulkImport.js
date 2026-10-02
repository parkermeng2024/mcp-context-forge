/**
 * Bulk Tool Import
 *
 * Modal and dropdown bulk-import flows for tools: file/JSON input handling,
 * client-side validation and auto-fixing, preview, submit, and result
 * rendering. Extracted from inline scripts in admin.html; registered on
 * window.Admin in admin.js.
 */

import { t } from "./i18n.js";
import { escapeHtml } from "./security.js";
import { getRootPath } from "./utils.js";

/** Maximum number of tools accepted in one bulk import. */
export const MAX_BULK_IMPORT_TOOLS = 200;

// Parsed import payload awaiting submission (modal flow).
let bulkImportData = null;

/**
 * Normalize a tool name to the validation format: start with a letter, only
 * letters/numbers/dots/underscores/hyphens, lowercase.
 * @param {string} name - Raw tool name
 * @returns {string} Sanitized tool name
 */
export const sanitizeToolName = function (name) {
  return String(name)
    .trim()
    .replace(/\s+/g, "_") // Replace spaces with underscores
    .replace(/[^a-zA-Z0-9._-]/g, "") // Remove invalid characters
    .replace(/^[^a-zA-Z]/, "tool_") // Ensure starts with letter
    .toLowerCase();
};

/**
 * Normalize tags to an array of valid lowercase tag strings.
 * Accepts a comma-separated string or an array.
 * @param {string|string[]} tags - Raw tags value
 * @returns {string[]} Sanitized tags
 */
export const sanitizeToolTags = function (tags) {
  const list = typeof tags === "string" ? tags.split(",") : tags;
  if (!Array.isArray(list)) {
    return list;
  }
  return list
    .map((tag) => String(tag).trim().toLowerCase())
    .map((tag) => tag.replace(/[^a-z0-9\-:.]/g, ""))
    .filter((tag) => tag.length >= 2);
};

/**
 * Validate the structural shape of an import payload.
 * @param {*} data - Parsed JSON payload
 * @returns {string|null} Error message, or null when structurally valid
 */
export const validateImportStructure = function (data) {
  if (!Array.isArray(data)) {
    return "Data must be an array of tool definitions";
  }
  if (data.length === 0) {
    return "Array cannot be empty";
  }
  if (data.length > MAX_BULK_IMPORT_TOOLS) {
    return `Too many tools (${data.length}). Maximum ${MAX_BULK_IMPORT_TOOLS} allowed.`;
  }
  return null;
};

/**
 * Auto-fix and validate each tool in an import payload.
 * @param {Array} data - Structurally valid array of tool definitions
 * @returns {{ fixedData: Array, errors: string[] }} Fixed tools and per-item errors
 */
export const fixImportTools = function (data) {
  const errors = [];
  const fixedData = data.map((tool, index) => {
    if (!tool || typeof tool !== "object") {
      errors.push(`Item ${index + 1}: Must be an object`);
      return tool;
    }

    // Create a copy to avoid modifying original
    const fixedTool = { ...tool };

    if (fixedTool.name) {
      const originalName = fixedTool.name;
      fixedTool.name = sanitizeToolName(originalName);
      if (fixedTool.name !== originalName) {
        console.log(`Auto-fixed tool name: "${originalName}" -> "${fixedTool.name}"`);
      }
    }

    if (fixedTool.tags) {
      const originalTags = fixedTool.tags;
      fixedTool.tags = sanitizeToolTags(originalTags);
      if (JSON.stringify(fixedTool.tags) !== JSON.stringify(originalTags)) {
        console.log(`Auto-fixed tags: ${JSON.stringify(originalTags)} -> ${JSON.stringify(fixedTool.tags)}`);
      }
    }

    // Only name is strictly required
    const missing = ["name"].filter(
      (field) =>
        !fixedTool[field] ||
        (typeof fixedTool[field] === "string" && fixedTool[field].trim() === "")
    );
    if (missing.length > 0) {
      errors.push(`Item ${index + 1}: Missing required fields: ${missing.join(", ")}`);
    }

    // Warn about missing recommended fields without blocking the import
    const missingRecommended = ["url"].filter(
      (field) =>
        !fixedTool[field] ||
        (typeof fixedTool[field] === "string" && fixedTool[field].trim() === "")
    );
    if (missingRecommended.length > 0) {
      console.warn(
        `Item ${index + 1} (${fixedTool.name || "unnamed"}): Missing recommended fields: ${missingRecommended.join(", ")}`
      );
    }

    return fixedTool;
  });
  return { fixedData, errors };
};

/**
 * Build the total/success/failed counts from an import result.
 * @param {Object} result - Import API result
 * @returns {{ total: number, success: number, failed: number }} Counts
 */
export const getImportCounts = function (result) {
  const success = result.created_count || result.imported || 0;
  const failed = result.failed_count || 0;
  return { total: success + failed, success, failed };
};

/**
 * Format a byte count as a human-readable size.
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size
 */
export const formatFileSize = function (bytes) {
  if (bytes === 0) {
    return "0 Bytes";
  }
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

/**
 * Open the bulk import modal in its initial state.
 */
export const openBulkImportModal = function () {
  const modal = document.getElementById("bulk-import-modal");
  if (modal) {
    modal.classList.remove("hidden");
    resetBulkImportModal();
  } else {
    console.error("Modal element not found!");
  }
};

/**
 * Close the bulk import modal and reset it.
 */
export const closeBulkImportModal = function () {
  document.getElementById("bulk-import-modal").classList.add("hidden");
  resetBulkImportModal();
};

/**
 * Reset the bulk import modal to its initial state.
 */
export const resetBulkImportModal = function () {
  document.querySelector('input[name="import-method"][value="file"]').checked = true;
  toggleImportMethod("file");

  document.getElementById("bulk-import-file").value = "";
  document.getElementById("file-info").classList.add("hidden");

  document.getElementById("bulk-import-json").value = "";

  document.getElementById("import-preview").classList.add("hidden");
  document.getElementById("import-status").classList.add("hidden");
  document.getElementById("import-loading").classList.add("hidden");
  document.getElementById("import-statistics").classList.add("hidden");

  const validationStatus = document.getElementById("json-validation-status");
  validationStatus.textContent = "";
  validationStatus.className = "text-sm";

  document.getElementById("import-submit-btn").disabled = true;

  bulkImportData = null;
};

/**
 * Toggle between file upload and JSON paste input methods.
 * @param {string} method - "file" or "paste"
 */
export const toggleImportMethod = function (method) {
  const fileSection = document.getElementById("file-upload-section");
  const pasteSection = document.getElementById("json-paste-section");

  if (method === "file") {
    fileSection.classList.remove("hidden");
    pasteSection.classList.add("hidden");
  } else {
    fileSection.classList.add("hidden");
    pasteSection.classList.remove("hidden");
  }

  // Clear preview when switching methods
  document.getElementById("import-preview").classList.add("hidden");
  document.getElementById("import-submit-btn").disabled = true;
  bulkImportData = null;
};

/**
 * Handle selection of a JSON file in the modal flow.
 * @param {HTMLInputElement} input - The file input element
 */
export const handleFileSelect = function (input) {
  const file = input.files[0];
  if (!file) {
    document.getElementById("file-info").classList.add("hidden");
    return;
  }

  if (!file.name.toLowerCase().endsWith(".json")) {
    showImportError("Please select a JSON file.");
    input.value = "";
    return;
  }

  document.getElementById("file-name").textContent = file.name;
  document.getElementById("file-size").textContent = `(${formatFileSize(file.size)})`;
  document.getElementById("file-info").classList.remove("hidden");

  const reader = new FileReader();
  reader.onload = function (e) {
    try {
      const jsonData = JSON.parse(e.target.result);
      processImportData(jsonData);
    } catch (error) {
      showImportError(`Invalid JSON file: ${error.message}`);
      input.value = "";
      document.getElementById("file-info").classList.add("hidden");
    }
  };
  reader.onerror = function () {
    showImportError("Error reading file.");
    input.value = "";
    document.getElementById("file-info").classList.add("hidden");
  };
  reader.readAsText(file);
};

/**
 * Validate the JSON textarea content in the modal flow.
 */
export const validateJsonInput = function () {
  const jsonText = document.getElementById("bulk-import-json").value.trim();
  const statusElement = document.getElementById("json-validation-status");

  if (!jsonText) {
    statusElement.textContent = "Please enter JSON data";
    statusElement.className = "text-sm text-yellow-600 dark:text-yellow-400";
    return;
  }

  try {
    const jsonData = JSON.parse(jsonText);

    if (!Array.isArray(jsonData)) {
      statusElement.textContent =
        "✗ JSON must be an array of tool objects [{}], not a single object {}";
      statusElement.className = "text-sm text-red-600 dark:text-red-400";
      document.getElementById("import-preview").classList.add("hidden");
      document.getElementById("import-submit-btn").disabled = true;
      bulkImportData = null;
      return;
    }

    if (jsonData.length === 0) {
      statusElement.textContent = "✗ Array cannot be empty - add at least one tool";
      statusElement.className = "text-sm text-red-600 dark:text-red-400";
      document.getElementById("import-preview").classList.add("hidden");
      document.getElementById("import-submit-btn").disabled = true;
      bulkImportData = null;
      return;
    }

    const toolCount = jsonData.length;
    const toolsWithNames = jsonData.filter((tool) => tool && tool.name);

    if (toolsWithNames.length === toolCount) {
      statusElement.textContent = `✓ Valid JSON array with ${toolCount} tool(s) - names will be auto-fixed for compatibility`;
      statusElement.className = "text-sm text-green-600 dark:text-green-400";
    } else {
      statusElement.textContent = `⚠ Valid JSON but ${toolCount - toolsWithNames.length} tool(s) missing required name field`;
      statusElement.className = "text-sm text-yellow-600 dark:text-yellow-400";
    }

    processImportData(jsonData);
  } catch (error) {
    let helpText = "";
    if (error.message.includes("Unexpected")) {
      helpText = " (Check for missing commas, quotes, or brackets)";
    }
    statusElement.textContent = `✗ Invalid JSON: ${error.message}${helpText}`;
    statusElement.className = "text-sm text-red-600 dark:text-red-400";
    document.getElementById("import-preview").classList.add("hidden");
    document.getElementById("import-submit-btn").disabled = true;
    bulkImportData = null;
  }
};

/**
 * Process and validate import data, then show the preview.
 * @param {Array} data - Parsed JSON payload
 */
function processImportData(data) {
  try {
    const structureError = validateImportStructure(data);
    if (structureError) {
      throw new Error(structureError);
    }

    const { fixedData, errors } = fixImportTools(data);

    if (errors.length > 0) {
      throw new Error(
        `Validation errors:\n${errors.slice(0, 5).join("\n")}${errors.length > 5 ? `\n... and ${errors.length - 5} more errors` : ""}`
      );
    }

    bulkImportData = fixedData;
    showImportPreview(fixedData);
    document.getElementById("import-submit-btn").disabled = false;
    document.getElementById("import-status").classList.add("hidden");
  } catch (error) {
    showImportError(error.message);
    bulkImportData = null;
    document.getElementById("import-submit-btn").disabled = true;
  }
}

/**
 * Render the import preview list.
 * @param {Array} data - Fixed tool definitions
 */
function showImportPreview(data) {
  document.getElementById("preview-count").textContent = data.length;

  const previewList = document.getElementById("preview-list");
  previewList.innerHTML = "";

  data.slice(0, 10).forEach((tool) => {
    const li = document.createElement("li");
    li.className = "flex justify-between";
    li.innerHTML = `
      <span class="truncate">${escapeHtml(tool.name || "Unnamed")}</span>
      <span class="ml-2 text-gray-500">${escapeHtml(tool.integrationType || "REST")}</span>
    `;
    previewList.appendChild(li);
  });

  if (data.length > 10) {
    const li = document.createElement("li");
    li.className = "text-gray-500 italic";
    li.textContent = `... and ${data.length - 10} more tools`;
    previewList.appendChild(li);
  }

  document.getElementById("import-preview").classList.remove("hidden");
}

/**
 * Toggle the validation guide visibility.
 */
export const toggleValidationGuide = function () {
  const guide = document.getElementById("validation-guide");
  const toggle = document.getElementById("validation-guide-toggle");

  if (guide.classList.contains("hidden")) {
    guide.classList.remove("hidden");
    toggle.textContent = "Hide Validation Rules";
  } else {
    guide.classList.add("hidden");
    toggle.textContent = "Show Validation Rules";
  }
};

/**
 * Toggle the preview details visibility.
 */
export const togglePreviewDetails = function () {
  const details = document.getElementById("preview-details");
  const toggleText = document.getElementById("preview-toggle-text");

  if (details.classList.contains("hidden")) {
    details.classList.remove("hidden");
    toggleText.textContent = "Hide Details";
  } else {
    details.classList.add("hidden");
    toggleText.textContent = "Show Details";
  }
};

/**
 * Submit the modal bulk import to the server.
 */
export const submitBulkImport = async function () {
  if (!bulkImportData) {
    showImportError("No valid data to import");
    return;
  }

  document.getElementById("import-loading").classList.remove("hidden");
  document.getElementById("import-submit-btn").disabled = true;

  try {
    const response = await fetch(`${getRootPath()}/admin/tools/import`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(bulkImportData),
    });

    const result = await response.json();

    document.getElementById("import-loading").classList.add("hidden");

    if (response.ok) {
      updateImportStatistics(result);

      if (result.success) {
        showImportSuccess(result);
        setTimeout(() => {
          closeBulkImportModal();
          location.reload(); // Refresh to show new tools
        }, 3000);
      } else if (result.created_count > 0) {
        showImportSuccess(result);
        // Longer delay so the partial-success message is visible
        setTimeout(() => {
          closeBulkImportModal();
          location.reload();
        }, 5000);
      } else {
        showImportError(result.message || "All tools failed to import", result);
        document.getElementById("import-submit-btn").disabled = false;
      }
    } else {
      showImportError(result.message || "Import failed", result);
      document.getElementById("import-submit-btn").disabled = false;
    }
  } catch (error) {
    document.getElementById("import-loading").classList.add("hidden");
    showImportError(`Network error: ${error.message}`, null);
    document.getElementById("import-submit-btn").disabled = false;
  }
};

/**
 * Render the modal import success message, including failed-tool details.
 * @param {Object} result - Import API result
 */
function showImportSuccess(result) {
  const statusDiv = document.getElementById("import-status");
  const isPartialSuccess = result.failed_count > 0;
  const bgColor = isPartialSuccess ? "yellow" : "green";
  const textColor = isPartialSuccess ? "yellow" : "green";
  const { total } = getImportCounts(result);

  statusDiv.innerHTML = `
    <div class="bg-${bgColor}-50 dark:bg-${bgColor}-900 border border-${bgColor}-200 dark:border-${bgColor}-800 rounded-md p-4">
      <div class="flex">
        <div class="flex-shrink-0">
          <svg class="h-5 w-5 text-${textColor}-400" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
          </svg>
        </div>
        <div class="ml-3 w-full">
          <h3 class="text-sm font-medium text-${textColor}-800 dark:text-${textColor}-200">
            ${isPartialSuccess ? "Import Partially Completed" : "Import Completed Successfully"}
          </h3>

          <div class="mt-3 grid grid-cols-3 gap-4 text-center">
            <div class="bg-white dark:bg-gray-800 rounded-lg p-3 border">
              <div class="text-lg font-bold text-blue-600 dark:text-blue-400">${total}</div>
              <div class="text-xs text-gray-600 dark:text-gray-400">Total Tools</div>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-lg p-3 border">
              <div class="text-lg font-bold text-green-600 dark:text-green-400">${result.created_count || 0}</div>
              <div class="text-xs text-gray-600 dark:text-gray-400">${t("tokens.usage.successful")}</div>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-lg p-3 border">
              <div class="text-lg font-bold text-red-600 dark:text-red-400">${result.failed_count || 0}</div>
              <div class="text-xs text-gray-600 dark:text-gray-400">${t("tools.import.failed")}</div>
            </div>
          </div>

          <div class="mt-3 text-sm text-${textColor}-700 dark:text-${textColor}-300">
            <p><strong>${result.created_count || 0}</strong> tools imported successfully out of <strong>${total}</strong> total tools</p>
            ${result.failed_count > 0 ? `<p class="text-red-600 dark:text-red-400"><strong>${result.failed_count}</strong> tools failed to import</p>` : ""}
            ${
  result.errors && result.errors.length > 0
    ? `
              <details class="mt-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                <summary class="cursor-pointer font-medium text-red-800 dark:text-red-200 hover:text-red-600 dark:hover:text-red-300">
                  📋 View Failed Tools (${result.errors.length})
                </summary>
                <div class="mt-3 max-h-64 overflow-y-auto">
                  <div class="space-y-2">
                    ${result.errors
    .map(
      (error, index) => `
                        <div class="bg-white dark:bg-gray-800 border border-red-200 dark:border-red-700 rounded p-2 text-xs">
                          <div class="flex justify-between items-start">
                            <div class="font-medium text-red-800 dark:text-red-200">
                              ${index + 1}. ${escapeHtml(error.name || error.tool_name || "Unnamed Tool")}
                            </div>
                            <span class="text-red-600 dark:text-red-400 text-xs">❌</span>
                          </div>
                          <div class="mt-1 text-red-700 dark:text-red-300">
                            <strong>Error:</strong> ${escapeHtml(error.error?.message || error.message || "Unknown error")}
                          </div>
                          ${error.url ? `<div class="mt-1 text-gray-600 dark:text-gray-400"><strong>URL:</strong> ${escapeHtml(error.url)}</div>` : ""}
                        </div>
                      `
    )
    .join("")}
                  </div>
                </div>
              </details>
            `
    : ""
}
            <p class="mt-3 text-xs text-gray-600 dark:text-gray-400">Page will refresh automatically...</p>
          </div>
        </div>
      </div>
    </div>
  `;
  statusDiv.classList.remove("hidden");
}

/**
 * Render the modal import error message, with statistics when available.
 * @param {string} message - Error message
 * @param {Object} [result] - Import API result, when available
 */
function showImportError(message, result = null) {
  const statusDiv = document.getElementById("import-status");

  let errorContent = `<p>${escapeHtml(message)}</p>`;

  if (result && (result.failed_count > 0 || result.errors)) {
    const { total, success, failed } = getImportCounts(result);

    errorContent = `
      <div class="mb-3 grid grid-cols-3 gap-4 text-center">
        <div class="bg-white dark:bg-gray-800 rounded-lg p-3 border">
          <div class="text-lg font-bold text-blue-600 dark:text-blue-400">${total}</div>
          <div class="text-xs text-gray-600 dark:text-gray-400">Total Tools</div>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-lg p-3 border">
          <div class="text-lg font-bold text-green-600 dark:text-green-400">${success}</div>
          <div class="text-xs text-gray-600 dark:text-gray-400">${t("tokens.usage.successful")}</div>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-lg p-3 border">
          <div class="text-lg font-bold text-red-600 dark:text-red-400">${failed}</div>
          <div class="text-xs text-gray-600 dark:text-gray-400">${t("tools.import.failed")}</div>
        </div>
      </div>
      <p>${escapeHtml(message)}</p>
    `;
  }

  statusDiv.innerHTML = `
    <div class="bg-red-50 dark:bg-red-900 border border-red-200 dark:border-red-800 rounded-md p-4">
      <div class="flex">
        <div class="flex-shrink-0">
          <svg class="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 001.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 10-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
          </svg>
        </div>
        <div class="ml-3 w-full">
          <h3 class="text-sm font-medium text-red-800 dark:text-red-200">
            Import ${result && result.created_count > 0 ? "Partially Failed" : "Failed"}
          </h3>
          <div class="mt-2 text-sm text-red-700 dark:text-red-300">
            ${errorContent}
          </div>
        </div>
      </div>
    </div>
  `;
  statusDiv.classList.remove("hidden");
}

/**
 * Update the modal import statistics display.
 * @param {Object} result - Import API result
 */
function updateImportStatistics(result) {
  const { total, success, failed } = getImportCounts(result);

  document.getElementById("stats-total").textContent = total;
  document.getElementById("stats-success").textContent = success;
  document.getElementById("stats-failed").textContent = failed;

  document.getElementById("import-statistics").classList.remove("hidden");
}

// ===================================================================
// Dropdown bulk import flow
// ===================================================================

/**
 * Toggle the bulk import dropdown visibility.
 */
export const toggleBulkImportDropdown = function () {
  const dropdown = document.getElementById("bulk-import-dropdown");
  dropdown.classList.toggle("hidden");
};

/**
 * Toggle the dropdown import input method.
 * @param {string} method - "file" or "paste"
 */
export const toggleDropdownImportMethod = function (method) {
  const fileSection = document.getElementById("dropdown-file-section");
  const pasteSection = document.getElementById("dropdown-paste-section");

  if (method === "file") {
    fileSection.classList.remove("hidden");
    pasteSection.classList.add("hidden");
  } else {
    fileSection.classList.add("hidden");
    pasteSection.classList.remove("hidden");
  }
  resetDropdownImport();
};

/**
 * Handle selection of a JSON file in the dropdown flow.
 * @param {HTMLInputElement} input - The file input element
 */
export const handleDropdownFileSelect = function (input) {
  const fileInfo = document.getElementById("dropdown-file-info");

  if (!input.files[0]) {
    resetDropdownImport();
    return;
  }

  const file = input.files[0];
  fileInfo.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  fileInfo.classList.remove("hidden");

  const reader = new FileReader();
  reader.onload = function (e) {
    try {
      const data = JSON.parse(e.target.result);
      validateDropdownData(data);
    } catch (error) {
      showDropdownStatus("error", `Invalid JSON: ${error.message}`);
    }
  };
  reader.readAsText(file);
};

/**
 * Validate the JSON textarea content in the dropdown flow.
 */
export const validateDropdownJson = function () {
  const textarea = document.getElementById("dropdown-json-textarea");
  const status = document.getElementById("dropdown-json-status");

  if (!textarea.value.trim()) {
    status.textContent = "";
    document.getElementById("dropdown-import-btn").disabled = true;
    document.getElementById("dropdown-preview").classList.add("hidden");
    return;
  }

  try {
    const data = JSON.parse(textarea.value);
    status.innerHTML = '<span class="text-green-600">✓ Valid JSON</span>';
    validateDropdownData(data);
  } catch (error) {
    status.innerHTML = `<span class="text-red-600">✗ Invalid JSON: ${escapeHtml(error.message)}</span>`;
    document.getElementById("dropdown-import-btn").disabled = true;
    document.getElementById("dropdown-preview").classList.add("hidden");
  }
};

/**
 * Validate parsed dropdown import data and enable the import button.
 * @param {*} data - Parsed JSON payload
 */
export const validateDropdownData = function (data) {
  const preview = document.getElementById("dropdown-preview");
  const count = document.getElementById("dropdown-preview-count");
  const importBtn = document.getElementById("dropdown-import-btn");

  if (!Array.isArray(data)) {
    showDropdownStatus("error", "Data must be an array of tools");
    return;
  }

  if (data.length === 0) {
    showDropdownStatus("error", "Array cannot be empty");
    return;
  }

  if (data.length > MAX_BULK_IMPORT_TOOLS) {
    showDropdownStatus(
      "error",
      `Cannot import more than ${MAX_BULK_IMPORT_TOOLS} tools at once`
    );
    return;
  }

  count.textContent = data.length;
  preview.classList.remove("hidden");
  importBtn.disabled = false;
  showDropdownStatus("success", `${data.length} tools ready for import`);
};

/**
 * Show a dropdown status message.
 * @param {string} type - One of error, warning, success
 * @param {string} message - Message text (escaped unless it contains HTML)
 */
export const showDropdownStatus = function (type, message) {
  const status = document.getElementById("dropdown-status");
  const colorClass = type === "error" ? "red" : type === "warning" ? "yellow" : "green";
  const content = message.includes("<div") ? message : escapeHtml(message);
  status.innerHTML = `<div class="text-${colorClass}-600 dark:text-${colorClass}-400 whitespace-pre-line text-xs">${content}</div>`;
  status.classList.remove("hidden");
};

/**
 * Show dropdown import result counts.
 * @param {number} total - Total tools processed
 * @param {number} success - Successfully imported
 * @param {number} failed - Failed to import
 */
export const showDropdownResults = function (total, success, failed) {
  document.getElementById("dropdown-stats-total").textContent = total;
  document.getElementById("dropdown-stats-success").textContent = success;
  document.getElementById("dropdown-stats-failed").textContent = failed;
  document.getElementById("dropdown-results").classList.remove("hidden");
};

/**
 * Render the failed-tools list in the dropdown status area.
 * @param {Array} errors - Per-tool import errors
 */
export const showDropdownFailedTools = function (errors) {
  const failedToolsHtml = errors
    .map(
      (error, index) =>
        `<div class="text-xs p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded mb-1">
          <div class="font-medium text-red-800 dark:text-red-200">${index + 1}. ${escapeHtml(error.name || error.tool_name || "Unnamed Tool")}</div>
          <div class="text-red-600 dark:text-red-400 mt-1">${escapeHtml(error.error?.message || error.message || "Unknown error")}</div>
        </div>`
    )
    .join("");

  showDropdownStatus(
    "error",
    `<div class="font-medium mb-2">Failed Tools (${errors.length}):</div><div class="max-h-32 overflow-y-auto">${failedToolsHtml}</div>`
  );
};

/**
 * Append the discard/execute action buttons to the dropdown status area.
 */
export const showDropdownActionButtons = function () {
  const actionButtonsHtml = `<div class="mt-3 flex justify-center space-x-2">
    <button data-action-click="toggleBulkImportDropdown" class="px-3 py-1 text-xs bg-gray-600 text-white rounded hover:bg-gray-700">
      Discard
    </button>
    <button data-action-click="executeBulkImportAndReload" class="px-3 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700">
      🔄 Execute Import
    </button>
  </div>`;

  const statusDiv = document.getElementById("dropdown-status");
  statusDiv.innerHTML += actionButtonsHtml;
};

/**
 * Reset the dropdown import form to its initial state.
 */
export const resetDropdownImport = function () {
  document.getElementById("dropdown-file-input").value = "";
  document.getElementById("dropdown-json-textarea").value = "";
  document.getElementById("dropdown-file-info").classList.add("hidden");
  document.getElementById("dropdown-json-status").textContent = "";
  document.getElementById("dropdown-preview").classList.add("hidden");
  document.getElementById("dropdown-status").classList.add("hidden");
  document.getElementById("dropdown-results").classList.add("hidden");
  document.getElementById("dropdown-import-btn").disabled = true;
};

/**
 * Submit the dropdown import from the selected file or pasted JSON.
 */
export const submitDropdownImport = async function () {
  let data;
  const fileInput = document.getElementById("dropdown-file-input");
  const textarea = document.getElementById("dropdown-json-textarea");

  if (fileInput.files[0]) {
    const reader = new FileReader();
    reader.onload = async function (e) {
      try {
        data = JSON.parse(e.target.result);
        await performDropdownImport(data);
      } catch (error) {
        showDropdownStatus("error", `Failed to parse file: ${error.message}`);
      }
    };
    reader.readAsText(fileInput.files[0]);
  } else if (textarea.value.trim()) {
    try {
      data = JSON.parse(textarea.value);
      await performDropdownImport(data);
    } catch (error) {
      showDropdownStatus("error", `Invalid JSON: ${error.message}`);
    }
  }
};

/**
 * POST the dropdown import payload to the server and render the outcome.
 * @param {Array} data - Tool definitions to import
 */
export const performDropdownImport = async function (data) {
  const importBtn = document.getElementById("dropdown-import-btn");

  importBtn.disabled = true;
  importBtn.textContent = "Importing...";

  try {
    const response = await fetch(`${getRootPath()}/admin/tools/import`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });

    const result = await response.json();

    if (response.ok) {
      const { total, success, failed } = getImportCounts(result);

      showDropdownResults(total, success, failed);

      let statusMessage = `✅ Import completed: ${success}/${total} tools imported successfully`;
      if (failed > 0) {
        statusMessage = `⚠️ Partial success: ${success}/${total} tools imported, ${failed} failed`;
      }

      showDropdownStatus("success", statusMessage);

      if (result.errors && result.errors.length > 0) {
        showDropdownFailedTools(result.errors);
      }

      showDropdownActionButtons();
    } else {
      showDropdownStatus(
        "error",
        `❌ Import failed: ${result.detail || result.message || "Unknown error"}`
      );
    }
  } catch (error) {
    showDropdownStatus("error", `❌ Network error: ${error.message}`);
  } finally {
    importBtn.disabled = false;
    importBtn.textContent = "Import Tools";
  }
};

/**
 * Wire up bulk-import listeners: JSON textarea auto-validation and closing the
 * dropdown when clicking outside of it.
 */
export const initBulkImport = function () {
  const jsonTextarea = document.getElementById("bulk-import-json");
  if (jsonTextarea) {
    let validationTimeout;
    jsonTextarea.addEventListener("input", () => {
      clearTimeout(validationTimeout);
      validationTimeout = setTimeout(() => {
        if (jsonTextarea.value.trim()) {
          validateJsonInput();
        }
      }, 1000); // Validate 1 second after user stops typing
    });
  }

  document.addEventListener("click", (event) => {
    const dropdown = document.getElementById("bulk-import-dropdown");
    const button = document.getElementById("bulk-import-dropdown-btn");

    if (dropdown && !dropdown.contains(event.target) && !button.contains(event.target)) {
      dropdown.classList.add("hidden");
    }
  });
};

document.addEventListener("DOMContentLoaded", initBulkImport);
