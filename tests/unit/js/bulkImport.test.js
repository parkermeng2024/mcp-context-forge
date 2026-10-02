/**
 * Unit tests for bulkImport.js module
 * Tests: payload structure validation, name and tag sanitizing, import counts,
 *        the modal open/close/reset cycle, the JSON textarea validation, and
 *        the tools-tab dropdown flow.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  MAX_BULK_IMPORT_TOOLS,
  closeBulkImportModal,
  fixImportTools,
  formatFileSize,
  getImportCounts,
  handleDropdownFileSelect,
  openBulkImportModal,
  performDropdownImport,
  resetBulkImportModal,
  resetDropdownImport,
  sanitizeToolName,
  sanitizeToolTags,
  toggleBulkImportDropdown,
  toggleImportMethod,
  validateDropdownData,
  validateDropdownJson,
  validateImportStructure,
  validateJsonInput,
} from "../../../mcpgateway/admin_ui/bulkImport.js";

/**
 * Render the bulk import modal markup the module drives.
 */
const renderModal = () => {
  document.body.innerHTML = `
    <div id="bulk-import-modal" class="hidden">
      <input type="radio" name="import-method" value="file" checked />
      <input type="radio" name="import-method" value="paste" />
      <div id="file-upload-section"></div>
      <div id="json-paste-section" class="hidden"></div>
      <input id="bulk-import-file" type="file" />
      <div id="file-info" class="hidden"></div>
      <textarea id="bulk-import-json"></textarea>
      <div id="json-validation-status"></div>
      <div id="import-preview" class="hidden">
        <div id="preview-count"></div>
        <ul id="preview-list"></ul>
      </div>
      <div id="import-status" class="hidden"></div>
      <div id="import-loading" class="hidden"></div>
      <div id="import-statistics" class="hidden"></div>
      <button id="import-submit-btn" disabled></button>
    </div>
    <div id="bulk-import-dropdown" class="hidden"></div>
    <button id="bulk-import-dropdown-btn"></button>
  `;
};

beforeEach(() => {
  window.ROOT_PATH = "";
  renderModal();
});

afterEach(() => {
  vi.restoreAllMocks();
  delete window.ROOT_PATH;
});

describe("sanitizeToolName", () => {
  test("replaces spaces and lowercases", () => {
    expect(sanitizeToolName("Weather API")).toBe("weather_api");
  });

  test("keeps dots, underscores and hyphens", () => {
    expect(sanitizeToolName("get.weather_v2-beta")).toBe("get.weather_v2-beta");
  });

  test("prefixes a name that does not start with a letter", () => {
    expect(sanitizeToolName("2fast")).toBe("tool_fast");
  });

  test("drops characters the server rejects", () => {
    expect(sanitizeToolName("wea!ther#api")).toBe("weatherapi");
  });
});

describe("sanitizeToolTags", () => {
  test("splits a comma-separated string", () => {
    expect(sanitizeToolTags("Weather, api")).toEqual(["weather", "api"]);
  });

  test("cleans an array of tags", () => {
    expect(sanitizeToolTags(["Weather!", "A", "api"])).toEqual(["weather", "api"]);
  });

  test("returns a non-array value unchanged", () => {
    expect(sanitizeToolTags(null)).toBeNull();
  });
});

describe("validateImportStructure", () => {
  test("accepts a non-empty array within the limit", () => {
    expect(validateImportStructure([{ name: "tool" }])).toBeNull();
  });

  test("rejects a payload that is not an array", () => {
    expect(validateImportStructure({})).toMatch(/array/i);
  });

  test("rejects an empty array", () => {
    expect(validateImportStructure([])).toMatch(/empty/i);
  });

  test("rejects more tools than the limit", () => {
    const data = new Array(MAX_BULK_IMPORT_TOOLS + 1).fill({ name: "tool" });
    expect(validateImportStructure(data)).toContain(String(MAX_BULK_IMPORT_TOOLS));
  });
});

describe("fixImportTools", () => {
  test("fixes names and tags without touching the input", () => {
    const input = [{ name: "Weather API", tags: "Weather, api" }];
    const { fixedData, errors } = fixImportTools(input);

    expect(errors).toEqual([]);
    expect(fixedData[0].name).toBe("weather_api");
    expect(fixedData[0].tags).toEqual(["weather", "api"]);
    expect(input[0].name).toBe("Weather API");
  });

  test("reports items that are not objects", () => {
    const { errors } = fixImportTools([null]);
    expect(errors[0]).toContain("Item 1");
  });

  test("reports a missing name", () => {
    const { errors } = fixImportTools([{ url: "https://example.com" }]);
    expect(errors[0]).toContain("name");
  });
});

describe("getImportCounts and formatFileSize", () => {
  test("builds the counts from either API shape", () => {
    expect(getImportCounts({ created_count: 2, failed_count: 1 })).toEqual({
      total: 3,
      success: 2,
      failed: 1,
    });
    expect(getImportCounts({ imported: 4 })).toEqual({
      total: 4,
      success: 4,
      failed: 0,
    });
  });

  test("formats byte counts", () => {
    expect(formatFileSize(0)).toBe("0 Bytes");
    expect(formatFileSize(2048)).toBe("2 KB");
  });
});

describe("modal lifecycle", () => {
  test("openBulkImportModal reveals and resets the modal", () => {
    const modal = document.getElementById("bulk-import-modal");
    document.getElementById("bulk-import-json").value = '{"a":1}';
    document.getElementById("import-submit-btn").disabled = false;

    openBulkImportModal();

    expect(modal.classList).not.toContain("hidden");
    expect(document.getElementById("bulk-import-json").value).toBe("");
    expect(document.getElementById("import-submit-btn").disabled).toBe(true);
  });

  test("closeBulkImportModal hides the modal", () => {
    document.getElementById("bulk-import-modal").classList.remove("hidden");
    closeBulkImportModal();
    expect(document.getElementById("bulk-import-modal").classList).toContain(
      "hidden"
    );
  });

  test("resetBulkImportModal restores the file method", () => {
    document.querySelector('input[name="import-method"][value="paste"]').checked = true;
    resetBulkImportModal();

    expect(
      document.querySelector('input[name="import-method"][value="file"]').checked
    ).toBe(true);
    expect(document.getElementById("file-upload-section").classList).not.toContain(
      "hidden"
    );
    expect(document.getElementById("json-paste-section").classList).toContain(
      "hidden"
    );
  });
});

describe("toggleImportMethod", () => {
  test("shows the paste section when the paste method is chosen", () => {
    toggleImportMethod("paste");
    expect(document.getElementById("json-paste-section").classList).not.toContain(
      "hidden"
    );
    expect(document.getElementById("file-upload-section").classList).toContain(
      "hidden"
    );
  });
});

describe("validateJsonInput", () => {
  const setJson = (value) => {
    document.getElementById("bulk-import-json").value = value;
  };

  test("asks for data when the textarea is empty", () => {
    setJson("");
    validateJsonInput();
    expect(
      document.getElementById("json-validation-status").textContent
    ).toContain("Please enter JSON data");
  });

  test("accepts a valid array and enables submit", () => {
    setJson(JSON.stringify([{ name: "Weather API" }]));
    validateJsonInput();

    const status = document.getElementById("json-validation-status");
    expect(status.className).toContain("green");
    expect(document.getElementById("import-submit-btn").disabled).toBe(false);
    expect(document.getElementById("preview-list").children.length).toBe(1);
  });

  test("rejects invalid JSON and keeps submit disabled", () => {
    setJson("{not json}");
    validateJsonInput();

    const status = document.getElementById("json-validation-status");
    expect(status.className).toContain("red");
    expect(document.getElementById("import-submit-btn").disabled).toBe(true);
  });

  test("rejects a payload that is not an array", () => {
    setJson('{"name": "tool"}');
    validateJsonInput();

    expect(
      document.getElementById("json-validation-status").className
    ).toContain("red");
  });
});

describe("dropdown flow", () => {
  beforeEach(() => {
    document.body.insertAdjacentHTML(
      "beforeend",
      `
      <input id="dropdown-file-input" type="file" />
      <div id="dropdown-file-info" class="hidden"></div>
      <textarea id="dropdown-json-textarea"></textarea>
      <div id="dropdown-json-status"></div>
      <div id="dropdown-preview" class="hidden">
        <span id="dropdown-preview-count"></span>
      </div>
      <div id="dropdown-status" class="hidden"></div>
      <div id="dropdown-results" class="hidden">
        <span id="dropdown-stats-total"></span>
        <span id="dropdown-stats-success"></span>
        <span id="dropdown-stats-failed"></span>
      </div>
      <button id="dropdown-import-btn" disabled></button>
      `
    );
  });

  test("toggleBulkImportDropdown flips the dropdown", () => {
    const dropdown = document.getElementById("bulk-import-dropdown");
    toggleBulkImportDropdown();
    expect(dropdown.classList).not.toContain("hidden");
    toggleBulkImportDropdown();
    expect(dropdown.classList).toContain("hidden");
  });

  test("validateDropdownData reports an empty array", () => {
    validateDropdownData([]);
    expect(document.getElementById("dropdown-status").textContent).toContain(
      "empty"
    );
  });

  test("validateDropdownData reports the tool limit", () => {
    const data = new Array(MAX_BULK_IMPORT_TOOLS + 1).fill({ name: "tool" });
    validateDropdownData(data);
    expect(document.getElementById("dropdown-status").textContent).toContain(
      String(MAX_BULK_IMPORT_TOOLS)
    );
  });

  test("validateDropdownData shows a preview for a valid payload", () => {
    validateDropdownData([{ name: "weather_api" }]);
    expect(document.getElementById("dropdown-preview").classList).not.toContain(
      "hidden"
    );
    expect(
      document.getElementById("dropdown-preview-count").textContent
    ).toBe("1");
  });

  test("validateDropdownJson clears the status when the textarea is empty", () => {
    document.getElementById("dropdown-json-status").textContent = "stale";
    validateDropdownJson();
    expect(document.getElementById("dropdown-json-status").textContent).toBe("");
    expect(document.getElementById("dropdown-import-btn").disabled).toBe(true);
  });

  test("handleDropdownFileSelect resets the flow when no file is chosen", () => {
    document.getElementById("dropdown-results").classList.remove("hidden");
    handleDropdownFileSelect({ files: [] });
    expect(document.getElementById("dropdown-results").classList).toContain(
      "hidden"
    );
  });

  test("performDropdownImport renders the success statistics", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ created_count: 2, failed_count: 1, errors: [{ index: 1 }] }),
    });

    await performDropdownImport([{ name: "weather_api" }]);

    const status = document.getElementById("dropdown-status");
    expect(status.textContent).toContain("Failed Tools");
    expect(document.getElementById("dropdown-results").classList).not.toContain(
      "hidden"
    );
    expect(document.getElementById("dropdown-stats-total").textContent).toBe("3");
    expect(status.innerHTML).toContain("executeBulkImportAndReload");
    expect(document.getElementById("dropdown-import-btn").disabled).toBe(false);
  });

  test("performDropdownImport reports a failed import", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      json: async () => ({ detail: "nope" }),
    });

    await performDropdownImport([{ name: "weather_api" }]);

    expect(document.getElementById("dropdown-status").textContent).toContain(
      "nope"
    );
  });

  test("resetDropdownImport clears the results", () => {
    document.getElementById("dropdown-results").classList.remove("hidden");
    resetDropdownImport();
    expect(document.getElementById("dropdown-results").classList).toContain(
      "hidden"
    );
  });
});
