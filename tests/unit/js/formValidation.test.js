/**
 * Unit tests for formValidation.js module
 * Tests: setupFormValidation
 */

import { describe, test, expect, vi, afterEach } from "vitest";

import { setupFormValidation } from "../../../mcpgateway/admin_ui/formValidation.js";
import { validateInputName, validateUrl } from "../../../mcpgateway/admin_ui/security.js";

vi.mock("../../../mcpgateway/admin_ui/security.js", () => ({
  validateInputName: vi.fn((value, label) => {
    if (!value || value.trim() === "") {
      return { valid: false, error: `${label || "Name"} is required` };
    }
    if (value.includes("<script>")) {
      return { valid: false, error: "Invalid characters" };
    }
    return { valid: true, value: value.trim() };
  }),
  validateUrl: vi.fn((value, label) => {
    if (!value || value.trim() === "") {
      return { valid: false, error: `${label || "URL"} is required` };
    }
    if (!value.startsWith("http")) {
      return { valid: false, error: "Invalid URL format" };
    }
    return { valid: true, value: value.trim() };
  }),
}));

afterEach(() => {
  document.body.innerHTML = "";
  vi.clearAllMocks();
});

describe("setupFormValidation", () => {
  test("attaches blur listeners to name fields", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-name">Name</label>
          <input id="test-name" name="name" value="" />
          <p data-error-message-for="name" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const nameField = document.getElementById("test-name");
    nameField.value = "ValidName";
    nameField.dispatchEvent(new Event("blur"));

    // label is undefined in jsdom since innerText is not supported
    expect(validateInputName).toHaveBeenCalledWith("ValidName", undefined);
  });

  test("shows error on invalid name field", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-name">Name</label>
          <input id="test-name" name="name" value="" />
          <p data-error-message-for="name" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const nameField = document.getElementById("test-name");
    nameField.value = "<script>alert(1)</script>";
    nameField.dispatchEvent(new Event("blur"));

    expect(nameField.classList.contains("border-red-500")).toBe(true);
    expect(nameField.getAttribute("aria-invalid")).toBe("true");
    const errorMsg = document.querySelector('[data-error-message-for="name"]');
    expect(errorMsg.classList.contains("invisible")).toBe(false);
  });

  test("clears aria-invalid when the field becomes valid", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-name">Name</label>
          <input id="test-name" name="name" value="" />
          <p data-error-message-for="name" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const nameField = document.getElementById("test-name");
    nameField.value = "<script>alert(1)</script>";
    nameField.dispatchEvent(new Event("blur"));
    expect(nameField.getAttribute("aria-invalid")).toBe("true");

    nameField.value = "ValidName";
    nameField.dispatchEvent(new Event("blur"));
    expect(nameField.hasAttribute("aria-invalid")).toBe(false);
  });

  test("clears error on valid name field", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-name">Name</label>
          <input id="test-name" name="name" value="" class="border-red-500" />
          <p data-error-message-for="name">Old error</p>
        </div>
      </form>
    `;

    setupFormValidation();

    const nameField = document.getElementById("test-name");
    nameField.value = "GoodName";
    nameField.dispatchEvent(new Event("blur"));

    expect(nameField.classList.contains("border-red-500")).toBe(false);
    const errorMsg = document.querySelector('[data-error-message-for="name"]');
    expect(errorMsg.classList.contains("invisible")).toBe(true);
  });

  test("attaches blur listeners to URL fields", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-url">URL</label>
          <input id="test-url" name="url" value="" required />
          <p data-error-message-for="url" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const urlField = document.getElementById("test-url");
    urlField.value = "http://example.com";
    urlField.dispatchEvent(new Event("blur"));

    expect(validateUrl).toHaveBeenCalledWith("http://example.com", undefined);
  });

  test("shows error on invalid URL field", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-url">URL</label>
          <input id="test-url" name="url" value="" required />
          <p data-error-message-for="url" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const urlField = document.getElementById("test-url");
    urlField.value = "not-a-url";
    urlField.dispatchEvent(new Event("blur"));

    expect(urlField.classList.contains("border-red-500")).toBe(true);
  });

  test("skips empty optional URL fields", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-url">URL</label>
          <input id="test-url" name="url" value="" />
          <p data-error-message-for="url" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const urlField = document.getElementById("test-url");
    urlField.value = "";
    urlField.dispatchEvent(new Event("blur"));

    // should not add error classes for empty optional fields
    expect(urlField.classList.contains("border-red-500")).toBe(false);
    expect(validateUrl).not.toHaveBeenCalled();
  });

  test("stays quiet when tabbing through an untouched empty form", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-name">Name</label>
          <input id="test-name" name="name" value="" required />
          <p data-error-message-for="name" class="invisible"></p>
        </div>
        <div>
          <label for="test-url">URL</label>
          <input id="test-url" name="url" value="" required />
          <p data-error-message-for="url" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const nameField = document.getElementById("test-name");
    const urlField = document.getElementById("test-url");
    nameField.dispatchEvent(new Event("blur"));
    urlField.dispatchEvent(new Event("blur"));

    expect(validateInputName).not.toHaveBeenCalled();
    expect(validateUrl).not.toHaveBeenCalled();
    expect(nameField.classList.contains("border-red-500")).toBe(false);
    expect(urlField.classList.contains("border-red-500")).toBe(false);
    expect(
      document
        .querySelector('[data-error-message-for="name"]')
        .classList.contains("invisible")
    ).toBe(true);
  });

  test("validates an empty field after the user typed and cleared it", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-name">Name</label>
          <input id="test-name" name="name" value="" required />
          <p data-error-message-for="name" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const nameField = document.getElementById("test-name");
    nameField.value = "draft";
    nameField.dispatchEvent(new Event("input"));
    nameField.value = "";
    nameField.dispatchEvent(new Event("blur"));

    expect(validateInputName).toHaveBeenCalled();
    expect(nameField.getAttribute("aria-invalid")).toBe("true");
    expect(nameField.hasAttribute("data-touched")).toBe(true);
  });

  test("replaces the native validation bubble with the inline message", () => {
    document.body.innerHTML = `
      <form>
        <div>
          <label for="test-name">Name</label>
          <input id="test-name" name="name" value="" required />
          <p data-error-message-for="name" class="invisible"></p>
        </div>
      </form>
    `;

    setupFormValidation();

    const nameField = document.getElementById("test-name");
    const event = new Event("invalid", { bubbles: true, cancelable: true });
    nameField.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(true);
    expect(nameField.getAttribute("aria-invalid")).toBe("true");
    const errorMsg = document.querySelector('[data-error-message-for="name"]');
    expect(errorMsg.classList.contains("invisible")).toBe(false);
  });

  test("leaves the native bubble alone for controls it does not validate", () => {
    document.body.innerHTML = `
      <form>
        <input id="other-required" name="description" required />
      </form>
    `;

    setupFormValidation();

    const event = new Event("invalid", { bubbles: true, cancelable: true });
    document.getElementById("other-required").dispatchEvent(event);

    expect(event.defaultPrevented).toBe(false);
  });

  test("validates multiple forms on the page", () => {
    document.body.innerHTML = `
      <form>
        <input name="name" value="" />
      </form>
      <form>
        <input name="name" value="" />
      </form>
    `;

    setupFormValidation();

    const inputs = document.querySelectorAll("input");
    inputs.forEach((input) => {
      input.value = "test";
      input.dispatchEvent(new Event("blur"));
    });

    expect(validateInputName).toHaveBeenCalledTimes(2);
  });
});
