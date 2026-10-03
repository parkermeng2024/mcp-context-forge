/**
 * Unit tests for newUserPassword.js
 * Tests: the create-user password validation and the submit-button toggle.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  initNewUserPassword,
  validateNewUserPassword,
} from "../../../mcpgateway/admin_ui/newUserPassword.js";

const validDetails = {
  length: true,
  complexityDetails: { uppercase: true, lowercase: true, numbers: true, special: true },
};

const installValidator = function (isValid = true) {
  const validator = {
    validate: vi.fn().mockReturnValue({ isValid, details: validDetails }),
    updateRequirementUI: vi.fn(),
  };
  window.PasswordValidator = validator;
  return validator;
};

beforeEach(() => {
  document.body.innerHTML = `
    <input id="new_user_password" value="Secret123!" />
    <button id="create_user_submit"></button>
  `;
  window.__ADMIN_CONFIG__ = { passwordPolicy: { enabled: true, requirements: {} } };
});

afterEach(() => {
  vi.restoreAllMocks();
  delete window.PasswordValidator;
  delete window.__ADMIN_CONFIG__;
});

describe("validateNewUserPassword", () => {
  test("enables submit and updates every requirement indicator for a valid password", () => {
    const validator = installValidator(true);

    validateNewUserPassword();

    expect(validator.validate).toHaveBeenCalledWith("Secret123!", {});
    expect(validator.updateRequirementUI).toHaveBeenCalledTimes(5);
    const submit = document.getElementById("create_user_submit");
    expect(submit.disabled).toBe(false);
    expect(submit.classList.contains("opacity-60")).toBe(false);
  });

  test("disables submit and marks it inactive for an invalid password", () => {
    installValidator(false);

    validateNewUserPassword();

    const submit = document.getElementById("create_user_submit");
    expect(submit.disabled).toBe(true);
    expect(submit.classList.contains("opacity-60")).toBe(true);
    expect(submit.classList.contains("cursor-not-allowed")).toBe(true);
  });

  test("does nothing when the password policy is disabled", () => {
    const validator = installValidator(true);
    window.__ADMIN_CONFIG__ = { passwordPolicy: { enabled: false, requirements: {} } };

    validateNewUserPassword();

    expect(validator.validate).not.toHaveBeenCalled();
  });

  test("does nothing when PasswordValidator is not loaded", () => {
    delete window.PasswordValidator;

    expect(() => validateNewUserPassword()).not.toThrow();
  });
});

describe("initNewUserPassword", () => {
  test("validates once the document is ready", () => {
    const validator = installValidator(true);
    initNewUserPassword();

    document.dispatchEvent(new Event("DOMContentLoaded"));

    expect(validator.validate).toHaveBeenCalled();
  });
});
