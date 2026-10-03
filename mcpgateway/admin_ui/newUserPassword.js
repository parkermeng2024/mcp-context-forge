/**
 * New User Password Validation
 *
 * Validates the create-user password field with the shared PasswordValidator
 * and toggles the submit button. Extracted from an inline script in admin.html;
 * `initNewUserPassword()` is called by admin.js.
 */

/**
 * Read the password policy from the server-injected config.
 * @returns {{enabled: boolean, requirements: object}} Password policy.
 */
const getPasswordPolicy = function () {
  const policy = window.__ADMIN_CONFIG__ && window.__ADMIN_CONFIG__.passwordPolicy;
  return policy || { enabled: false, requirements: {} };
};

/**
 * Validate the create-user password field, update the requirement indicators,
 * and enable or disable the submit button.
 */
export const validateNewUserPassword = function () {
  const passwordPolicy = getPasswordPolicy();
  if (!passwordPolicy.enabled || !window.PasswordValidator) {
    return;
  }

  const password = document.getElementById("new_user_password")?.value || "";
  const validation = window.PasswordValidator.validate(password, passwordPolicy.requirements);

  window.PasswordValidator.updateRequirementUI("req-length", validation.details.length);
  window.PasswordValidator.updateRequirementUI("req-uppercase", validation.details.complexityDetails.uppercase);
  window.PasswordValidator.updateRequirementUI("req-lowercase", validation.details.complexityDetails.lowercase);
  window.PasswordValidator.updateRequirementUI("req-numbers", validation.details.complexityDetails.numbers);
  window.PasswordValidator.updateRequirementUI("req-special", validation.details.complexityDetails.special);

  const submitBtn = document.getElementById("create_user_submit");
  if (submitBtn) {
    submitBtn.disabled = !validation.isValid;
    if (submitBtn.disabled) {
      submitBtn.classList.add("opacity-60", "cursor-not-allowed");
    } else {
      submitBtn.classList.remove("opacity-60", "cursor-not-allowed");
    }
  }
};

/**
 * Validate the password field once the document is ready. Call once from
 * admin.js.
 */
export const initNewUserPassword = function () {
  document.addEventListener("DOMContentLoaded", function () {
    validateNewUserPassword();
  });
};
