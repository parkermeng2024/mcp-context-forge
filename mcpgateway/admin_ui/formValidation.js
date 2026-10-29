// ===================================================================
// ENHANCED FORM VALIDATION for All Forms
// ===================================================================

import { validateInputName, validateUrl } from "./security.js";

/**
 * Tailwind utility classes applied to an input to signal a field-level error.
 *
 * Shared so that client-side validation and server-side error attribution
 * (formSubmitHandlers.js) render identically. ``modals.js`` clears this exact
 * set when resetting a form *inside a modal*; forms rendered inline on a page
 * must clear it themselves.
 *
 * @type {ReadonlyArray<string>}
 */
export const FIELD_ERROR_CLASSES = [
  "border-red-500",
  "focus:ring-red-500",
  "dark:border-red-500",
  "dark:ring-red-500",
];

/**
 * Marks a field the user has already interacted with.
 *
 * Blur alone does not validate an empty field: tabbing through a fresh form
 * would otherwise report every required field as missing. The flag is set on
 * the first input or change event, and cleared when a modal resets its form.
 */
const TOUCHED_ATTRIBUTE = "data-touched";

const NAME_FIELD_SELECTOR =
  'input[name="name"], input[name="customName"], input[name="custom_name"]';
const URL_FIELD_SELECTOR = 'input[name*="url"], input[name*="URL"]';

/**
 * Return true when the field is a technical name input this module validates.
 *
 * Hidden inputs are skipped, and any display-name-like field is left optional.
 *
 * @param {Element} field - Candidate form control.
 * @returns {boolean}
 */
function isNameField(field) {
  if (!field || !field.matches || !field.matches(NAME_FIELD_SELECTOR)) {
    return false;
  }
  if (field.type && field.type.toLowerCase() === "hidden") {
    return false;
  }
  return !/display/i.test(field.name || "");
}

/**
 * Return true when the field is a URL input this module validates.
 *
 * @param {Element} field - Candidate form control.
 * @returns {boolean}
 */
function isUrlField(field) {
  return Boolean(field && field.matches && field.matches(URL_FIELD_SELECTOR));
}

/**
 * Find the inline error paragraph rendered for a field.
 *
 * @param {Element} field - Form control whose wrapper holds the paragraph.
 * @param {string} key - `data-error-message-for` value.
 * @returns {HTMLParagraphElement|null}
 */
function findErrorElement(field, key) {
  return (
    field.parentNode?.querySelector(`p[data-error-message-for="${key}"]`) ??
    null
  );
}

/**
 * Reset a field to its non-error appearance.
 *
 * @param {Element} field - Form control to reset.
 * @param {string} key - `data-error-message-for` value of its inline message.
 * @returns {void}
 */
function clearFieldState(field, key) {
  field.setCustomValidity("");
  field.removeAttribute("aria-invalid");
  field.classList.remove(...FIELD_ERROR_CLASSES);
  findErrorElement(field, key)?.classList.add("invisible");
}

/**
 * Mark a field as invalid and render the message inline.
 *
 * @param {Element} field - Form control to mark.
 * @param {string} key - `data-error-message-for` value of its inline message.
 * @param {string} message - Localized message to show.
 * @returns {void}
 */
function showFieldState(field, key, message) {
  field.setCustomValidity(message);
  field.setAttribute("aria-invalid", "true");
  field.classList.add(...FIELD_ERROR_CLASSES);
  const errorElement = findErrorElement(field, key);
  if (errorElement) {
    errorElement.innerText = message;
    errorElement.classList.remove("invisible");
  }
}

/**
 * Validate a name field and render the result.
 *
 * @param {HTMLInputElement} field - Name input to validate.
 * @returns {void}
 */
function validateNameField(field) {
  const inputLabel = field.parentNode?.querySelector(
    `label[for="${field.id}"]`,
  );
  const validation = validateInputName(field.value, inputLabel?.innerText);
  if (validation.valid) {
    clearFieldState(field, "name");
    field.value = validation.value;
    return;
  }
  showFieldState(field, "name", validation.error);
}

/**
 * Validate a URL field and render the result.
 *
 * @param {HTMLInputElement} field - URL input to validate.
 * @returns {void}
 */
function validateUrlField(field) {
  const inputLabel = field.parentNode?.querySelector(
    `label[for="${field.id}"]`,
  );
  const validation = validateUrl(field.value, inputLabel?.innerText);
  if (validation.valid) {
    clearFieldState(field, "url");
    field.value = validation.value;
    return;
  }
  showFieldState(field, "url", validation.error);
}

/**
 * Decide whether a blur should validate.
 *
 * Empty fields stay silent until the user typed into them, or until a submit
 * attempt reported them.
 *
 * @param {HTMLInputElement} field - Field that lost focus.
 * @returns {boolean} True when the field should be validated.
 */
function shouldValidateOnBlur(field) {
  if (field.value.trim() !== "") {
    return true;
  }
  return field.hasAttribute(TOUCHED_ATTRIBUTE);
}

/**
 * Focus the first invalid field of a submit attempt.
 *
 * The browser fires one `invalid` event per control in the same task, so a
 * zero-delay reset keeps the focus on the first one.
 *
 * @param {HTMLInputElement} field - Invalid field.
 * @param {() => void} release - Callback that clears the pending state.
 * @returns {void}
 */
function focusFirstInvalid(field, release) {
  field.focus();
  setTimeout(release, 0);
}

export const setupFormValidation = function () {
  // Add validation to all forms on the page
  const forms = document.querySelectorAll("form");

  forms.forEach((form) => {
    // Target only the actual technical name inputs (avoid matching displayName)
    const nameFields = Array.from(
      form.querySelectorAll(NAME_FIELD_SELECTOR),
    ).filter(isNameField);

    nameFields.forEach((field) => {
      const markTouched = () => field.setAttribute(TOUCHED_ATTRIBUTE, "true");
      field.addEventListener("input", markTouched);
      field.addEventListener("change", markTouched);
      field.addEventListener("blur", () => {
        if (!shouldValidateOnBlur(field)) {
          clearFieldState(field, "name");
          return;
        }
        validateNameField(field);
      });
    });

    // Add validation to URL fields
    form.querySelectorAll(URL_FIELD_SELECTOR).forEach((field) => {
      const markTouched = () => field.setAttribute(TOUCHED_ATTRIBUTE, "true");
      field.addEventListener("input", markTouched);
      field.addEventListener("change", markTouched);
      field.addEventListener("blur", () => {
        // Empty optional URL fields never show a message.
        if (!field.value.trim() && !field.required) {
          clearFieldState(field, "url");
          return;
        }
        if (!shouldValidateOnBlur(field)) {
          clearFieldState(field, "url");
          return;
        }
        validateUrlField(field);
      });
    });

    // Replace the native "please fill out this field" bubble with the inline
    // message for the fields above. Other controls keep the browser default.
    let focusPending = false;
    form.addEventListener(
      "invalid",
      (event) => {
        const field = event.target;
        const nameField = isNameField(field);
        if (!nameField && !isUrlField(field)) {
          return;
        }
        event.preventDefault();
        field.setAttribute(TOUCHED_ATTRIBUTE, "true");
        if (nameField) {
          validateNameField(field);
        } else {
          validateUrlField(field);
        }
        if (!focusPending) {
          focusPending = true;
          focusFirstInvalid(field, () => {
            focusPending = false;
          });
        }
      },
      true,
    );
  });
};
