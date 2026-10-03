/**
 * Flash Messages
 *
 * Display flash messages carried in the URL query string (?error= / ?success=)
 * in the global notification area, then clean the URL. Extracted from an
 * inline script in admin.html.
 */

import { safeReplaceState } from "./security.js";

/**
 * Read the flash message parameters from a query string.
 * @param {string} search - URL query string, e.g. location.search
 * @returns {{ error: string|null, success: string|null }} Decoded messages
 */
export const getFlashParams = function (search) {
  const urlParams = new URLSearchParams(search);
  const error = urlParams.get("error");
  const success = urlParams.get("success");
  return {
    error: error === null ? null : decodeURIComponent(error),
    success: success === null ? null : decodeURIComponent(success),
  };
};

/**
 * Show the URL flash message, if any, and clean the URL after auto-dismiss.
 */
export const initFlashMessages = function () {
  const { error, success } = getFlashParams(window.location.search);
  if (!error && !success) {
    return;
  }

  const notificationDiv = document.getElementById("global-notification");
  if (!notificationDiv) {
    return;
  }

  const messageDiv = document.createElement("div");
  messageDiv.className = error
    ? "bg-red-50 border border-red-300 text-red-700 px-4 py-3 rounded dark:bg-red-800 dark:border-red-600 dark:text-red-200"
    : "bg-green-50 border border-green-300 text-green-700 px-4 py-3 rounded dark:bg-green-800 dark:border-green-600 dark:text-green-200";
  // textContent keeps URL-supplied content inert
  messageDiv.textContent = `${error ? "❌" : "✅"} ${error || success}`;
  notificationDiv.replaceChildren(messageDiv);
  notificationDiv.style.display = "block";

  // Auto-dismiss after 5 seconds
  setTimeout(() => {
    notificationDiv.style.display = "none";
    notificationDiv.innerHTML = "";

    // Clean up URL by removing the message parameters
    const cleanUrl = new URL(window.location);
    cleanUrl.searchParams.delete("error");
    cleanUrl.searchParams.delete("success");
    safeReplaceState({}, "", cleanUrl);
  }, 5000);
};
