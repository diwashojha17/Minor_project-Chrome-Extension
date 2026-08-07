/**
 * utils.js
 * Shared helper functions used across the extension (popup, background, content scripts).
 */

/** Safely parse a URL string, returning null on failure. */
function safeParseUrl(urlString) {
  try {
    return new URL(urlString);
  } catch (e) {
    return null;
  }
}

/** Get the currently active tab in the current window. */
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

/** Debounce helper for expensive operations. */
function debounce(fn, delay) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

/** Format a timestamp into a human-readable string. */
function formatTimestamp(ts) {
  const d = new Date(ts);
  return d.toLocaleString();
}

/** Clamp a number between min and max. */
function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

/** Map a risk label to a CSS class suffix used by badges/list items. */
function riskToClass(riskLabel) {
  const map = {
    "Secure": "secure",
    "Low Risk": "low",
    "Medium Risk": "medium",
    "High Risk": "high",
    "XSS Risk": "high",
    "SQL Injection Risk": "critical",
    "Clickjacking Risk": "medium",
    "Information Disclosure": "medium"
  };
  return map[riskLabel] || "medium";
}

/** Generate a simple unique id (not cryptographically secure, fine for local storage keys). */
function generateId() {
  return `scan_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

// Expose to other scripts loaded via <script> tags (non-module context).
if (typeof module !== "undefined") {
  module.exports = {
    safeParseUrl, getActiveTab, debounce, formatTimestamp, clamp, riskToClass, generateId
  };
}
