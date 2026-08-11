/**
 * storage.js
 * Wraps chrome.storage.local to persist scan history and settings locally,
 * as a fallback / cache alongside the backend SQLite database.
 */

const STORAGE_KEYS = {
  HISTORY: "scan_history",
  SETTINGS: "scanner_settings"
};

/** Save a completed scan result to local history (keeps last 100 entries). */
async function saveScanToHistory(scanResult) {
  const data = await chrome.storage.local.get(STORAGE_KEYS.HISTORY);
  const history = data[STORAGE_KEYS.HISTORY] || [];
  history.unshift(scanResult);
  const trimmed = history.slice(0, 100);
  await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: trimmed });
  return trimmed;
}

/** Retrieve full local scan history. */
async function getScanHistory() {
  const data = await chrome.storage.local.get(STORAGE_KEYS.HISTORY);
  return data[STORAGE_KEYS.HISTORY] || [];
}

/** Clear local scan history. */
async function clearScanHistory() {
  await chrome.storage.local.remove(STORAGE_KEYS.HISTORY);
}

/** Get user settings (backend URL, active scan opt-in, theme, etc.) with defaults. */
async function getSettings() {
  const defaults = {
    backendUrl: "http://127.0.0.1:5000",
    allowActiveScan: false,
    theme: "dark"
  };
  const data = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
  return { ...defaults, ...(data[STORAGE_KEYS.SETTINGS] || {}) };
}

/** Update user settings (merges with existing). */
async function updateSettings(partial) {
  const current = await getSettings();
  const updated = { ...current, ...partial };
  await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: updated });
  return updated;
}

if (typeof module !== "undefined") {
  module.exports = { saveScanToHistory, getScanHistory, clearScanHistory, getSettings, updateSettings };
}
