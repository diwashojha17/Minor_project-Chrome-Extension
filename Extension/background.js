/**
 * background.js
 * Manifest V3 service worker. Handles installation setup, header inspection
 * via webRequest, and message routing between popup/content scripts.
 */

// Cache of response headers keyed by tab id, populated via webRequest listener.
// Content scripts cannot see response headers directly, so background captures them.
const tabHeaderCache = {};

chrome.runtime.onInstalled.addListener(() => {
  console.log("[AI Vulnerability Scanner] Extension installed.");
  chrome.storage.local.get("scanner_settings", (data) => {
    if (!data.scanner_settings) {
      chrome.storage.local.set({
        scanner_settings: {
          backendUrl: "http://127.0.0.1:5000",
          allowActiveScan: false,
          theme: "dark"
        }
      });
    }
  });
});

// Capture response headers for security header analysis (CSP, HSTS, X-Frame-Options, etc.)
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === "main_frame") {
      const headers = {};
      (details.responseHeaders || []).forEach((h) => {
        headers[h.name.toLowerCase()] = h.value;
      });
      tabHeaderCache[details.tabId] = {
        url: details.url,
        status: details.statusCode,
        headers
      };
    }
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["responseHeaders"]
);

// Message router: popup/content scripts request cached headers or trigger actions.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_CACHED_HEADERS") {
    const tabId = message.tabId;
    sendResponse(tabHeaderCache[tabId] || null);
    return true;
  }

  if (message.type === "GET_COOKIES_FOR_URL") {
    chrome.cookies.getAll({ url: message.url }, (cookies) => {
      sendResponse(cookies);
    });
    return true; // keep channel open for async response
  }

  return false;
});

// Clean up cache when a tab is closed to avoid unbounded memory growth.
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabHeaderCache[tabId];
});
