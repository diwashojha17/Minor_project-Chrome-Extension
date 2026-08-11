/**
 * dashboardLink.js
 * Opens the full HTML dashboard (served by the Flask backend as a static page,
 * or loaded directly from dashboard/dashboard.html) in a new browser tab.
 */

async function openDashboard() {
  const settings = await getSettings();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const targetUrl = tab && tab.url ? encodeURIComponent(tab.url) : "";
  const dashboardUrl = targetUrl
    ? `${settings.backendUrl}/dashboard?site=${targetUrl}`
    : `${settings.backendUrl}/dashboard`;
  chrome.tabs.create({ url: dashboardUrl });
}

if (typeof module !== "undefined") {
  module.exports = { openDashboard };
}
