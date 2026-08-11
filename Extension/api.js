/**
 * api.js
 * Handles all HTTP communication between the extension and the Flask backend.
 */

/** POST extracted features to backend /api/scan/predict for ML classification. */
async function submitScanForPrediction(features) {
  const settings = await getSettings();
  const endpoint = `${settings.backendUrl}/api/scan/predict`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ features })
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Backend error (${response.status}): ${errText}`);
  }

  return response.json();
}

/** Save a full scan record (url, features, prediction, findings) to backend database. */
async function saveScanRecord(record) {
  const settings = await getSettings();
  const endpoint = `${settings.backendUrl}/api/scan/save`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(record)
  });

  if (!response.ok) {
    throw new Error(`Failed to save scan record: ${response.status}`);
  }

  return response.json();
}

/** Fetch aggregate dashboard stats from backend. */
async function fetchDashboardStats() {
  const settings = await getSettings();
  const endpoint = `${settings.backendUrl}/api/dashboard/stats`;
  const response = await fetch(endpoint);
  if (!response.ok) throw new Error("Failed to fetch dashboard stats");
  return response.json();
}

/** Fetch scan history list from backend (paginated). */
async function fetchScanHistoryFromBackend(limit = 50, offset = 0) {
  const settings = await getSettings();
  const endpoint = `${settings.backendUrl}/api/scan/history?limit=${limit}&offset=${offset}`;
  const response = await fetch(endpoint);
  if (!response.ok) throw new Error("Failed to fetch scan history");
  return response.json();
}

/** Check backend health/availability. */
async function checkBackendHealth() {
  try {
    const settings = await getSettings();
    const response = await fetch(`${settings.backendUrl}/api/health`, { method: "GET" });
    return response.ok;
  } catch (e) {
    return false;
  }
}

if (typeof module !== "undefined") {
  module.exports = {
    submitScanForPrediction, saveScanRecord, fetchDashboardStats,
    fetchScanHistoryFromBackend, checkBackendHealth
  };
}
