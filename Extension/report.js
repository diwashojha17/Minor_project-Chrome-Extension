/**
 * report.js
 * Client-side helper to request report generation (PDF/CSV) from the backend
 * for a given scan id, and trigger a browser download of the result.
 */

async function downloadReport(scanId, format = "pdf") {
  const settings = await getSettings();
  const endpoint = `${settings.backendUrl}/api/report/${scanId}?format=${format}`;

  const response = await fetch(endpoint);
  if (!response.ok) {
    throw new Error(`Failed to generate report (${response.status})`);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);

  chrome.downloads.download({
    url,
    filename: `vulnscan_report_${scanId}.${format}`,
    saveAs: true
  });
}

if (typeof module !== "undefined") {
  module.exports = { downloadReport };
}
