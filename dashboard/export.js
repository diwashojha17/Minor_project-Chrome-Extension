/**
 * export.js
 * Wires the "Export CSV" button to trigger a download of the full scan
 * history via the backend's /api/report/history/csv endpoint.
 */

function initExport() {
  document.getElementById("exportCsvBtn").addEventListener("click", () => {
    window.open("/api/report/history/csv", "_blank");
  });
}
