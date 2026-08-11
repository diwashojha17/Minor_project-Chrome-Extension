/**
 * filters.js
 * Handles the search box and severity dropdown filtering of the currently
 * loaded scan history / vulnerabilities tables.
 */

function applyFilters() {
  const searchInput = document.getElementById("searchInput");
  const historySearchInput = document.getElementById("historySearchInput");
  const severityFilter = document.getElementById("severityFilter");
  const statusFilter = document.getElementById("statusFilter");

  if (!searchInput || !severityFilter || !statusFilter) {
    return;
  }

  const searchTerms = [searchInput.value, historySearchInput?.value]
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const severity = severityFilter.value;
  const status = statusFilter.value;

  const filteredScans = currentScans.filter((scan) => {
    const scanUrl = `${scan.url || ""}`.toLowerCase();
    const matchesSearch = !searchTerms.length || searchTerms.some((term) => scanUrl.includes(term));
    return matchesSearch;
  });

  renderHistoryTable(filteredScans);
  renderVulnerabilityTable(filteredScans, severity, status, searchTerms.join(" "));
  renderFilteredDashboard(filteredScans);
}

function initFilters() {
  const searchInput = document.getElementById("searchInput");
  const historySearchInput = document.getElementById("historySearchInput");
  const severityFilter = document.getElementById("severityFilter");
  const statusFilter = document.getElementById("statusFilter");

  if (!searchInput || !severityFilter || !statusFilter) {
    return;
  }

  searchInput.addEventListener("input", debounceFilter(applyFilters, 250));
  historySearchInput?.addEventListener("input", debounceFilter(applyFilters, 250));
  severityFilter.addEventListener("change", applyFilters);
  statusFilter.addEventListener("change", applyFilters);
}

function debounceFilter(fn, delay) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}
