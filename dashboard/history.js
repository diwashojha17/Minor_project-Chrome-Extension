



/**
 * history.js
 * Renders the scan history table and the vulnerability findings table.
 */

let currentScans = [];

function renderHistoryTable(scans) {
  const tbody = document.getElementById("historyTableBody");
  tbody.innerHTML = "";

  scans.forEach((scan) => {
    const tr = document.createElement("tr");

    const dateStr = new Date(scan.timestamp).toLocaleString();
    const confidencePct = (scan.confidence * 100).toFixed(1) + "%";

    tr.innerHTML = `
      <td>
        <a class="scan-link" href="/api/report/${scan.id}?format=pdf" target="_blank" rel="noopener noreferrer" title="Open scan details">
          ${escapeHtml(scan.url)}
        </a>
      </td>
      <td>${dateStr}</td>
      <td>${escapeHtml(scan.prediction)}</td>
      <td>${confidencePct}</td>
      <td>${scan.active_scan_used ? "Yes" : "No"}</td>
      <td>
        <button class="link-btn" data-scan-id="${scan.id}" data-action="pdf">PDF</button> |
        <button class="link-btn" data-scan-id="${scan.id}" data-action="csv">CSV</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-action]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const scanId = btn.getAttribute("data-scan-id");
      const format = btn.getAttribute("data-action");
      window.open(`/api/report/${scanId}?format=${format}`, "_blank");
    });
  });
}

const VULNERABILITY_CATEGORY = {
  HTTPS: "Transport",
  HEADER: "Headers",
  COOKIE: "Cookies",
  MIXED_CONTENT: "Transport",
  FORM: "Application",
  EXPOSED_PATH: "Data Exposure",
  XSS: "Injection",
  SQLI: "Injection",
  OPEN_REDIRECT: "Redirect",
  GENERAL: "Information Disclosure",
};

const VULNERABILITY_LABEL = {
  HTTPS: "HTTPS Enforcement",
  HEADER: "Missing Security Header",
  COOKIE: "Cookie Security",
  MIXED_CONTENT: "Mixed Content",
  FORM: "Insecure Form",
  EXPOSED_PATH: "Exposed Path",
  XSS: "Cross-Site Scripting",
  SQLI: "SQL Injection",
  OPEN_REDIRECT: "Open Redirect",
};

function mapSeverityToStatus(severity) {
  const normalized = (severity || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "fail";
  if (normalized === "medium") return "warning";
  return "pass";
}

function renderVulnerabilityTable(scans, severityFilterValue = "", statusFilterValue = "", searchTerm = "") {
  const tbody = document.getElementById("vulnTableBody");
  tbody.innerHTML = "";

  scans.forEach((scan) => {
    let findings = [];
    try {
      findings = JSON.parse(scan.findings_json || "[]");
    } catch (e) {
      findings = [];
    }

    findings
      .filter((f) => {
        const severityMatch = !severityFilterValue || f.severity === severityFilterValue;
        const statusMatch = !statusFilterValue || mapSeverityToStatus(f.severity) === statusFilterValue;
        const searchMatch = !searchTerm || (scan.url || "").toLowerCase().includes(searchTerm);
        return severityMatch && statusMatch && searchMatch;
      })
      .forEach((f) => {
        const category = VULNERABILITY_CATEGORY[f.type] || "General";
        const vulnLabel = VULNERABILITY_LABEL[f.type] || f.type || "Finding";
        const status = mapSeverityToStatus(f.severity);

        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${escapeHtml(category)}</td>
          <td>${escapeHtml(vulnLabel)}</td>
          <td><span class="badge ${f.severity}">${f.severity.toUpperCase()}</span></td>
          <td>${escapeHtml(f.message)}</td>
          <td>${escapeHtml(f.recommendation || "Review remediation guidance for this finding.")}</td>
          <td><span class="status-pill ${status}">${status.toUpperCase()}</span></td>
          <td>${escapeHtml(scan.url)}</td>
        `;
        tbody.appendChild(tr);
      });
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}
