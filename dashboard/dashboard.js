/**
 * dashboard.js
 * Main controller: fetches data from the Flask backend API, renders stat
 * cards, charts, tables, top findings, and recommendations, and wires up
 * navigation, theme toggling, filters, clock, and export actions.
 */

const RECOMMENDATION_MAP = {
  HTTPS: "Migrate the site to HTTPS using a valid TLS certificate and redirect all HTTP traffic.",
  HEADER: "Add missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
  COOKIE: "Set Secure, HttpOnly, and SameSite attributes on all session cookies.",
  MIXED_CONTENT: "Update all resource references to use HTTPS URLs.",
  FORM: "Ensure all forms, especially those with password fields, submit over HTTPS.",
  EXPOSED_PATH: "Restrict public access to sensitive directories (.git, .env, backups).",
  XSS: "Sanitize and encode all user-supplied input before rendering it in HTML.",
  SQLI: "Use parameterized queries for all database access.",
  OPEN_REDIRECT: "Validate redirect destinations against an allow-list."
};

function explainSeverity(severity) {
  const normalized = `${severity || ""}`.toLowerCase();
  if (normalized === "critical") {
    return "This is shown as a failure because the issue is critical and must be fixed immediately.";
  }
  if (normalized === "high") {
    return "This is shown as a failure because the issue is high severity and exposes serious risk.";
  }
  if (normalized === "medium") {
    return "This is shown as a warning because it is a medium-severity issue: it is important, but not immediately critical.";
  }
  if (normalized === "low") {
    return "This is shown as a pass/notice because it is a low-severity issue and usually a minor improvement.";
  }
  return "This issue is categorized by its severity level so the site owner can prioritize the most urgent fixes first.";
}

function buildRecommendationText(finding) {
  const base = RECOMMENDATION_MAP[finding.type] || "Review this finding and apply the recommended remediation.";
  return `${base} ${explainSeverity(finding.severity)}`;
}

async function loadDashboard() {
  try {
    const historyRes = await fetch("/api/scan/history?limit=200");
    const historyData = await historyRes.json();
    currentScans = (historyData.scans || []).slice().sort(
      (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
    );

    const targetSite = getDashboardTargetSite() || currentScans[0]?.url || "";
    setActiveSiteLabel(targetSite);

    let siteScopedScans = currentScans;
    if (targetSite) {
      siteScopedScans = currentScans.filter((scan) => scanMatchesTargetSite(scan, targetSite));
    }

    currentScans = siteScopedScans.length ? [siteScopedScans[0]] : [];

    renderDashboardStats({}, currentScans);
    renderRecommendations(currentScans);
    renderRiskDistributionChart(currentScans);
    renderRiskTrendChart(currentScans);
    renderRecentScans(currentScans);
    renderTopFindings(currentScans);
    renderReportSummaries(currentScans);
    renderFilteredDashboard(currentScans);

    applyFilters();
  } catch (e) {
    console.error("Failed to load dashboard data. Is the Flask backend running?", e);
    const main = document.querySelector(".content");
    if (main) {
      main.insertAdjacentHTML(
        "afterbegin",
        `<div class="error-banner">Unable to reach the backend API. Make sure the Flask server (app.py) is running at the configured backend URL.</div>`
      );
    }
  }
}

function getDashboardTargetSite() {
  const params = new URLSearchParams(window.location.search);
  const rawSite = params.get("site") || "";
  const decoded = rawSite ? decodeURIComponent(rawSite) : "";
  return decoded.trim().replace(/\/+$/, "");
}

function setActiveSiteLabel(targetSite) {
  const label = document.getElementById("activeSiteLabel");
  if (!label) return;
  label.textContent = targetSite
    ? `Showing results for: ${targetSite}`
    : "Showing all available scan results";
}

function normalizeDashboardUrl(url) {
  return `${(url || "").trim().replace(/\/+$/, "")}`;
}

function normalizeSiteHost(url) {
  try {
    const parsed = new URL(url);
    let hostname = (parsed.hostname || "").toLowerCase();
    if (hostname.startsWith("www.")) {
      hostname = hostname.slice(4);
    }
    return hostname;
  } catch (e) {
    return normalizeDashboardUrl(url).toLowerCase();
  }
}

function scanMatchesTargetSite(scan, targetSite) {
  if (!targetSite) return true;

  const scanUrl = normalizeDashboardUrl(scan.url);
  const target = normalizeDashboardUrl(targetSite);
  if (!scanUrl) return false;

  const scanHost = normalizeSiteHost(scanUrl);
  const targetHost = normalizeSiteHost(target);
  const sameHost = scanHost === targetHost;
  const hostMatch = scanHost.endsWith(`.${targetHost}`) || targetHost.endsWith(`.${scanHost}`);
  const samePath = scanUrl === target || scanUrl.startsWith(`${target}/`);

  return sameHost || hostMatch || samePath;
}

function parseScanFeatures(scan) {
  const rawFeatures = scan.features || scan.features_json || "{}";
  if (typeof rawFeatures === "string") {
    try {
      return JSON.parse(rawFeatures);
    } catch (e) {
      return {};
    }
  }
  return rawFeatures || {};
}

function parseScanFindings(scan) {
  const rawFindings = scan.findings || scan.findings_json || "[]";
  if (typeof rawFindings === "string") {
    try {
      return JSON.parse(rawFindings);
    } catch (e) {
      return [];
    }
  }
  return Array.isArray(rawFindings) ? rawFindings : [];
}

/* ---------- Stat cards + week-over-week deltas ---------- */

function inLastNDays(scan, n, offset) {
  const now = Date.now();
  const start = now - (n + offset) * 86400000;
  const end = now - offset * 86400000;
  const t = new Date(scan.timestamp).getTime();
  return t >= start && t < end;
}

function formatDelta(recent, previous) {
  if (previous === 0) {
    if (recent === 0) return { text: "No change this week", cls: "flat" };
    return { text: `+${recent} this week`, cls: "up" };
  }
  const pct = Math.round(((recent - previous) / previous) * 100);
  if (pct === 0) return { text: "No change this week", cls: "flat" };
  const arrow = pct > 0 ? "↑" : "↓";
  return { text: `${arrow} ${Math.abs(pct)}% this week`, cls: pct > 0 ? "up" : "down" };
}

function severityTierCount(scans, tier) {
  let count = 0;
  scans.forEach((scan) => {
    parseScanFindings(scan).forEach((f) => {
      const severity = (f && f.severity) || "";
      if (tier === "high" && (severity === "critical" || severity === "high")) count += 1;
      if (tier === "medium" && severity === "medium") count += 1;
      if (tier === "low" && severity === "low") count += 1;
    });
  });
  return count;
}

function renderDashboardStats(stats, scans) {
  const recentScans = scans.filter((s) => inLastNDays(s, 7, 0));
  const previousScans = scans.filter((s) => inLastNDays(s, 7, 7));

  const total = scans.length;
  const totalDelta = formatDelta(recentScans.length, previousScans.length);

  const highNow = severityTierCount(recentScans, "high");
  const highPrev = severityTierCount(previousScans, "high");
  const mediumNow = severityTierCount(recentScans, "medium");
  const mediumPrev = severityTierCount(previousScans, "medium");
  const lowNow = severityTierCount(recentScans, "low");
  const lowPrev = severityTierCount(previousScans, "low");

  const highTotal = severityTierCount(scans, "high");
  const mediumTotal = severityTierCount(scans, "medium");
  const lowTotal = severityTierCount(scans, "low");

  setStat("totalScans", total, totalDelta);
  setStat("highRiskCount", highTotal, formatDelta(highNow, highPrev));
  setStat("mediumRiskCount", mediumTotal, formatDelta(mediumNow, mediumPrev));
  setStat("lowRiskCount", lowTotal, formatDelta(lowNow, lowPrev));
  setStat("reportsGenerated", total, totalDelta);
}

function setStat(prefix, value, delta) {
  const valueEl = document.getElementById(prefix);
  const deltaEl = document.getElementById(`${prefix}Delta`);
  if (valueEl) valueEl.textContent = value;
  if (deltaEl) {
    deltaEl.textContent = delta.text;
    deltaEl.className = `stat-delta ${delta.cls}`;
  }
}

/* ---------- Header coverage ---------- */

function renderHeaderCoverage(headerCoverage) {
  const map = {
    missingCSP: headerCoverage.missingCSP,
    missingHSTS: headerCoverage.missingHSTS,
    missingXFrameOptions: headerCoverage.missingXFrameOptions,
    missingXContentTypeOptions: headerCoverage.missingXContentTypeOptions
  };
  Object.keys(map).forEach((key) => {
    const el = document.getElementById(key);
    if (el) el.textContent = map[key] || 0;
  });
}

function aggregateFilteredMetrics(scans) {
  const bySeverity = {};
  const headerCoverage = {
    missingCSP: 0,
    missingHSTS: 0,
    missingXFrameOptions: 0,
    missingXContentTypeOptions: 0,
    missingAnyHeader: 0
  };

  scans.forEach((scan) => {
    parseScanFindings(scan).forEach((f) => {
      if (!f || !f.severity) return;
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    });

    const features = parseScanFeatures(scan);
    let missingAny = false;

    if (features.csp === 0) { headerCoverage.missingCSP += 1; missingAny = true; }
    if (features.hsts === 0) { headerCoverage.missingHSTS += 1; missingAny = true; }
    if (features.x_frame_options === 0) { headerCoverage.missingXFrameOptions += 1; missingAny = true; }
    if (features.x_content_type_options === 0) { headerCoverage.missingXContentTypeOptions += 1; missingAny = true; }

    if (missingAny) headerCoverage.missingAnyHeader += 1;
  });

  return { bySeverity, headerCoverage };
}

function renderFilteredDashboard(scans) {
  const metrics = aggregateFilteredMetrics(scans);
  renderSeverityChart(metrics.bySeverity);
  renderHeaderCoverageChart(metrics.headerCoverage);
  renderHeaderCoverage(metrics.headerCoverage);
}

function renderHeaderCoverageChart(headerCoverage) {
  const canvas = document.getElementById("headerCoverageChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const labels = ["Missing CSP", "Missing HSTS", "Missing X-Frame-Options", "Missing X-Content-Type-Options"];
  const data = [
    headerCoverage.missingCSP || 0,
    headerCoverage.missingHSTS || 0,
    headerCoverage.missingXFrameOptions || 0,
    headerCoverage.missingXContentTypeOptions || 0
  ];
  const colors = ["#f59e0b", "#ef4444", "#a855f7", "#0ea5e9"];

  if (window.headerCoverageChartInstance) window.headerCoverageChartInstance.destroy();

  window.headerCoverageChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "Missing Header Count", data, backgroundColor: colors, borderRadius: 8, maxBarThickness: 32 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (context) => `${context.parsed.y || context.parsed} missing` } }
      },
      scales: {
        x: { ticks: { color: getComputedDimColor() }, grid: { display: false } },
        y: { ticks: { color: getComputedDimColor() }, beginAtZero: true, grid: { color: "rgba(148,163,184,0.15)" } }
      }
    }
  });
}

/* ---------- Failed scans preview (overview) ---------- */

function renderRecentScans(scans) {
  const tbody = document.getElementById("recentScansBody");
  if (!tbody) return;
  tbody.innerHTML = "";

  const failedScans = scans
    .filter((scan) => {
      const prediction = (scan.prediction || "").toLowerCase();
      return prediction.includes("high") || prediction.includes("medium");
    })
    .slice(0, 5);

  failedScans.forEach((scan) => {
    const prediction = (scan.prediction || "Low Risk").trim();
    const tier = prediction.toLowerCase().includes("high") ? "high" : prediction.toLowerCase().includes("medium") ? "medium" : "low";
    const dateStr = new Date(scan.timestamp).toLocaleString();
    const confidencePct = ((scan.confidence || 0) * 100).toFixed(0) + "%";
    const scanType = scan.active_scan_used ? "Active" : "Passive";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>
        <a class="scan-link" href="/api/report/${scan.id}?format=pdf" target="_blank" rel="noopener noreferrer" title="Open scan details">
          ${escapeHtml(scan.url)}
        </a>
      </td>
      <td><span class="risk-tag ${tier}">${escapeHtml(prediction)}</span></td>
      <td>${confidencePct}</td>
      <td>${scanType}</td>
      <td>${dateStr}</td>
      <td>
        <button class="icon-btn" data-scan-id="${scan.id}" data-action="pdf" title="View PDF">👁</button>
        <button class="icon-btn" data-scan-id="${scan.id}" data-action="csv" title="Download CSV">⭳</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  if (failedScans.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="6">No failed scans found.</td>';
    tbody.appendChild(tr);
  }

  tbody.querySelectorAll("button[data-action]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const scanId = btn.getAttribute("data-scan-id");
      const format = btn.getAttribute("data-action");
      window.open(`/api/report/${scanId}?format=${format}`, "_blank");
    });
  });
}

/* ---------- Top findings ---------- */

function renderTopFindings(scans) {
  const list = document.getElementById("topFindingsList");
  if (!list) return;
  list.innerHTML = "";

  const counts = {};
  scans.forEach((scan) => {
    parseScanFindings(scan).forEach((f) => {
      if (!f || !f.type) return;
      counts[f.type] = (counts[f.type] || 0) + 1;
    });
  });

  const top = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  if (top.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No findings recorded yet.";
    list.appendChild(li);
    return;
  }

  top.forEach(([type, count]) => {
    const label = (typeof VULNERABILITY_LABEL !== "undefined" && VULNERABILITY_LABEL[type]) || type;
    const li = document.createElement("li");
    li.innerHTML = `<span>${escapeHtml(label)}</span><span class="count-pill">${count}</span>`;
    list.appendChild(li);
  });
}

/* ---------- Recommendations ---------- */

function renderRecommendations(recentScans) {
  const seenTypes = new Set();
  const list = document.getElementById("recommendationList");
  if (!list) return;
  list.innerHTML = "";

  recentScans.forEach((scan) => {
    let findings = [];
    try {
      findings = JSON.parse(scan.findings_json || "[]");
    } catch (e) {}
    findings.forEach((f) => {
      if (f.type && !seenTypes.has(f.type)) {
        seenTypes.add(f.type);
        const li = document.createElement("li");
        li.textContent = buildRecommendationText(f);
        list.appendChild(li);
      }
    });
  });

  if (list.children.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No active recommendations — recent scans look clean.";
    list.appendChild(li);
  }
}

/* ---------- Reports / analytics summaries ---------- */

function renderReportSummaries(scans) {
  const summaryEl = document.getElementById("reportsSummaryText");
  if (summaryEl) summaryEl.textContent = `${scans.length} scan${scans.length === 1 ? "" : "s"} tracked`;

  const trendEl = document.getElementById("scanTrendText");
  if (trendEl) {
    const recent = scans.filter((s) => inLastNDays(s, 7, 0)).length;
    const previous = scans.filter((s) => inLastNDays(s, 7, 7)).length;
    const delta = formatDelta(recent, previous);
    trendEl.textContent = delta.text;
  }
}

/* ---------- Navigation ---------- */

function activateSection(target) {
  const sections = document.querySelectorAll(".section");
  document.querySelectorAll(".sidebar-item").forEach((l) => {
    l.classList.toggle("active", l.getAttribute("data-section") === target);
  });
  sections.forEach((s) => s.classList.toggle("hidden", s.id !== target));
  const sidebar = document.getElementById("sidebar");
  if (sidebar) sidebar.classList.remove("open");
}

function initNavigation() {
  const links = document.querySelectorAll(".sidebar-item, [data-section-link]");

  links.forEach((link) => {
    link.addEventListener("click", (e) => {
      const target = link.getAttribute("data-section") || link.getAttribute("data-section-link");
      if (!target) return;
      e.preventDefault();
      activateSection(target);
    });
  });
}

function initThemeToggle() {
  const btn = document.getElementById("themeToggle");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const body = document.body;
    const current = body.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    body.setAttribute("data-theme", next);
    loadDashboard();
  });
}

function initMenuToggle() {
  const btn = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");
  if (!btn || !sidebar) return;
  btn.addEventListener("click", () => sidebar.classList.toggle("open"));
}

function initRefreshButton() {
  const btn = document.getElementById("refreshBtn");
  if (!btn) return;
  btn.addEventListener("click", () => loadDashboard());
}

function initBackToOverviewButton() {
  const btn = document.getElementById("backToOverviewBtn");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const params = new URLSearchParams(window.location.search);
    const site = params.get("site") || "";
    const target = site ? `/dashboard?site=${encodeURIComponent(site)}` : "/dashboard";
    window.location.href = target;
  });
}

function initRiskCardInteractions() {
  document.querySelectorAll(".stat-card[data-risk-tier]").forEach((card) => {
    card.addEventListener("click", () => {
      const tier = card.getAttribute("data-risk-tier") || "";
      const severityFilter = document.getElementById("severityFilter");
      if (severityFilter) {
        severityFilter.value = tier;
        applyFilters();
      }
      activateSection("vulnerabilities");
    });
  });
}

function initExtraExportButton() {
  const pdfBtn = document.getElementById("exportPdfBtn");
  if (pdfBtn) {
    pdfBtn.addEventListener("click", () => {
      const latest = currentScans && currentScans[0];
      if (latest) {
        window.open(`/api/report/${latest.id}?format=pdf`, "_blank");
      }
    });
  }
  const csvBtn2 = document.getElementById("exportCsvBtn2");
  if (csvBtn2) {
    csvBtn2.addEventListener("click", () => {
      window.open("/api/report/history/csv", "_blank");
    });
  }
}

function startClock() {
  const el = document.getElementById("topbarDate");
  if (!el) return;
  const update = () => {
    el.textContent = new Date().toLocaleString(undefined, {
      day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit"
    });
  };
  update();
  setInterval(update, 60000);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initThemeToggle();
  initMenuToggle();
  initRefreshButton();
  initBackToOverviewButton();
  initRiskCardInteractions();
  initExtraExportButton();
  initFilters();
  initExport();
  startClock();
  loadDashboard();
});
