/**
 * charts.js
 * Builds and updates the Chart.js visualizations on the dashboard:
 * risk distribution (doughnut), risk trend (line), findings by severity
 * (bar), and missing header coverage (bar).
 */

let riskDistributionChartInstance = null;
let riskTrendChartInstance = null;
let severityChartInstance = null;

const RISK_TIER_COLORS = {
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#22c55e"
};

const RISK_TIER_LABELS = {
  high: "High Risk (Critical / High Severity)",
  medium: "Medium Risk (Moderate Findings)",
  low: "Low Risk (Minor Findings)"
};

const SEVERITY_COLORS = {
  critical: "#dc2626",
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#22c55e"
};

/**
 * Classifies a single scan into a risk tier (high/medium/low) based on the
 * severities of its findings.
 */
function classifyScanRisk(scan) {
  const findings = parseScanFindings(scan);
  let hasHigh = false;
  let hasMedium = false;

  findings.forEach((f) => {
    const severity = (f && f.severity) || "";
    if (severity === "critical" || severity === "high") hasHigh = true;
    if (severity === "medium") hasMedium = true;
  });

  if (hasHigh) return "high";
  if (hasMedium) return "medium";
  return "low";
}

const centerTextPlugin = {
  id: "centerText",
  afterDraw(chart) {
    if (chart.config.type !== "doughnut" || !chart.config._centerText) return;
    const { ctx, chartArea } = chart;
    const { value, label } = chart.config._centerText;
    const cx = (chartArea.left + chartArea.right) / 2;
    const cy = (chartArea.top + chartArea.bottom) / 2;

    ctx.save();
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle = getComputedTextColor();
    ctx.font = "700 26px Inter, sans-serif";
    ctx.fillText(value, cx, cy - 8);
    ctx.font = "600 10px Inter, sans-serif";
    ctx.fillStyle = getComputedDimColor();
    ctx.fillText(label, cx, cy + 14);
    ctx.restore();
  }
};

function renderRiskDistributionChart(scans) {
  const canvas = document.getElementById("riskDistributionChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const counts = { high: 0, medium: 0, low: 0 };
  scans.forEach((scan) => {
    counts[classifyScanRisk(scan)] += 1;
  });

  const tiers = ["high", "medium", "low"];
  const data = tiers.map((t) => counts[t]);
  const colors = tiers.map((t) => RISK_TIER_COLORS[t]);
  const total = data.reduce((sum, v) => sum + v, 0);

  if (riskDistributionChartInstance) riskDistributionChartInstance.destroy();

  riskDistributionChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: tiers.map((t) => RISK_TIER_LABELS[t]),
      datasets: [{ data, backgroundColor: colors, borderWidth: 0, cutout: "72%" }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (context) => {
              const value = context.parsed || 0;
              const pct = total ? ((value / total) * 100).toFixed(1) : 0;
              return `${context.label}: ${value} scan(s) (${pct}%)`;
            }
          }
        }
      },
      onClick: (evt, elements) => {
        if (!elements.length) return;
        const tier = tiers[elements[0].index];
        const severityMap = { high: "high", medium: "medium", low: "low" };
        const select = document.getElementById("severityFilter");
        if (select) {
          select.value = severityMap[tier] || "";
          applyFilters();
        }
      }
    },
    plugins: [centerTextPlugin]
  });
  riskDistributionChartInstance.config._centerText = { value: String(total), label: "Total" };
  riskDistributionChartInstance.update();

  renderRiskDistributionLegend(tiers, data, colors, total);
}

function renderRiskDistributionLegend(tiers, data, colors, total) {
  const legend = document.getElementById("riskDistributionLegend");
  if (!legend) return;
  legend.innerHTML = "";

  tiers.forEach((tier, i) => {
    const pct = total ? Math.round((data[i] / total) * 100) : 0;
    const row = document.createElement("div");
    row.className = "legend-item clickable";
    row.setAttribute("data-tier", tier);
    row.setAttribute("title", `Click to view ${RISK_TIER_LABELS[tier]} findings`);
    row.innerHTML = `
      <span class="name"><span class="swatch" style="background:${colors[i]}"></span>${RISK_TIER_LABELS[tier]}</span>
      <span class="value">${data[i]} (${pct}%)</span>
    `;
    row.addEventListener("click", () => {
      const select = document.getElementById("severityFilter");
      if (select) {
        select.value = tier;
        applyFilters();
      }
      activateSection("vulnerabilities");
    });
    legend.appendChild(row);
  });
}

function renderRiskTrendChart(scans) {
  const canvas = document.getElementById("riskTrendChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const uniqueDates = [...new Set(
    scans
      .filter((scan) => scan.timestamp)
      .map((scan) => new Date(scan.timestamp).toISOString().slice(0, 10))
  )].sort();

  const days = uniqueDates.map((dateString) => new Date(`${dateString}T12:00:00Z`));
  const dayKey = (d) => d.toISOString().slice(0, 10);
  const dayLabel = (d) => d.toLocaleDateString(undefined, { month: "short", day: "numeric" });

  const buckets = {};
  days.forEach((d) => {
    buckets[dayKey(d)] = { high: 0, medium: 0, low: 0 };
  });

  scans.forEach((scan) => {
    if (!scan.timestamp) return;
    const key = new Date(scan.timestamp).toISOString().slice(0, 10);
    if (!buckets[key]) return;
    parseScanFindings(scan).forEach((f) => {
      const severity = (f && f.severity) || "";
      if (severity === "critical" || severity === "high") buckets[key].high += 1;
      else if (severity === "medium") buckets[key].medium += 1;
      else if (severity === "low") buckets[key].low += 1;
    });
  });

  const labels = days.map(dayLabel);
  const highData = days.map((d) => buckets[dayKey(d)].high);
  const mediumData = days.map((d) => buckets[dayKey(d)].medium);
  const lowData = days.map((d) => buckets[dayKey(d)].low);

  if (riskTrendChartInstance) riskTrendChartInstance.destroy();

  riskTrendChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "High Risk", data: highData, borderColor: RISK_TIER_COLORS.high, backgroundColor: "transparent", tension: 0.35, pointRadius: 3 },
        { label: "Medium Risk", data: mediumData, borderColor: RISK_TIER_COLORS.medium, backgroundColor: "transparent", tension: 0.35, pointRadius: 3 },
        { label: "Low Risk", data: lowData, borderColor: RISK_TIER_COLORS.low, backgroundColor: "transparent", tension: 0.35, pointRadius: 3 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "top", align: "end", labels: { color: getComputedTextColor(), boxWidth: 10, font: { size: 11 } } }
      },
      scales: {
        x: { ticks: { color: getComputedDimColor() }, grid: { display: false } },
        y: { ticks: { color: getComputedDimColor() }, beginAtZero: true, grid: { color: "rgba(148,163,184,0.1)" } }
      }
    }
  });
}

function renderSeverityChart(bySeverity) {
  const canvas = document.getElementById("severityChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const order = ["critical", "high", "medium", "low"];
  const labels = order.filter((s) => bySeverity[s] !== undefined);
  const data = labels.map((s) => bySeverity[s]);
  const colors = labels.map((s) => SEVERITY_COLORS[s]);

  if (severityChartInstance) severityChartInstance.destroy();

  severityChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels.map((l) => l.charAt(0).toUpperCase() + l.slice(1)),
      datasets: [{ label: "Findings", data, backgroundColor: colors, borderRadius: 6 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (context) => `${context.dataset.label}: ${context.parsed.y || context.parsed}`
          }
        }
      },
      onClick: (evt, elements) => {
        if (!elements.length) return;
        const index = elements[0].index;
        const severity = labels[index];
        const select = document.getElementById("severityFilter");
        if (select) {
          select.value = severity;
          applyFilters();
        }
      },
      scales: {
        x: { ticks: { color: getComputedDimColor() }, grid: { display: false } },
        y: { ticks: { color: getComputedDimColor() }, beginAtZero: true, grid: { color: "rgba(148,163,184,0.1)" } }
      }
    }
  });
}

function getComputedTextColor() {
  return getComputedStyle(document.body).getPropertyValue("--text-main").trim() || "#f1f5f9";
}

function getComputedDimColor() {
  return getComputedStyle(document.body).getPropertyValue("--text-dim").trim() || "#8a97ac";
}
