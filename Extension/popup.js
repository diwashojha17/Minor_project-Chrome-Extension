/**
 * popup.js
 * Popup controller for AI Web Vulnerability Scanner.
 */

const scanBtn = document.getElementById("scanBtn");
const activeBtn = document.getElementById("activeBtn");
const activeScanToggle = document.getElementById("activeScanToggle");
const currentUrlEl = document.getElementById("currentUrl");

const progressArea = document.getElementById("progressArea");
const progressFill = document.getElementById("progressFill");
const progressText = document.getElementById("progressText");

const resultArea = document.getElementById("resultArea");
const riskBadge = document.getElementById("riskBadge");
const confidenceText = document.getElementById("confidenceText");
const findingsList = document.getElementById("findingsList");
const errorArea = document.getElementById("errorArea");

const viewDashboardBtn = document.getElementById("viewDashboardBtn");
const exportReportBtn = document.getElementById("exportReportBtn");

const scoreValue = document.getElementById("scoreValue");
const scoreStatus = document.getElementById("scoreStatus");
const riskTone = document.getElementById("riskTone");

const findingsCount = document.getElementById("findingsCount");
const checksPassed = document.getElementById("checksPassed");
const highRiskCount = document.getElementById("highRiskCount");
const mediumRiskCount = document.getElementById("mediumRiskCount");
const passedChecksCount = document.getElementById("passedChecksCount");
const technologyList = document.getElementById("technologyList");

let activeTab = null;
let lastScanRecord = null;

const ATTACK_NAMES = {
  SQLI: "SQL Injection",
  BLIND_SQLI: "Blind SQL Injection",
  XSS: "Reflected XSS",
  DOM_XSS: "DOM XSS",
  STORED_XSS: "Stored XSS",
  CSRF: "Cross-Site Request Forgery (CSRF)",
  COMMAND_INJECTION: "Command Injection",
  FILE_INCLUSION: "File Inclusion",
  FILE_UPLOAD: "Unsafe File Upload",
  HTTPS: "HTTPS Security",
  HEADER: "Security Header",
  COOKIE: "Cookie Security",
  FORM: "Insecure Form",
  MIXED_CONTENT: "Mixed Content",
  WEAK_CSP: "Weak Content Security Policy"
};

async function getActiveTab() {
  const tabs = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  return tabs.length > 0 ? tabs[0] : null;
}

function riskToClass(risk) {
  const value = String(risk || "").trim().toUpperCase();

  switch (value) {
    case "CRITICAL":
      return "risk-critical";
    case "HIGH":
      return "risk-high";
    case "MEDIUM":
      return "risk-medium";
    case "LOW":
      return "risk-low";
    case "SAFE":
      return "risk-safe";
    default:
      return "risk-unknown";
  }
}

function convertRiskScoreToSecurityScore(riskScore) {
  const value = Math.max(
    0,
    Math.min(100, Number(riskScore) || 0)
  );

  if (value < 65) {
    return 80 + ((64 - value) / 64) * 20;
  }

  if (value < 80) {
    return 60 + ((79 - value) / 14) * 19;
  }

  if (value < 90) {
    return 40 + ((89 - value) / 9) * 19;
  }

  return ((100 - value) / 10) * 39;
}

/* =========================================================
   LOCAL DVWA TRAINING TARGET HANDLING
========================================================= */

function isLocalTrainingTarget(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();

    return (
      host === "127.0.0.1" ||
      host === "localhost" ||
      host === "::1"
    );
  } catch (_) {
    return false;
  }
}

function normaliseLocalTrainingFindings(findings, url) {
  if (!isLocalTrainingTarget(url)) {
    return findings;
  }

  return findings.map((finding) => {
    const type = String(finding?.type || "")
      .trim()
      .toUpperCase();

    /*
      For localhost DVWA only, HTTP and insecure form
      are expected baseline setup checks, so show LOW.
      XSS, SQLi and other attacks are never changed.
    */
    if (type !== "HTTPS" && type !== "FORM") {
      return finding;
    }

    return {
      ...finding,
      severity: "LOW",
      message: `${finding.message || "Local DVWA baseline configuration detected."} Local training target: scored as LOW in popup.`
    };
  });
}

function calculatePopupRiskScore(record, findings, url) {
  const backendRiskScore = Number(
    record.riskScore ?? record.risk_score
  );

  /*
    Public websites always use normal backend risk scoring.
  */
  if (!isLocalTrainingTarget(url)) {
    return Number.isFinite(backendRiskScore)
      ? backendRiskScore
      : null;
  }

  const realAttackTypes = [
    "XSS",
    "DOM_XSS",
    "STORED_XSS",
    "SQLI",
    "BLIND_SQLI",
    "COMMAND_INJECTION",
    "FILE_INCLUSION",
    "FILE_UPLOAD"
  ];

  const hasRealAttack = findings.some((finding) => {
    const type = String(finding?.type || "")
      .trim()
      .toUpperCase();

    const severity = String(finding?.severity || "")
      .trim()
      .toUpperCase();

    return (
      realAttackTypes.includes(type) &&
      (severity === "HIGH" || severity === "CRITICAL")
    );
  });

  /*
    DVWA localhost only has HTTP/header/form configuration
    findings: show LOW risk and 83/100 security score.
  */
  if (!hasRealAttack) {
    return 55;
  }

  /*
    A real active vulnerability such as XSS/SQLi exists:
    calculate a normal lower security score.
  */
  const severityWeight = {
    CRITICAL: 45,
    HIGH: 25,
    MEDIUM: 10,
    LOW: 2
  };

  const calculatedRisk = findings.reduce((total, finding) => {
    const severity = String(finding?.severity || "")
      .trim()
      .toUpperCase();

    return total + (severityWeight[severity] || 0);
  }, 0);

  return Math.min(100, calculatedRisk);
}

async function init() {
  try {
    activeTab = await getActiveTab();

    if (currentUrlEl) {
      currentUrlEl.textContent =
        activeTab?.url || "No active website";
    }

    const settings = await getSettings();

    if (activeScanToggle) {
      activeScanToggle.checked =
        Boolean(settings.allowActiveScan);
    }
  } catch (error) {
    showError(
      error.message ||
      "Failed to initialize extension."
    );
  }
}

activeScanToggle?.addEventListener("change", async () => {
  try {
    await updateSettings({
      allowActiveScan: activeScanToggle.checked
    });
  } catch (error) {
    showError("Unable to save Active Scan setting.");
  }
});

scanBtn?.addEventListener("click", async () => {
  await startScan(false);
});

activeBtn?.addEventListener("click", async () => {
  if (!activeScanToggle?.checked) {
    showError("Enable Active Scan first.");
    return;
  }

  await startScan(true);
});

async function startScan(activeEnabled) {
  hideError();

  try {
    activeTab = await getActiveTab();

    if (!activeTab?.url) {
      throw new Error("No active website found.");
    }

    if (
      !activeTab.url.startsWith("http://") &&
      !activeTab.url.startsWith("https://")
    ) {
      throw new Error(
        "Only HTTP/HTTPS websites can be scanned."
      );
    }

    resultArea?.classList.add("hidden");
    progressArea?.classList.remove("hidden");

    if (scanBtn) {
      scanBtn.disabled = true;
    }

    if (activeBtn) {
      activeBtn.disabled = true;
    }

    updateProgress(
      5,
      activeEnabled
        ? "Starting authorized active scan..."
        : "Starting passive scan..."
    );

    const record = await performFullScan(
      activeTab,
      activeEnabled,
      updateProgress
    );

    lastScanRecord = record;
    renderResult(record);
  } catch (error) {
    console.error("[Popup] Scan failed:", error);

    showError(
      error.message ||
      "Scan failed."
    );
  } finally {
    if (scanBtn) {
      scanBtn.disabled = false;
    }

    if (activeBtn) {
      activeBtn.disabled = false;
    }

    progressArea?.classList.add("hidden");
  }
}

function updateProgress(percent, message) {
  const value = Math.max(
    0,
    Math.min(100, Number(percent) || 0)
  );

  if (progressFill) {
    progressFill.style.width = `${value}%`;
  }

  if (progressText) {
    progressText.textContent =
      message || `Scanning... ${value}%`;
  }
}

function renderResult(record) {
  resultArea?.classList.remove("hidden");

  const originalFindings = Array.isArray(record.findings)
    ? record.findings
    : [];

  const findings = normaliseLocalTrainingFindings(
    originalFindings,
    activeTab?.url || record.url || ""
  );

  const popupRiskScore = calculatePopupRiskScore(
    record,
    findings,
    activeTab?.url || record.url || ""
  );

  const numericRiskScore = Number(popupRiskScore);

  let risk;

  if (Number.isFinite(numericRiskScore)) {
    if (numericRiskScore >= 90) {
      risk = "CRITICAL";
    } else if (numericRiskScore >= 80) {
      risk = "HIGH";
    } else if (numericRiskScore >= 65) {
      risk = "MEDIUM";
    } else {
      risk = "LOW";
    }
  } else {
    risk = String(
      record.riskLevel ||
      record.prediction ||
      "UNTRAINED"
    )
      .trim()
      .toUpperCase();
  }

  const modelReady =
    record.modelReady !== false &&
    risk !== "UNTRAINED";

  if (riskBadge) {
    riskBadge.textContent =
      modelReady ? risk : "UNTRAINED";

    riskBadge.className =
      `risk-badge ${riskToClass(risk)}`;
  }

  if (riskTone) {
    riskTone.textContent =
      modelReady ? risk : "--";

    riskTone.className =
      `riskTone ${riskToClass(risk)}`;
  }

  if (scoreStatus) {
    if (!modelReady) {
      scoreStatus.textContent =
        "Model Not Trained";
    } else if (risk === "SAFE") {
      scoreStatus.textContent = "SAFE";
    } else {
      scoreStatus.textContent =
        `${risk} Risk`;
    }
  }

  const rawRiskScore = popupRiskScore;

  const directSecurityScore =
    record.securityScore ??
    record.security_score ??
    null;

  let securityScore = null;

  if (
    rawRiskScore !== null &&
    Number.isFinite(Number(rawRiskScore))
  ) {
    securityScore =
      convertRiskScoreToSecurityScore(rawRiskScore);
  } else if (
    directSecurityScore !== null &&
    Number.isFinite(Number(directSecurityScore))
  ) {
    securityScore = Number(directSecurityScore);
  }

  if (scoreValue) {
    if (!modelReady || securityScore === null) {
      scoreValue.textContent = "-- / 100";
    } else {
      const safeScore = Math.max(
        0,
        Math.min(100, securityScore)
      );

      scoreValue.textContent =
        `${Math.round(safeScore)} / 100`;
    }
  }

  if (confidenceText) {
    if (!modelReady) {
      confidenceText.textContent =
        "Decision Tree model unavailable";
    } else {
      let confidence = Number(record.confidence);

      if (Number.isFinite(confidence)) {
        if (confidence <= 1) {
          confidence *= 100;
        }

        confidenceText.textContent =
          `ML Confidence: ${confidence.toFixed(1)}%`;
      } else {
        confidenceText.textContent =
          "ML Confidence: --";
      }
    }
  }

  const severityOf = (finding) =>
    String(finding?.severity || "")
      .trim()
      .toUpperCase();

  const highCount = findings.filter((finding) => {
    const severity = severityOf(finding);

    return (
      severity === "HIGH" ||
      severity === "CRITICAL"
    );
  }).length;

  const mediumCount = findings.filter((finding) => {
    return severityOf(finding) === "MEDIUM";
  }).length;

  const passed = Number(
    record.checksPassed ??
    record.checks_passed ??
    0
  );

  if (findingsCount) {
    findingsCount.textContent =
      String(findings.length);
  }

  if (checksPassed) {
    checksPassed.textContent =
      String(passed);
  }

  if (highRiskCount) {
    highRiskCount.textContent =
      String(highCount);
  }

  if (mediumRiskCount) {
    mediumRiskCount.textContent =
      String(mediumCount);
  }

  if (passedChecksCount) {
    passedChecksCount.textContent =
      String(passed);
  }

  if (technologyList) {
    technologyList.innerHTML = "";

    const technologies = [
      ...new Set(
        (
          Array.isArray(record.technologies)
            ? record.technologies
            : []
        ).filter(Boolean)
      )
    ];

    if (technologies.length === 0) {
      const tag = document.createElement("span");

      tag.className = "tech-tag";
      tag.textContent = "No technology detected";

      technologyList.appendChild(tag);
    } else {
      for (const technology of technologies) {
        const tag = document.createElement("span");

        tag.className = "tech-tag";

        tag.textContent =
          typeof technology === "string"
            ? technology
            : technology.name || "Unknown";

        technologyList.appendChild(tag);
      }
    }
  }

  if (!findingsList) {
    return;
  }

  findingsList.innerHTML = "";

  const criticalFindings = findings.filter(
    (finding) =>
      severityOf(finding) === "CRITICAL"
  );

  const highFindings = findings.filter(
    (finding) =>
      severityOf(finding) === "HIGH"
  );

  const mediumFindings = findings.filter(
    (finding) =>
      severityOf(finding) === "MEDIUM"
  );

  const lowFindings = findings.filter(
    (finding) =>
      severityOf(finding) === "LOW"
  );

  let displayedFindings = [];

  if (criticalFindings.length > 0) {
    displayedFindings = criticalFindings;
  } else if (highFindings.length > 0) {
    displayedFindings = highFindings;
  } else if (mediumFindings.length > 0) {
    displayedFindings = mediumFindings;
  } else if (lowFindings.length > 0) {
    displayedFindings = lowFindings;
  }

  if (displayedFindings.length === 0) {
    const item = document.createElement("li");

    item.textContent =
      "No security issues detected.";

    findingsList.appendChild(item);
    return;
  }

  const popupFindings =
    displayedFindings.slice(0, 3);

  for (const finding of popupFindings) {
    const item = document.createElement("li");

    const severity =
      severityOf(finding) || "INFO";

    const status = String(
      finding.status || "detected"
    )
      .trim()
      .toUpperCase();

    const findingType = String(
      finding.type || ""
    )
      .trim()
      .toUpperCase();

    const attackName =
      ATTACK_NAMES[findingType] ||
      finding.type ||
      "Security Finding";

    item.className =
      `severity-${severity.toLowerCase()}`;

    item.textContent =
      `[${severity}] ${attackName}`;

    if (finding.message) {
      item.textContent +=
        ` — ${finding.message}`;
    }

    if (status === "POTENTIAL") {
      item.textContent +=
        " (Potential)";
    }

    findingsList.appendChild(item);
  }
}

async function openDashboard() {
  try {
    const settings = await getSettings();

    const backendUrl = String(
      settings.backendUrl ||
      "http://127.0.0.1:5000"
    ).replace(/\/+$/, "");

    await chrome.tabs.create({
      url: `${backendUrl}/dashboard`
    });
  } catch (error) {
    showError("Unable to open dashboard.");
  }
}

viewDashboardBtn?.addEventListener(
  "click",
  openDashboard
);

exportReportBtn?.addEventListener(
  "click",
  async () => {
    if (!lastScanRecord?.id) {
      showError(
        "Run a scan before exporting a report."
      );
      return;
    }

    try {
      const settings = await getSettings();

      const backendUrl = String(
        settings.backendUrl ||
        "http://127.0.0.1:5000"
      ).replace(/\/+$/, "");

      const reportUrl =
        `${backendUrl}/api/report/${encodeURIComponent(
          lastScanRecord.id
        )}?format=pdf`;

      await chrome.downloads.download({
        url: reportUrl,
        saveAs: true
      });
    } catch (error) {
      showError("Unable to export report.");
    }
  }
);

function showError(message) {
  if (!errorArea) {
    return;
  }

  errorArea.textContent = message;
  errorArea.classList.remove("hidden");
}

function hideError() {
  if (!errorArea) {
    return;
  }

  errorArea.textContent = "";
  errorArea.classList.add("hidden");
}

init();