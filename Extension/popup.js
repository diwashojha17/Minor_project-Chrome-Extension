/**
 * popup.js
 * Main controller for the extension popup UI. Wires button clicks to the
 * scanner pipeline and renders results.
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

let activeTab = null;

async function init() {
  activeTab = await getActiveTab();
  currentUrlEl.textContent = activeTab ? activeTab.url : "No active tab";

  const settings = await getSettings();
  activeScanToggle.checked = !!settings.allowActiveScan;
}

activeScanToggle.addEventListener("change", async () => {
  await updateSettings({ allowActiveScan: activeScanToggle.checked });
});

scanBtn.addEventListener("click", async () => {
  hideError();
  resultArea.classList.add("hidden");
  progressArea.classList.remove("hidden");
  scanBtn.disabled = true;
  activeBtn.disabled = true;

  try {
    const record = await performFullScan(activeTab, activeScanToggle.checked, updateProgress);
    renderResult(record);
  } catch (err) {
    showError(err.message || "Scan failed. Is the backend running?");
  } finally {
    scanBtn.disabled = false;
    activeBtn.disabled = false;
    progressArea.classList.add("hidden");
  }
});

activeBtn.addEventListener("click", async () => {
  hideError();
  resultArea.classList.add("hidden");
  progressArea.classList.remove("hidden");
  scanBtn.disabled = true;
  activeBtn.disabled = true;
  activeScanToggle.checked = true;
  await updateSettings({ allowActiveScan: true });

  try {
    const record = await performFullScan(activeTab, true, updateProgress);
    renderResult(record);
  } catch (err) {
    showError(err.message || "Active scan failed. Is the backend running?");
  } finally {
    scanBtn.disabled = false;
    activeBtn.disabled = false;
    progressArea.classList.add("hidden");
  }
});

viewDashboardBtn.addEventListener("click", () => {
  openDashboard();
});

function updateProgress(percent, label) {
  progressFill.style.width = `${percent}%`;
  progressText.textContent = label;
}

function renderResult(record) {
  resultArea.classList.remove("hidden");

  riskBadge.textContent = record.prediction;
  riskBadge.className = `risk-badge ${riskToClass(record.prediction)}`;
  confidenceText.textContent = `Confidence: ${(record.confidence * 100).toFixed(1)}%`;

  findingsList.innerHTML = "";
  if (record.findings.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No issues detected in this scan.";
    findingsList.appendChild(li);
  } else {
    record.findings.forEach((f) => {
      const li = document.createElement("li");
      li.textContent = f.message;
      li.className = `severity-${f.severity}`;
      findingsList.appendChild(li);
    });
  }
}

function showError(msg) {
  errorArea.textContent = msg;
  errorArea.classList.remove("hidden");
}

function hideError() {
  errorArea.classList.add("hidden");
  errorArea.textContent = "";
}

init();
