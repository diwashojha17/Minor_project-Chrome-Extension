/**
 * scanner.js
 * Top-level orchestrator: runs passive scan (always) + active scan (if enabled),
 * extracts ML features, sends them to the backend for classification, and
 * persists the result both locally and to the backend database.
 */

/**
 * Full scan pipeline.
 * @param {object} tab - active browser tab
 * @param {boolean} activeScanEnabled - whether user opted into active scanning
 * @param {function} onProgress - callback(percent:number, label:string)
 */
async function performFullScan(tab, activeScanEnabled, onProgress = () => {}) {
  onProgress(10, "Running passive checks...");
  const passiveResult = await runPassiveScan(tab);

  let activeResult = null;
  if (activeScanEnabled) {
    onProgress(40, "Running active checks (authorized scan)...");
    activeResult = await runActiveScan(tab);
  }

  onProgress(65, "Extracting ML features...");
  const features = extractFeatures(tab, passiveResult, activeResult);

  onProgress(80, "Classifying risk with Decision Tree model...");
  const prediction = await submitScanForPrediction(features);

  const allFindings = [
    ...(passiveResult.findings || []),
    ...((activeResult && activeResult.findings) || [])
  ];

  const scanRecord = {
    id: generateId(),
    url: tab.url,
    title: tab.title || "",
    timestamp: Date.now(),
    activeScanUsed: !!activeScanEnabled,
    features,
    prediction: prediction.label,
    confidence: prediction.confidence,
    findings: allFindings
  };

  onProgress(95, "Saving results to backend...");
  try {
    await saveScanRecord(scanRecord);
  } catch (e) {
    console.warn("Backend save failed (is Flask running?):", e.message);
  }

  onProgress(100, "Done.");
  return scanRecord;
}

if (typeof module !== "undefined") {
  module.exports = { performFullScan };
}
