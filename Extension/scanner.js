/**
 * scanner.js
 *
 * Main scanner orchestrator.
 *
 * IMPORTANT:
 * Scanning works even when the Decision Tree
 * has not been trained yet.
 *
 * This allows us to collect real feature data
 * for dataset.csv before training the model.
 */


function generateScanId() {

  if (
    typeof crypto !== "undefined" &&
    crypto.randomUUID
  ) {
    return crypto.randomUUID();
  }

  return (
    `scan_${Date.now()}_${Math.random()
      .toString(36)
      .slice(2, 10)}`
  );
}


/**
 * Run complete scan.
 */
async function performFullScan(
  tab,
  activeScanEnabled,
  onProgress = () => {}
) {

  // ========================================================
  // Validate tab
  // ========================================================

  if (
    !tab?.id ||
    !tab?.url
  ) {

    throw new Error(
      "No valid browser tab selected."
    );
  }


  // ========================================================
  // PASSIVE SCAN
  // ========================================================

  onProgress(
    10,
    "Running passive checks..."
  );


  const passiveResult =
    await runPassiveScan(
      tab
    );


  // ========================================================
  // ACTIVE SCAN
  // ========================================================

  let activeResult = null;


  if (activeScanEnabled) {

    onProgress(
      35,
      "Running authorized active checks..."
    );


    activeResult =
      await runActiveScan(
        tab,
        {
          maxTargetsToTest: 5
        }
      );
  }


  // ========================================================
  // FEATURE EXTRACTION
  // ========================================================

  onProgress(
    65,
    "Extracting security features..."
  );


  const features =
    extractFeatures(
      tab,
      passiveResult,
      activeResult
    );


  console.log(
    "[Scanner] Extracted features:",
    features
  );


  // ========================================================
  // DECISION TREE
  // ========================================================

  onProgress(
    80,
    "Checking Decision Tree model..."
  );


  let prediction = null;

  let modelReady = false;

  let classificationError = null;


  try {

    prediction =
      await submitScanForPrediction(
        features
      );


    modelReady =
      prediction?.modelReady !== false;

  } catch (error) {

    /*
     * This is EXPECTED while we are
     * collecting the training dataset.
     *
     * The scan must continue.
     */

    classificationError =
      error.message ||
      "Model not available";


    console.warn(
      "[Scanner] Decision Tree unavailable:",
      classificationError
    );


    prediction = {
      label: "UNTRAINED",

      confidence: null,

      risk_score: null,

      security_score: null,

      probabilities: {},

      modelReady: false
    };


    modelReady = false;


    onProgress(
      82,
      "Model not trained — saving features for dataset..."
    );
  }


  // ========================================================
  // RISK RESULT
  // ========================================================

  const riskLevel =
    String(
      prediction?.label ??
      prediction?.riskLevel ??
      prediction?.risk_level ??
      "UNTRAINED"
    )
      .trim()
      .toUpperCase();


  const rawRiskScore =
    prediction?.risk_score ??
    prediction?.riskScore ??
    prediction?.score ??
    null;


  const riskScore =
    rawRiskScore !== null &&
    Number.isFinite(
      Number(rawRiskScore)
    )
      ? Number(rawRiskScore)
      : null;


  let securityScore =
    prediction?.security_score ??
    prediction?.securityScore ??
    null;


  if (
    securityScore !== null &&
    Number.isFinite(
      Number(securityScore)
    )
  ) {

    securityScore =
      Number(securityScore);

  } else {

    securityScore = null;
  }


  /*
   * If backend returned only a risk score,
   * derive the security score.
   */

  if (
    securityScore === null &&
    riskScore !== null
  ) {

    securityScore =
      Math.max(
        0,
        Math.min(
          100,
          100 - riskScore
        )
      );
  }


  // ========================================================
  // FINDINGS
  // ========================================================

  const findings = [

    ...(
      passiveResult.findings ||
      []
    ),

    ...(
      activeResult?.findings ||
      []
    )

  ];


  // ========================================================
  // SCAN RECORD
  // ========================================================

  const scanRecord = {

    id:
      generateScanId(),

    url:
      tab.url,

    title:
      tab.title || "",

    timestamp:
      Date.now(),

    activeScanUsed:
      Boolean(
        activeScanEnabled
      ),


    // ----------------------------------------
    // Model status
    // ----------------------------------------

    modelReady,

    prediction:
      riskLevel,

    riskLevel,

    riskScore,

    /*
     * score means UI Security Score.
     */
    score:
      securityScore,

    securityScore,

    confidence:
      prediction?.confidence ??
      null,

    probabilities:
      prediction?.probabilities ||
      {},


    // ----------------------------------------
    // ML dataset features
    // ----------------------------------------

    features,


    // ----------------------------------------
    // Scanner findings
    // ----------------------------------------

    findings,


    // ----------------------------------------
    // Passive checks
    // ----------------------------------------

    checks:
      passiveResult.checks ||
      [],

    checksPassed:
      passiveResult.checksPassed ||
      0,

    checksTotal:
      passiveResult.checksTotal ||
      0,


    // ----------------------------------------
    // Technology detection
    // ----------------------------------------

    technologies:
      passiveResult.technologies ||
      [],


    // ----------------------------------------
    // Counts
    // ----------------------------------------

    passiveFindingCount:
      passiveResult
        .findings
        ?.length || 0,

    activeFindingCount:
      activeResult
        ?.findings
        ?.length || 0,


    // ----------------------------------------
    // Informational surfaces
    // ----------------------------------------

    surfaces:
      activeResult?.surfaces ||
      {},

    informational:
      activeResult?.informational ||
      [],


    classificationError
  };


  // ========================================================
  // LOCAL SAVE
  // ========================================================

  onProgress(
    90,
    "Saving scan locally..."
  );


  try {

    await saveScanToHistory(
      scanRecord
    );

  } catch (error) {

    console.warn(
      "[Scanner] Local save failed:",
      error.message
    );
  }


  // ========================================================
  // BACKEND SAVE
  // ========================================================

  onProgress(
    95,
    modelReady
      ? "Saving scan to backend..."
      : "Saving training features to backend..."
  );


  try {

    await saveScanRecord(
      scanRecord
    );

  } catch (error) {

    /*
     * Local scanning still succeeds even
     * when Flask is unavailable.
     */

    console.warn(
      "[Scanner] Backend save failed:",
      error.message
    );
  }


  // ========================================================
  // FINISH
  // ========================================================

  onProgress(
    100,
    modelReady
      ? "Scan completed."
      : "Scan completed — ML classification pending."
  );


  return scanRecord;
}