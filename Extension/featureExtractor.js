/**
 * featureExtractor.js
 * Converts raw passive/active scan data into a flat numeric feature vector
 * matching the schema expected by the Decision Tree model on the backend.
 */

/**
 * Build the ML feature object from passive + (optional) active scan results.
 * Keys here MUST match backend/feature_extractor.py and model/train_model.py.
 */
function extractFeatures(tab, passiveResult, activeResult) {
  const headers = passiveResult.headers || {};
  const domData = passiveResult.domData || {};
  const forms = domData.forms || [];

  const url = tab.url;
  const passwordFields = forms.filter((f) => f.hasPasswordField).length;

  const features = {
    https: passiveResult.headers ? (tab.url.startsWith("https://") ? 1 : 0) : 0,
    csp: headers["content-security-policy"] ? 1 : 0,
    hsts: headers["strict-transport-security"] ? 1 : 0,
    x_frame_options: headers["x-frame-options"] ? 1 : 0,
    x_content_type_options: headers["x-content-type-options"] ? 1 : 0,
    secure_cookie: passiveResult.findings.some((f) => f.type === "COOKIE" && f.message.includes("Secure")) ? 0 : 1,
    httponly_cookie: passiveResult.findings.some((f) => f.type === "COOKIE" && f.message.includes("HttpOnly")) ? 0 : 1,
    samesite_cookie: passiveResult.findings.some((f) => f.type === "COOKIE" && f.message.includes("SameSite")) ? 0 : 1,
    num_forms: forms.length,
    password_fields: passwordFields,
    url_length: url.length,
    query_parameters: (new URL(url)).searchParams.toString().split("&").filter(Boolean).length,
    external_scripts: (domData.scripts && domData.scripts.externalScripts) ? domData.scripts.externalScripts.length : 0,
    inline_scripts: (domData.scripts && domData.scripts.inlineScriptCount) || 0,
    http_status: 200,
    sql_error_indicator: activeResult ? (activeResult.sqlResults || []).some((r) => r.sqlErrorDetected) ? 1 : 0 : 0,
    reflected_payload_indicator: activeResult ? (activeResult.xssResults || []).some((r) => r.reflectedUnescaped) ? 1 : 0 : 0,
    server_error_indicator: 0,
    mixed_content_count: (domData.mixedContent || []).length,
    exposed_paths: activeResult ? (activeResult.directoryResults || []).filter((d) => d.exists).length : 0
  };

  return features;
}

if (typeof module !== "undefined") {
  module.exports = { extractFeatures };
}
