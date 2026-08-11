/**
 * passiveScanner.js
 * Performs read-only, non-intrusive security checks against the current tab.
 * No requests are sent other than what the browser already made when loading the page,
 * plus cookie/header inspection. Safe to run on ANY website.
 */

/** Run all passive checks for the given tab and return a structured result. */
async function runPassiveScan(tab) {
  const findings = [];

  // 1. Get cached response headers captured by background.js webRequest listener.
  const headerData = await chrome.runtime.sendMessage({ type: "GET_CACHED_HEADERS", tabId: tab.id });
  const headers = (headerData && headerData.headers) || {};

  // 2. Get DOM-level data from content script.
  let domData;
  try {
    domData = await chrome.tabs.sendMessage(tab.id, { type: "COLLECT_PASSIVE_DOM_DATA" });
  } catch (e) {
    domData = null;
  }

  // 3. Get cookies for this URL.
  const cookies = await chrome.runtime.sendMessage({ type: "GET_COOKIES_FOR_URL", url: tab.url });

  // --- HTTPS check ---
  const isHttps = tab.url.startsWith("https://");
  if (!isHttps) {
    findings.push({ type: "HTTPS", severity: "high", message: "Site is not served over HTTPS." });
  }

  // --- Security headers ---
  const requiredHeaders = {
    "content-security-policy": "Content-Security-Policy (CSP) header missing.",
    "strict-transport-security": "HTTP Strict-Transport-Security (HSTS) header missing.",
    "x-frame-options": "X-Frame-Options header missing (clickjacking risk).",
    "x-content-type-options": "X-Content-Type-Options header missing."
  };
  for (const [header, message] of Object.entries(requiredHeaders)) {
    if (!headers[header]) {
      findings.push({ type: "HEADER", severity: "medium", message });
    }
  }

  // --- Cookie security ---
  let insecureCookies = 0, missingHttpOnly = 0, missingSameSite = 0;
  if (Array.isArray(cookies)) {
    cookies.forEach((c) => {
      if (!c.secure) insecureCookies++;
      if (!c.httpOnly) missingHttpOnly++;
      if (!c.sameSite || c.sameSite === "unspecified" || c.sameSite === "no_restriction") missingSameSite++;
    });
    if (insecureCookies > 0) {
      findings.push({ type: "COOKIE", severity: "medium", message: `${insecureCookies} cookie(s) missing Secure flag.` });
    }
    if (missingHttpOnly > 0) {
      findings.push({ type: "COOKIE", severity: "medium", message: `${missingHttpOnly} cookie(s) missing HttpOnly flag.` });
    }
    if (missingSameSite > 0) {
      findings.push({ type: "COOKIE", severity: "low", message: `${missingSameSite} cookie(s) missing SameSite attribute.` });
    }
  }

  // --- Mixed content ---
  if (domData && domData.mixedContent && domData.mixedContent.length > 0) {
    findings.push({
      type: "MIXED_CONTENT",
      severity: "high",
      message: `${domData.mixedContent.length} insecure (HTTP) resource(s) loaded on an HTTPS page.`
    });
  }

  // --- Forms without HTTPS action ---
  if (domData && domData.forms) {
    const insecureForms = domData.forms.filter((f) => f.action && f.action.startsWith("http://"));
    if (insecureForms.length > 0) {
      findings.push({ type: "FORM", severity: "high", message: `${insecureForms.length} form(s) submit data over HTTP.` });
    }
    const passwordFormsNoHttps = domData.forms.filter((f) => f.hasPasswordField && !isHttps);
    if (passwordFormsNoHttps.length > 0) {
      findings.push({ type: "FORM", severity: "high", message: "Password field present on a non-HTTPS page." });
    }
  }

  return {
    headers,
    domData,
    cookies: Array.isArray(cookies) ? cookies.length : 0,
    findings
  };
}

if (typeof module !== "undefined") {
  module.exports = { runPassiveScan };
}
