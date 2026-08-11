/**
 * activeScanner.js
 * Performs light active checks (crawling links/forms already present on the page,
 * safe reflected-parameter probing, and directory existence checks) against the
 * CURRENT site only, and ONLY when the user has explicitly enabled "Active Scan"
 * in the popup. This module must never run automatically.
 *
 * IMPORTANT (viva talking point): Active scanning must only be used on websites
 * the user owns or has explicit written permission to test. Unauthorized active
 * testing of third-party sites can be illegal. This tool does not bypass that
 * responsibility — it is a decision the user makes via the opt-in toggle.
 */

const COMMON_DIRECTORIES = ["/admin", "/backup", "/.git/", "/.env", "/config", "/test", "/uploads"];
const SAFE_XSS_MARKER = "vulnscan_probe_12345";
const SQL_ERROR_SIGNATURES = [
  "sql syntax", "mysql_fetch", "ora-01756", "sqlite3.operationalerror",
  "unclosed quotation mark", "pg_query", "warning: mysql", "syntax error near"
];

/** Discover links and forms already present on the page via content script DOM data. */
async function discoverLinksAndForms(tab) {
  const domData = await chrome.tabs.sendMessage(tab.id, { type: "COLLECT_PASSIVE_DOM_DATA" });
  return {
    forms: (domData && domData.forms) || [],
    linkCount: (domData && domData.linkCount) || 0
  };
}

/**
 * Safe reflected-XSS check: appends a harmless, inert marker string to a URL
 * query parameter and checks whether it is reflected unescaped in the response
 * HTML. Does NOT execute any script — purely a text-reflection probe.
 */
async function checkReflectedParameter(baseUrl, paramName) {
  try {
    const url = new URL(baseUrl);
    url.searchParams.set(paramName, SAFE_XSS_MARKER);
    const response = await fetch(url.toString(), { method: "GET", credentials: "omit" });
    const text = await response.text();
    const reflectedRaw = text.includes(`<${SAFE_XSS_MARKER}`) || text.includes(`"${SAFE_XSS_MARKER}"<`);
    const reflectedPlain = text.includes(SAFE_XSS_MARKER);
    return {
      param: paramName,
      reflected: reflectedPlain,
      reflectedUnescaped: reflectedRaw
    };
  } catch (e) {
    return { param: paramName, error: e.message };
  }
}

/**
 * Error-based SQL injection indicator check: appends a single quote to a
 * parameter value and looks for common database error signatures in the
 * response body. This is a passive detection technique (no data is altered).
 */
async function checkSqlErrorIndicator(baseUrl, paramName) {
  try {
    const url = new URL(baseUrl);
    const original = url.searchParams.get(paramName) || "1";
    url.searchParams.set(paramName, `${original}'`);
    const response = await fetch(url.toString(), { method: "GET", credentials: "omit" });
    const text = (await response.text()).toLowerCase();
    const matched = SQL_ERROR_SIGNATURES.find((sig) => text.includes(sig));
    return { param: paramName, sqlErrorDetected: !!matched, signature: matched || null };
  } catch (e) {
    return { param: paramName, error: e.message };
  }
}

/** Check for common sensitive/backup directories returning 200 OK. */
async function checkCommonDirectories(origin) {
  const results = [];
  for (const dir of COMMON_DIRECTORIES) {
    try {
      const response = await fetch(origin + dir, { method: "GET", credentials: "omit" });
      results.push({ path: dir, status: response.status, exists: response.status === 200 });
    } catch (e) {
      results.push({ path: dir, error: e.message });
    }
  }
  return results;
}

/** Check for open redirect via common redirect parameter names. */
async function checkOpenRedirect(baseUrl) {
  const redirectParams = ["redirect", "url", "next", "return", "dest"];
  const findings = [];
  const url = new URL(baseUrl);
  for (const param of redirectParams) {
    if (url.searchParams.has(param)) {
      const testUrl = new URL(baseUrl);
      testUrl.searchParams.set(param, "https://example.com/vulnscan-redirect-test");
      try {
        const response = await fetch(testUrl.toString(), { method: "GET", redirect: "manual", credentials: "omit" });
        if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
          findings.push({ param, potentialOpenRedirect: true });
        }
      } catch (e) {
        // opaque redirects throw in some contexts; treat as inconclusive
      }
    }
  }
  return findings;
}

/**
 * Orchestrates the active scan. Only called when user explicitly opts in.
 * @param {object} tab - the active browser tab
 * @param {object} options - { maxParamsToTest: number }
 */
async function runActiveScan(tab, options = {}) {
  const maxParamsToTest = options.maxParamsToTest || 3;
  const findings = [];
  const origin = new URL(tab.url).origin;

  const { forms } = await discoverLinksAndForms(tab);

  // Directory discovery
  const dirResults = await checkCommonDirectories(origin);
  const exposedDirs = dirResults.filter((d) => d.exists);
  if (exposedDirs.length > 0) {
    findings.push({
      type: "EXPOSED_PATH",
      severity: "high",
      message: `Potentially exposed path(s): ${exposedDirs.map((d) => d.path).join(", ")}`
    });
  }

  // Parameter-based checks (reflected XSS marker + SQL error signature) on current URL only
  const url = new URL(tab.url);
  const paramNames = Array.from(url.searchParams.keys()).slice(0, maxParamsToTest);

  const xssResults = [];
  const sqlResults = [];
  for (const param of paramNames) {
    xssResults.push(await checkReflectedParameter(tab.url, param));
    sqlResults.push(await checkSqlErrorIndicator(tab.url, param));
  }

  const reflectedFindings = xssResults.filter((r) => r.reflectedUnescaped);
  if (reflectedFindings.length > 0) {
    findings.push({
      type: "XSS",
      severity: "high",
      message: `Unescaped reflection detected for parameter(s): ${reflectedFindings.map((r) => r.param).join(", ")}`
    });
  }

  const sqlFindings = sqlResults.filter((r) => r.sqlErrorDetected);
  if (sqlFindings.length > 0) {
    findings.push({
      type: "SQLI",
      severity: "critical",
      message: `Database error signature triggered for parameter(s): ${sqlFindings.map((r) => r.param).join(", ")}`
    });
  }

  // Open redirect check
  const redirectFindings = await checkOpenRedirect(tab.url);
  if (redirectFindings.length > 0) {
    findings.push({
      type: "OPEN_REDIRECT",
      severity: "medium",
      message: `Potential open redirect via parameter(s): ${redirectFindings.map((r) => r.param).join(", ")}`
    });
  }

  return {
    forms,
    directoryResults: dirResults,
    xssResults,
    sqlResults,
    redirectFindings,
    findings
  };
}

if (typeof module !== "undefined") {
  module.exports = { runActiveScan, checkReflectedParameter, checkSqlErrorIndicator, checkCommonDirectories, checkOpenRedirect };
}
