/**
 * passiveScanner.js
 *
 * Improved passive/read-only security scanner.
 * No payloads are submitted.
 * No application state is changed.
 *
 * Confirmed attack testing belongs in activeScanner.js.
 */


/* ============================================================
   NORMALIZE HEADERS
============================================================ */

function normalizeHeaders(raw) {
  const result = {};

  if (Array.isArray(raw)) {
    for (const header of raw) {
      if (!header?.name) continue;

      result[String(header.name).toLowerCase()] =
        header.value || "";
    }

    return result;
  }

  if (raw && typeof raw === "object") {
    for (const [name, value] of Object.entries(raw)) {
      result[String(name).toLowerCase()] =
        typeof value === "string"
          ? value
          : value?.value || "";
    }
  }

  return result;
}


/* ============================================================
   GET DOM DATA
============================================================ */

async function getDomDataForTab(tabId) {
  try {
    return await chrome.tabs.sendMessage(
      tabId,
      {
        type: "COLLECT_PASSIVE_DOM_DATA"
      }
    );

  } catch (firstError) {
    console.warn(
      "[Passive Scanner] content.js unavailable; attempting injection.",
      firstError
    );
  }

  try {
    await chrome.scripting.executeScript({
      target: {
        tabId
      },

      files: [
        "content.js"
      ]
    });

    return await chrome.tabs.sendMessage(
      tabId,
      {
        type: "COLLECT_PASSIVE_DOM_DATA"
      }
    );

  } catch (error) {
    throw new Error(
      `Unable to inspect website DOM: ${error.message}`
    );
  }
}


/* ============================================================
   HEADER VALIDATION HELPERS
============================================================ */

function hasValidXFrameOptions(value) {
  const normalized =
    String(value || "")
      .trim()
      .toUpperCase();

  return (
    normalized === "DENY" ||
    normalized === "SAMEORIGIN"
  );
}


function hasValidNoSniff(value) {
  return String(value || "")
    .toLowerCase()
    .split(",")
    .some(
      (part) =>
        part.trim() === "nosniff"
    );
}


function hasUsableHsts(value) {
  const normalized =
    String(value || "")
      .toLowerCase();

  if (!normalized) {
    return false;
  }

  const match =
    normalized.match(
      /max-age\s*=\s*(\d+)/i
    );

  return Boolean(
    match &&
    Number(match[1]) > 0
  );
}


function uniqueStrings(values) {
  return [
    ...new Set(
      (values || [])
        .filter(Boolean)
        .map(
          (value) =>
            String(value).trim()
        )
        .filter(Boolean)
    )
  ];
}


/* ============================================================
   MAIN PASSIVE SCAN
============================================================ */

async function runPassiveScan(tab) {

  if (!tab?.id || !tab?.url) {
    throw new Error(
      "No valid browser tab selected."
    );
  }

  if (
    !tab.url.startsWith("http://") &&
    !tab.url.startsWith("https://")
  ) {
    throw new Error(
      "Passive scan supports HTTP/HTTPS pages only."
    );
  }


  const findings = [];
  const checks = [];


  /* ==========================================================
     HELPERS
  ========================================================== */

  function addFinding(
    type,
    severity,
    message,
    status = "detected"
  ) {
    findings.push({
      type,
      severity,
      status,
      message
    });
  }


  function addCheck(
    name,
    passed,
    type,
    severity,
    message
  ) {
    const success =
      Boolean(passed);

    checks.push({
      name,

      passed:
        success,

      status:
        success
          ? "PASS"
          : "FAIL"
    });

    if (!success) {
      addFinding(
        type,
        severity,
        message
      );
    }
  }


  /* ==========================================================
     RESPONSE HEADERS
  ========================================================== */

  let headerData = {};

  try {
    headerData =
      await chrome.runtime.sendMessage({
        type:
          "GET_CACHED_HEADERS",

        tabId:
          tab.id
      });

  } catch (error) {
    console.warn(
      "[Passive Scanner] Header inspection failed:",
      error
    );
  }


  const headers =
    normalizeHeaders(
      headerData?.headers || {}
    );


  const httpStatus =
    Number(
      headerData?.statusCode ??
      headerData?.status ??
      0
    );


  /* ==========================================================
     DOM INSPECTION
  ========================================================== */

  const domData =
    await getDomDataForTab(
      tab.id
    );


  const forms =
    Array.isArray(
      domData?.forms
    )
      ? domData.forms
      : [];


  /* ==========================================================
     COOKIES
  ========================================================== */

  let cookies = [];

  try {
    const cookieResult =
      await chrome.runtime.sendMessage({
        type:
          "GET_COOKIES_FOR_URL",

        url:
          tab.url
      });

    cookies =
      Array.isArray(cookieResult)
        ? cookieResult
        : [];

  } catch (error) {
    console.warn(
      "[Passive Scanner] Cookie inspection failed:",
      error
    );
  }


  /* ==========================================================
     HTTPS
  ========================================================== */

  const isHttps =
    new URL(tab.url)
      .protocol === "https:";


  addCheck(
    "HTTPS",

    isHttps,

    "HTTPS",

    "high",

    "Website is served over HTTP instead of HTTPS. Network traffic is not protected by TLS."
  );


  /* ==========================================================
     CSP
  ========================================================== */

  const csp =
    String(
      headers[
        "content-security-policy"
      ] || ""
    );


  const hasCsp =
    csp.trim().length > 0;


  addCheck(
    "Content-Security-Policy",

    hasCsp,

    "HEADER",

    "medium",

    "Content-Security-Policy (CSP) response header is missing."
  );


  /* ==========================================================
     WEAK CSP
  ========================================================== */

  const cspLower =
    csp.toLowerCase();


  const cspWeakReasons = [];


  if (hasCsp) {

    if (
      cspLower.includes(
        "'unsafe-inline'"
      )
    ) {
      cspWeakReasons.push(
        "unsafe-inline"
      );
    }


    if (
      cspLower.includes(
        "'unsafe-eval'"
      )
    ) {
      cspWeakReasons.push(
        "unsafe-eval"
      );
    }


    if (
      /default-src\s+\*/i.test(
        csp
      )
    ) {
      cspWeakReasons.push(
        "wildcard default-src"
      );
    }
  }


  const weakCsp =
    !hasCsp ||
    cspWeakReasons.length > 0;


  if (
    hasCsp &&
    cspWeakReasons.length > 0
  ) {
    addFinding(
      "WEAK_CSP",

      "medium",

      `CSP is present but contains potentially weak directives: ${cspWeakReasons.join(", ")}.`,

      "potential"
    );
  }


  /* ==========================================================
     HSTS
  ========================================================== */

  const hsts =
    String(
      headers[
        "strict-transport-security"
      ] || ""
    );


  /*
   * HSTS only makes sense on HTTPS.
   */
  if (isHttps) {

    addCheck(
      "HSTS",

      hasUsableHsts(
        hsts
      ),

      "HEADER",

      "medium",

      "HTTP Strict-Transport-Security (HSTS) is missing or has no positive max-age."
    );
  }


  /* ==========================================================
     CLICKJACKING PROTECTION
  ========================================================== */

  const xFrameOptions =
    String(
      headers[
        "x-frame-options"
      ] || ""
    );


  const cspFrameAncestors =
    /(?:^|;)\s*frame-ancestors\s+/i.test(
      csp
    );


  const frameProtected =
    hasValidXFrameOptions(
      xFrameOptions
    ) ||
    cspFrameAncestors;


  addCheck(
    "Frame Protection",

    frameProtected,

    "HEADER",

    "medium",

    "Clickjacking protection is missing: neither a valid X-Frame-Options value nor CSP frame-ancestors was detected."
  );


  /* ==========================================================
     X-CONTENT-TYPE-OPTIONS
  ========================================================== */

  const contentTypeOptions =
    String(
      headers[
        "x-content-type-options"
      ] || ""
    );


  addCheck(
    "X-Content-Type-Options",

    hasValidNoSniff(
      contentTypeOptions
    ),

    "HEADER",

    "medium",

    "X-Content-Type-Options: nosniff is missing."
  );


  /* ==========================================================
     REFERRER POLICY
  ========================================================== */

  const referrerPolicy =
    String(
      headers[
        "referrer-policy"
      ] || ""
    ).trim();


  addCheck(
    "Referrer-Policy",

    referrerPolicy.length > 0,

    "HEADER",

    "low",

    "Referrer-Policy header is missing."
  );


  /* ==========================================================
     PERMISSIONS POLICY
  ========================================================== */

  const permissionsPolicy =
    String(
      headers[
        "permissions-policy"
      ] || ""
    ).trim();


  addCheck(
    "Permissions-Policy",

    permissionsPolicy.length > 0,

    "HEADER",

    "low",

    "Permissions-Policy header is missing."
  );


  /* ==========================================================
     COOKIE SECURITY
  ========================================================== */

  const insecureCookies =
    cookies.filter(
      (cookie) =>
        !cookie.secure
    );


  const missingHttpOnly =
    cookies.filter(
      (cookie) =>
        !cookie.httpOnly
    );


  const missingSameSite =
    cookies.filter(
      (cookie) => {

        const value =
          String(
            cookie.sameSite || ""
          )
            .trim()
            .toLowerCase();

        return (
          !value ||
          value === "unspecified"
        );
      }
    );


  addCheck(
    "Secure Cookies",

    insecureCookies.length === 0,

    "COOKIE",

    "medium",

    `${insecureCookies.length} cookie(s) are missing the Secure attribute.`
  );


  addCheck(
    "HttpOnly Cookies",

    missingHttpOnly.length === 0,

    "COOKIE",

    "medium",

    `${missingHttpOnly.length} cookie(s) are missing the HttpOnly attribute.`
  );


  addCheck(
    "SameSite Cookies",

    missingSameSite.length === 0,

    "COOKIE",

    "low",

    `${missingSameSite.length} cookie(s) have no explicit SameSite protection.`
  );


  /* ==========================================================
     MIXED CONTENT
  ========================================================== */

  const mixedContent =
    Array.isArray(
      domData?.mixedContent
    )
      ? domData.mixedContent
      : [];


  addCheck(
    "Mixed Content",

    mixedContent.length === 0,

    "MIXED_CONTENT",

    "high",

    `${mixedContent.length} HTTP resource(s) were referenced from this HTTPS page.`
  );


  /* ==========================================================
     FORM SECURITY
  ========================================================== */

  const insecureForms =
    forms.filter(
      (form) => {

        try {
          const action =
            new URL(
              form.action ||
              tab.url,

              tab.url
            );

          return (
            action.protocol ===
            "http:"
          );

        } catch (_) {
          return false;
        }
      }
    );


  addCheck(
    "Secure Form Submission",

    insecureForms.length === 0,

    "FORM",

    "high",

    `${insecureForms.length} form(s) submit data over HTTP.`
  );


  /* ==========================================================
     CSRF HEURISTIC

     Important:
     This is only a potential indicator.
     Missing token does NOT prove CSRF exploitation.
  ========================================================== */

  const csrfTokenPattern =
    /csrf|xsrf|token|nonce|authenticity|verification/i;


  const stateChangePattern =
    /password_new|password_conf|new_password|confirm_password|change|update|delete|remove|reset|transfer|amount|upload|save/i;


  const sensitiveForms =
    forms.filter(
      (form) => {

        const fields =
          Array.isArray(
            form.fields
          )
            ? form.fields
            : [];


        const method =
          String(
            form.method ||
            "GET"
          ).toUpperCase();


        const passwordCount =
          fields.filter(
            (field) =>
              String(
                field.type
              ).toLowerCase() ===
              "password"
          ).length;


        const hasStateChangeField =
          fields.some(
            (field) =>
              stateChangePattern.test(
                `${field.name || ""} ${field.id || ""}`
              )
          );


        /*
         * Normal login form is not
         * automatically called CSRF.
         */
        const simpleLogin =
          passwordCount === 1 &&
          !hasStateChangeField &&
          !form.hasFileField;


        if (simpleLogin) {
          return false;
        }


        return (
          method === "POST" ||
          Boolean(
            form.hasFileField
          ) ||
          hasStateChangeField ||
          passwordCount >= 2
        );
      }
    );


  const csrfMissingForms =
    sensitiveForms.filter(
      (form) => {

        if (
          form.hasCsrfToken ===
          true
        ) {
          return false;
        }


        const fields =
          Array.isArray(
            form.fields
          )
            ? form.fields
            : [];


        return !fields.some(
          (field) =>
            csrfTokenPattern.test(
              `${field.name || ""} ${field.id || ""}`
            )
        );
      }
    );


  if (
    csrfMissingForms.length > 0
  ) {

    addFinding(
      "CSRF",

      "medium",

      `${csrfMissingForms.length} state-changing form(s) have no obvious anti-CSRF token. This is a heuristic and requires validation.`,

      "potential"
    );
  }


  /* ==========================================================
     FILE UPLOAD SURFACE

     IMPORTANT:
     Finding a file input does NOT mean the website
     has an unsafe file upload vulnerability.

     Confirmation is handled by activeScanner.js.
  ========================================================== */

  const uploadForms =
    forms.filter(
      (form) =>
        Boolean(
          form.hasFileField
        )
    );


  const fileUploadSurface =
    uploadForms.length > 0;


  /* ==========================================================
     DOM XSS HEURISTIC

     This is static/read-only analysis.
     It is not confirmation of XSS.
  ========================================================== */

  const domXssPotential =
    Boolean(
      domData
        ?.domAnalysis
        ?.potentialDomXss
    );


  if (domXssPotential) {

    addFinding(
      "DOM_XSS",

      "medium",

      "DOM-controlled input sources and potentially dangerous HTML/JavaScript sinks were found together. Manual or active validation is required.",

      "potential"
    );
  }


  /* ==========================================================
     WEAK SESSION
  ========================================================== */

  const weakSession =
    cookies.length > 0 &&
    (
      insecureCookies.length > 0 ||
      missingHttpOnly.length > 0 ||
      missingSameSite.length > 0
    );


  /* ==========================================================
     LOGIN SURFACE
  ========================================================== */

  const authSurface =
    forms.some(
      (form) =>
        Boolean(
          form.hasPasswordField
        )
    );


  /* ==========================================================
     API SURFACE
  ========================================================== */

  const apiSurface =
    (
      domData?.links ||
      []
    ).some(
      (url) => {

        try {
          const parsed =
            new URL(
              url,
              tab.url
            );

          return (
            /\/api(?:\/|$)/i.test(
              parsed.pathname
            )
          );

        } catch (_) {
          return false;
        }
      }
    );


  /* ==========================================================
     TECHNOLOGIES
  ========================================================== */

  const technologies =
    uniqueStrings(
      domData?.technologies ||
      []
    );


  /* ==========================================================
     INDICATORS FOR featureExtractor.js

     KEEP THESE NAMES UNCHANGED.
  ========================================================== */

  const indicators = {

    csrfMissingToken:
      csrfMissingForms.length > 0,


    weakCsp:
      weakCsp,


    domXss:
      domXssPotential,


    /*
     * Passive scanning must NOT mark an
     * upload as confirmed unsafe.
     *
     * activeScanner.js will set the real
     * unsafe_upload_indicator.
     */
    unsafeUpload:
      false,


    fileUploadSurface:
      fileUploadSurface,


    weakSession:
      weakSession,


    authSurface:
      authSurface,


    apiSurface:
      apiSurface,


    captchaSurface:
      Boolean(
        domData?.captchaSurface
      )
  };


  /* ==========================================================
     FINAL RESULT
  ========================================================== */

  return {

    isHttps,

    httpStatus,

    headers,

    domData,


    cookies:
      cookies.length,


    technologies,

    indicators,

    checks,


    checksPassed:
      checks.filter(
        (check) =>
          check.passed
      ).length,


    checksTotal:
      checks.length,


    findings
  };
}


/* ============================================================
   OPTIONAL NODE EXPORT
============================================================ */

if (
  typeof module !==
  "undefined"
) {

  module.exports = {

    runPassiveScan,

    normalizeHeaders,

    hasValidXFrameOptions,

    hasValidNoSniff,

    hasUsableHsts
  };
}