/**
 * featureExtractor.js
 *
 * Converts passive + active scan results into
 * the exact 33 numeric features used by the ML model.
 */

const FEATURE_ORDER = [
  "https",
  "csp",
  "hsts",
  "x_frame_options",
  "x_content_type_options",
  "secure_cookie",
  "httponly_cookie",
  "samesite_cookie",
  "num_forms",
  "password_fields",
  "url_length",
  "query_parameters",
  "external_scripts",
  "inline_scripts",
  "http_status",
  "sql_error_indicator",
  "reflected_payload_indicator",
  "server_error_indicator",
  "mixed_content_count",
  "exposed_paths",
  "blind_sqli_indicator",
  "dom_xss_indicator",
  "csrf_missing_token",
  "unsafe_upload_indicator",
  "weak_session_indicator",
  "weak_csp_indicator",
  "open_redirect_indicator",
  "command_input_surface",
  "file_path_input_surface",
  "stored_input_surface",
  "file_upload_surface",
  "login_surface",
  "api_surface"
];


function numberFlag(value) {
  return value ? 1 : 0;
}


function getHeaders(passiveResult) {
  return (
    passiveResult?.headers ||
    {}
  );
}


function countPasswordFields(forms) {
  let count = 0;

  for (
    const form
    of forms || []
  ) {
    for (
      const field
      of form.fields || []
    ) {
      if (
        String(
          field.type || ""
        ).toLowerCase() ===
        "password"
      ) {
        count++;
      }
    }
  }

  return count;
}


function countQueryParameters(url) {
  try {
    return Array.from(
      new URL(url)
        .searchParams
        .keys()
    ).length;

  } catch (error) {
    return 0;
  }
}


function hasFindingMessage(
  findings,
  text
) {
  const search =
    String(text)
      .toLowerCase();

  return (
    findings || []
  ).some(
    (finding) =>
      String(
        finding?.message ||
        ""
      )
        .toLowerCase()
        .includes(search)
  );
}


function extractFeatures(
  tab,
  passiveResult,
  activeResult
) {
  const url =
    tab?.url || "";

  const headers =
    getHeaders(
      passiveResult
    );

  const domData =
    passiveResult?.domData ||
    {};

  const forms =
    Array.isArray(
      domData.forms
    )
      ? domData.forms
      : [];

  const scripts =
    domData.scripts ||
    {};

  const passiveIndicators =
    passiveResult?.indicators ||
    {};

  const activeIndicators =
    activeResult?.indicators ||
    {};

  const surfaces =
    activeResult?.surfaces ||
    {};

  const passiveFindings =
    passiveResult?.findings ||
    [];


  /* ==========================================================
     COOKIE FEATURES
  ========================================================== */

  const secureCookie =
    !hasFindingMessage(
      passiveFindings,
      "missing secure flag"
    );

  const httpOnlyCookie =
    !hasFindingMessage(
      passiveFindings,
      "missing httponly flag"
    );

  const sameSiteCookie =
    !hasFindingMessage(
      passiveFindings,
      "missing samesite"
    );


  /* ==========================================================
     EXPOSED PATH COUNT
  ========================================================== */

  const exposedPaths =
    (
      activeResult
        ?.directoryResults ||
      []
    ).filter(
      (result) =>
        result?.exists
    ).length;


  /* ==========================================================
     STATUS
  ========================================================== */

  const httpStatus =
    Number(
      passiveResult?.httpStatus ||
      200
    );


  /* ==========================================================
     FEATURES
  ========================================================== */

  const features = {

    https:
      numberFlag(
        passiveResult?.isHttps
      ),


    csp:
      numberFlag(
        headers[
          "content-security-policy"
        ]
      ),


    hsts:
      numberFlag(
        headers[
          "strict-transport-security"
        ]
      ),


    x_frame_options:
      numberFlag(
        headers[
          "x-frame-options"
        ] ||
        String(
          headers[
            "content-security-policy"
          ] || ""
        )
          .toLowerCase()
          .includes(
            "frame-ancestors"
          )
      ),


    x_content_type_options:
      numberFlag(
        headers[
          "x-content-type-options"
        ]
      ),


    secure_cookie:
      numberFlag(
        secureCookie
      ),


    httponly_cookie:
      numberFlag(
        httpOnlyCookie
      ),


    samesite_cookie:
      numberFlag(
        sameSiteCookie
      ),


    num_forms:
      forms.length,


    password_fields:
      countPasswordFields(
        forms
      ),


    url_length:
      url.length,


    query_parameters:
      countQueryParameters(
        url
      ),


    external_scripts:
      Array.isArray(
        scripts.externalScripts
      )
        ? scripts
            .externalScripts
            .length
        : 0,


    inline_scripts:
      Number(
        scripts.inlineScriptCount ||
        0
      ),


    http_status:
      httpStatus,


    /* =========================
       ACTIVE VULNERABILITIES
    ========================= */

    sql_error_indicator:
      numberFlag(
        activeIndicators
          .sqlError
      ),


    reflected_payload_indicator:
      numberFlag(
        activeIndicators
          .reflectedXss
      ),


    server_error_indicator:
      numberFlag(
        httpStatus >= 500
      ),


    mixed_content_count:
      Array.isArray(
        domData.mixedContent
      )
        ? domData
            .mixedContent
            .length
        : 0,


    exposed_paths:
      exposedPaths,


    blind_sqli_indicator:
      numberFlag(
        activeIndicators
          .blindSqli
      ),


    dom_xss_indicator:
      numberFlag(
        passiveIndicators
          .domXss ||
        surfaces
          .domXssSurface
      ),


    csrf_missing_token:
      numberFlag(
        passiveIndicators
          .csrfMissingToken
      ),


    /*
     * IMPORTANT FIX:
     *
     * Active scanner confirmation now
     * controls unsafe_upload_indicator.
     */
    unsafe_upload_indicator:
      numberFlag(
        activeIndicators
          .unsafeUpload ||
        passiveIndicators
          .unsafeUpload
      ),


    weak_session_indicator:
      numberFlag(
        passiveIndicators
          .weakSession
      ),


    weak_csp_indicator:
      numberFlag(
        passiveIndicators
          .weakCsp
      ),


    open_redirect_indicator:
      numberFlag(
        activeIndicators
          .openRedirect
      ),


    /* =========================
       ATTACK SURFACES
    ========================= */

    command_input_surface:
      numberFlag(
        surfaces
          .commandInputSurface
      ),


    file_path_input_surface:
      numberFlag(
        surfaces
          .filePathInputSurface
      ),


    stored_input_surface:
      numberFlag(
        surfaces
          .storedInputSurface
      ),


    file_upload_surface:
      numberFlag(
        surfaces
          .fileUploadSurface ||
        passiveIndicators
          .fileUploadSurface
      ),


    login_surface:
      numberFlag(
        surfaces
          .loginSurface ||
        passiveIndicators
          .authSurface
      ),


    api_surface:
      numberFlag(
        surfaces
          .apiSurface ||
        passiveIndicators
          .apiSurface
      )
  };


  /*
   * Guarantee all 33 features are numeric.
   */
  for (
    const key
    of FEATURE_ORDER
  ) {
    const value =
      Number(
        features[key]
      );

    features[key] =
      Number.isFinite(value)
        ? value
        : 0;
  }


  return features;
}


/* ============================================================
   OPTIONAL NODE EXPORT
============================================================ */

if (
  typeof module !==
  "undefined"
) {
  module.exports = {
    FEATURE_ORDER,
    extractFeatures
  };
}