/**
 * activeScanner.js
 *
 * Active checks for AUTHORIZED training/test targets.
 *
 * Local DVWA is allowed by default.
 * Other websites must be explicitly added to
 * AUTHORIZED_ACTIVE_HOSTS after permission is obtained.
 *
 * Project scope:
 * 1. SQL Injection
 * 2. Blind SQL Injection
 * 3. Reflected XSS
 * 4. DOM XSS -> passive scanner
 * 5. Stored XSS
 * 6. CSRF -> passive scanner
 * 7. Command Injection
 * 8. File Inclusion
 * 9. Unsafe File Upload
 */

const ACTIVE_TIMEOUT = 8000;


/* ============================================================
   AUTHORIZED WEBSITES
============================================================ */

const AUTHORIZED_ACTIVE_HOSTS = [
  "localhost",
    "https://0a03005c0370dae480dba8c4007a00a6.web-security-academy.net/",
  "127.0.0.1",
  "ncit.edu.np",
  "0a03005c0370dae480dba8c4007a00a6.web-security-academy.net",
  "::1",

  // "your-test-site.com"
];


/* ============================================================
   SQL ERROR SIGNATURES
============================================================ */

const SQL_ERROR_SIGNATURES = [
  "sql syntax",
  "mysql_fetch",
  "mysql_num_rows",
  "warning: mysql",
  "mysqli_sql_exception",
  "ora-01756",
  "sqlite3.operationalerror",
  "unclosed quotation mark",
  "pg_query",
  "postgresql query failed",
  "syntax error near"
];


/* ============================================================
   AUTHORIZATION CHECK
============================================================ */

function assertLocalLab(targetUrl) {
  const url = new URL(targetUrl);

  if (
    !AUTHORIZED_ACTIVE_HOSTS.includes(
      url.hostname
    )
  ) {
    throw new Error(
      `Active Scan is not authorized for ${url.hostname}. ` +
      "If you have permission to test this site, please add it to AUTHORIZED_ACTIVE_HOSTS in activeScanner.js."
    );
  }

  return true;
}


/* ============================================================
   FETCH
============================================================ */

async function labFetch(
  url,
  options = {}
) {
  assertLocalLab(url);

  const controller =
    new AbortController();

  const timer =
    setTimeout(
      () => controller.abort(),
      ACTIVE_TIMEOUT
    );

  try {
    return await fetch(
      url,
      {
        credentials:
          "include",

        cache:
          "no-store",

        redirect:
          "follow",

        ...options,

        signal:
          controller.signal
      }
    );

  } finally {
    clearTimeout(timer);
  }
}


/* ============================================================
   FORM DISCOVERY
============================================================ */

async function discoverLabForms(
  tab
) {
  let domData = {};

  try {
    domData =
      (
        await chrome.tabs.sendMessage(
          tab.id,
          {
            type:
              "COLLECT_PASSIVE_DOM_DATA"
          }
        )
      ) || {};

  } catch (error) {
    console.warn(
      "Passive DOM data unavailable:",
      error.message
    );
  }


  let forms = [];


  try {
    const results =
      await chrome.scripting.executeScript({
        target: {
          tabId:
            tab.id
        },

        func: () => {

          return Array.from(
            document.querySelectorAll(
              "form"
            )
          ).map(
            (form) => ({

              action:
                form.action ||
                location.href,

              method:
                (
                  form.method ||
                  "GET"
                ).toUpperCase(),

              enctype:
                form.enctype ||
                "application/x-www-form-urlencoded",

              fields:
                Array.from(
                  form.querySelectorAll(
                    "input, textarea, select, button"
                  )
                ).map(
                  (field) => ({

                    name:
                      field.name ||
                      "",

                    type:
                      field.tagName
                        .toLowerCase() ===
                      "textarea"
                        ? "textarea"
                        : String(
                            field.type ||
                            field.tagName ||
                            "text"
                          ).toLowerCase(),

                    /*
                     * Never collect
                     * password values.
                     */
                    value:
                      String(
                        field.type
                      ).toLowerCase() ===
                      "password"
                        ? ""
                        : (
                            field.value ||
                            ""
                          )
                  })
                )
            })
          );
        }
      });


    forms =
      Array.isArray(
        results?.[0]?.result
      )
        ? results[0].result
        : [];

  } catch (error) {

    console.warn(
      "Active form inspection failed:",
      error.message
    );


    forms =
      Array.isArray(
        domData?.forms
      )
        ? domData.forms
        : [];
  }


  return {
    forms,
    domData
  };
}


/* ============================================================
   SURFACE ANALYSIS
============================================================ */

function analyzeSurfaces(
  tabUrl,
  forms,
  domData
) {
  const allFields =
    forms.flatMap(
      (form) =>
        form.fields ||
        []
    );


  const currentUrl =
    new URL(tabUrl);


  const urlParams =
    [
      ...currentUrl
        .searchParams
        .keys()
    ];


  /* LOGIN */

  const loginSurface =
    allFields.some(
      (field) =>
        field.type ===
        "password"
    );


  /* COMMAND */

  const commandPattern =
    /^(ip|host|hostname|cmd|command|ping)$/i;


  const commandInputSurface =
    allFields.some(
      (field) =>
        field.name &&
        commandPattern.test(
          field.name
        )
    );


  /* FILE PATH */

  const filePathPattern =
    /^(page|file|path|template|include)$/i;


  const filePathInputSurface =
    allFields.some(
      (field) =>
        field.name &&
        filePathPattern.test(
          field.name
        )
    ) ||

    urlParams.some(
      (name) =>
        filePathPattern.test(
          name
        )
    );


  /* STORED INPUT */

  const storedInputSurface =
    forms.some(
      (form) => {

        const isPost =
          String(
            form.method ||
            "GET"
          ).toUpperCase() ===
          "POST";


        const hasText =
          (
            form.fields ||
            []
          ).some(
            (field) =>
              [
                "text",
                "textarea"
              ].includes(
                field.type
              )
          );


        return (
          isPost &&
          hasText
        );
      }
    );


  /* FILE UPLOAD */

  const fileUploadSurface =
    allFields.some(
      (field) =>
        field.type ===
        "file"
    );


  /* DOM XSS */

  const domXssSurface =
    Boolean(
      domData
        ?.domAnalysis
        ?.potentialDomXss
    );


  /* API */

  const links =
    Array.isArray(
      domData?.links
    )
      ? domData.links
      : [];


  const apiSurface =
    links.some(
      (link) => {

        const value =
          typeof link ===
          "string"
            ? link
            : (
                link?.href ||
                ""
              );


        return /\/api(?:\/|\?|$)/i
          .test(value);
      }
    );


  return {
    loginSurface,
    commandInputSurface,
    filePathInputSurface,
    storedInputSurface,
    fileUploadSurface,
    domXssSurface,
    apiSurface
  };
}


/* ============================================================
   PARAMETER TARGETS
============================================================ */

function buildTargets(
  tabUrl,
  forms,
  maxTargets = 5
) {
  const targets = [];

  const seen =
    new Set();


  const ignored =
    /^(submit|button|btn|action|csrf|xsrf|token|nonce|user_token)$/i;


  function addTarget(
    target
  ) {
    if (
      !target.param ||
      ignored.test(
        target.param
      )
    ) {
      return;
    }


    const parsed =
      new URL(
        target.url,
        tabUrl
      );


    assertLocalLab(
      parsed.toString()
    );


    const key =
      `${parsed.origin}${parsed.pathname}|${target.method}|${target.param}`;


    if (
      seen.has(key)
    ) {
      return;
    }


    seen.add(key);


    targets.push({
      ...target,

      url:
        parsed.toString()
    });
  }


  /* URL PARAMETERS */

  const current =
    new URL(tabUrl);


  for (
    const [
      param,
      value
    ]
    of current.searchParams
  ) {

    addTarget({

      url:
        current.toString(),

      method:
        "GET",

      param,

      originalValue:
        value ||
        "1",

      fields:
        []
    });
  }


  /* FORM PARAMETERS */

  const testableTypes =
    new Set([
      "text",
      "search",
      "number",
      "email",
      "url",
      "textarea"
    ]);


  for (
    const form
    of forms
  ) {

    const fields =
      form.fields ||
      [];


    for (
      const field
      of fields
    ) {

      if (
        field.name &&
        testableTypes.has(
          field.type
        )
      ) {

        addTarget({

          url:
            form.action ||
            tabUrl,

          method:
            String(
              form.method ||
              "GET"
            ).toUpperCase(),

          param:
            field.name,

          originalValue:
            field.value ||
            "1",

          fields
        });
      }
    }
  }


  return targets.slice(
    0,
    maxTargets
  );
}


/* ============================================================
   SEND PARAMETER
============================================================ */

async function requestTarget(
  target,
  injectedValue
) {

  const url =
    new URL(
      target.url
    );


  /* GET */

  if (
    target.method ===
    "GET"
  ) {

    for (
      const field
      of target.fields ||
      []
    ) {

      if (
        field.name &&
        field.type !==
          "password" &&
        field.type !==
          "file"
      ) {

        url.searchParams.set(
          field.name,

          field.name ===
          target.param
            ? injectedValue
            : (
                field.value ||
                ""
              )
        );
      }
    }


    url.searchParams.set(
      target.param,
      injectedValue
    );


    return labFetch(
      url.toString()
    );
  }


  /* POST */

  const body =
    new URLSearchParams();


  for (
    const field
    of target.fields ||
    []
  ) {

    if (
      !field.name ||
      field.type ===
        "password" ||
      field.type ===
        "file"
    ) {
      continue;
    }


    body.set(
      field.name,

      field.name ===
      target.param
        ? injectedValue
        : (
            field.value ||
            ""
          )
    );
  }


  body.set(
    target.param,
    injectedValue
  );


  return labFetch(
    url.toString(),
    {
      method:
        "POST",

      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body:
        body.toString()
    }
  );
}


/* ============================================================
   REFLECTED XSS
============================================================ */

async function checkReflectedParameter(
  target
) {

  const unique =
    `${Date.now()}_${Math.random()
      .toString(36)
      .slice(2, 8)}`;


  /*
   * Harmless marker.
   * No JavaScript.
   */

  const marker =
    `<vulnscan-probe-${unique}>`;


  try {

    const response =
      await requestTarget(
        target,
        marker
      );


    const text =
      await response.text();


    return {

      param:
        target.param,

      reflected:
        text.includes(
          `vulnscan-probe-${unique}`
        ),

      reflectedUnescaped:
        text.includes(
          marker
        )
    };

  } catch (error) {

    return {

      param:
        target.param,

      reflected:
        false,

      reflectedUnescaped:
        false,

      error:
        error.message
    };
  }
}


/* ============================================================
   SQL INJECTION ERROR INDICATOR
============================================================ */

async function checkSqlErrorIndicator(
  target
) {

  try {

    const probe =
      `${target.originalValue || "1"}'`;


    const response =
      await requestTarget(
        target,
        probe
      );


    const text =
      (
        await response.text()
      ).toLowerCase();


    const signature =
      SQL_ERROR_SIGNATURES.find(
        (item) =>
          text.includes(
            item
          )
      ) || null;


    return {

      param:
        target.param,

      sqlErrorDetected:
        Boolean(
          signature
        ),

      signature
    };

  } catch (error) {

    return {

      param:
        target.param,

      sqlErrorDetected:
        false,

      signature:
        null,

      error:
        error.message
    };
  }
}


/* ============================================================
   BLIND SQL INJECTION
============================================================ */

function normalizedLength(
  text
) {

  return String(
    text ||
    ""
  )
    .replace(
      /\s+/g,
      " "
    )
    .trim()
    .length;
}


async function checkBlindSqlIndicator(
  target
) {

  const base =
    target.originalValue ||
    "1";


  const trueProbe =
    `${base}' AND '1'='1' #`;


  const falseProbe =
    `${base}' AND '1'='2' #`;


  try {

    const [
      trueResponse,
      falseResponse
    ] =
      await Promise.all([

        requestTarget(
          target,
          trueProbe
        ),

        requestTarget(
          target,
          falseProbe
        )
      ]);


    const trueText =
      await trueResponse.text();


    const falseText =
      await falseResponse.text();


    const trueLength =
      normalizedLength(
        trueText
      );


    const falseLength =
      normalizedLength(
        falseText
      );


    const difference =
      Math.abs(
        trueLength -
        falseLength
      );


    const denominator =
      Math.max(
        trueLength,
        falseLength,
        1
      );


    const differenceRatio =
      difference /
      denominator;


    const potentialBlindSql =
      difference >= 20 &&
      differenceRatio >=
        0.01;


    return {

      param:
        target.param,

      trueLength,

      falseLength,

      difference,

      differenceRatio,

      potentialBlindSql
    };

  } catch (error) {

    return {

      param:
        target.param,

      potentialBlindSql:
        false,

      error:
        error.message
    };
  }
}


/* ============================================================
   COMMAND INJECTION
============================================================ */

async function checkCommandInjection(
  tabUrl,
  forms
) {

  const results = [];


  const pattern =
    /^(ip|host|hostname|cmd|command|ping)$/i;


  /*
   * Harmless arithmetic probes.
   */

  const probes = [

    {
      name:
        "windows",

      value:
        "127.0.0.1 & set /a 314159+271828",

      expected:
        "585987"
    },

    {
      name:
        "unix",

      value:
        "127.0.0.1; expr 314159 + 271828",

      expected:
        "585987"
    }
  ];


  for (
    const form
    of forms
  ) {

    const fields =
      form.fields ||
      [];


    for (
      const field
      of fields
    ) {

      if (
        !field.name ||
        !pattern.test(
          field.name
        )
      ) {
        continue;
      }


      const target = {

        url:
          form.action ||
          tabUrl,

        method:
          String(
            form.method ||
            "GET"
          ).toUpperCase(),

        param:
          field.name,

        originalValue:
          field.value ||
          "127.0.0.1",

        fields
      };


      for (
        const probe
        of probes
      ) {

        try {

          const response =
            await requestTarget(
              target,
              probe.value
            );


          const text =
            await response.text();


          const detected =
            text.includes(
              probe.expected
            );


          results.push({

            param:
              field.name,

            probeType:
              probe.name,

            commandInjectionDetected:
              detected
          });


          if (
            detected
          ) {
            break;
          }

        } catch (error) {

          results.push({

            param:
              field.name,

            probeType:
              probe.name,

            commandInjectionDetected:
              false,

            error:
              error.message
          });
        }
      }
    }
  }


  return results;
}


/* ============================================================
   FILE INCLUSION
============================================================ */

async function checkFileInclusion(
  tabUrl,
  targets
) {

  const results = [];


  const pattern =
    /^(page|file|path|template|include)$/i;


  for (
    const target
    of targets
  ) {

    if (
      !pattern.test(
        target.param
      )
    ) {
      continue;
    }


    try {

      /*
       * Harmless project README.
       * No operating-system file.
       */

      const response =
        await requestTarget(
          target,
          "../../README.md"
        );


      const text =
        await response.text();


      const lower =
        text.toLowerCase();


      const detected =
        lower.includes(
          "damn vulnerable web application (dvwa)"
        ) &&
        (
          lower.includes(
            "legal disclaimer"
          ) ||

          lower.includes(
            "vulnerability levels"
          ) ||

          lower.includes(
            "digininja"
          )
        );


      results.push({

        param:
          target.param,

        fileInclusionDetected:
          detected
      });

    } catch (error) {

      results.push({

        param:
          target.param,

        fileInclusionDetected:
          false,

        error:
          error.message
      });
    }
  }


  return results;
}


/* ============================================================
   FILE UPLOAD
============================================================ */

function dvwaUploadVerificationUrl(
  tabUrl,
  filename
) {

  const url =
    new URL(
      tabUrl
    );


  const marker =
    "/vulnerabilities/";


  const index =
    url.pathname.indexOf(
      marker
    );


  const dvwaBase =
    index >= 0
      ? url.pathname.slice(
          0,
          index
        )
      : "";


  return (
    `${url.origin}${dvwaBase}` +
    `/hackable/uploads/${encodeURIComponent(filename)}`
  );
}


async function checkUnsafeFileUpload(
  tabUrl,
  forms
) {

  const results = [];


  const uploadForms =
    forms.filter(
      (form) =>
        (
          form.fields ||
          []
        ).some(
          (field) =>
            field.type ===
            "file"
        )
    );


  for (
    const form
    of uploadForms
  ) {

    /*
     * Unique every scan.
     * Prevents stale-file false positives.
     */

    const uniqueUploadId =
      `${Date.now()}_${Math.random()
        .toString(36)
        .slice(2, 8)}`;


    const marker =
      `VULNSCAN_SAFE_UPLOAD_${uniqueUploadId}`;


    const filename =
      `vulnscan_safe_${uniqueUploadId}.php`;


    try {

      const action =
        new URL(
          form.action ||
          tabUrl,
          tabUrl
        );


      assertLocalLab(
        action.toString()
      );


      const data =
        new FormData();


      for (
        const field
        of form.fields ||
        []
      ) {

        if (
          !field.name
        ) {
          continue;
        }


        if (
          field.type ===
          "password"
        ) {
          continue;
        }


        if (
          field.type ===
          "file"
        ) {

          /*
           * Plain text marker.
           * NO PHP code.
           */

          const harmlessFile =
            new Blob(
              [marker],
              {
                type:
                  "text/plain"
              }
            );


          data.append(
            field.name,
            harmlessFile,
            filename
          );

        } else {

          data.append(
            field.name,
            field.value ||
            ""
          );
        }
      }


      const uploadResponse =
        await labFetch(
          action.toString(),
          {
            method:
              "POST",

            body:
              data
          }
        );


      const uploadText =
        await uploadResponse.text();


      let verificationUrl =
        dvwaUploadVerificationUrl(
          tabUrl,
          filename
        );


      const escapedFilename =
        filename.replace(
          /[.*+?^${}()|[\]\\]/g,
          "\\$&"
        );


      const pathRegex =
        new RegExp(
          `(?:\\.\\./)*hackable/uploads/${escapedFilename}`,
          "i"
        );


      const pathMatch =
        uploadText.match(
          pathRegex
        );


      if (
        pathMatch
      ) {

        verificationUrl =
          new URL(
            pathMatch[0],
            action.toString()
          ).toString();
      }


      let publiclyAccessible =
        false;


      try {

        const verifyResponse =
          await labFetch(
            verificationUrl
          );


        if (
          verifyResponse.ok
        ) {

          const verifyText =
            await verifyResponse.text();


          publiclyAccessible =
            verifyText.includes(
              marker
            );
        }

      } catch (error) {

        publiclyAccessible =
          false;
      }


      results.push({

        filename,

        uploadStatus:
          uploadResponse.status,

        verificationUrl,

        unsafeUploadDetected:
          publiclyAccessible
      });

    } catch (error) {

      results.push({

        filename,

        unsafeUploadDetected:
          false,

        error:
          error.message
      });
    }
  }


  return results;
}


/* ============================================================
   STORED XSS
============================================================ */

async function checkStoredXss(
  tabUrl,
  forms
) {

  const results = [];


  const current =
    new URL(
      tabUrl
    );


  /*
   * Keep the persistent probe restricted
   * to the DVWA stored-XSS laboratory page.
   */

  if (
    !current.pathname.includes(
      "/vulnerabilities/xss_s/"
    )
  ) {
    return results;
  }


  const candidateForm =
    forms.find(
      (form) =>

        String(
          form.method ||
          "GET"
        ).toUpperCase() ===
        "POST" &&

        (
          form.fields ||
          []
        ).some(
          (field) =>

            field.type ===
            "textarea" ||

            /message|comment|mtx/i
              .test(
                field.name ||
                ""
              )
        )
    );


  if (
    !candidateForm
  ) {
    return results;
  }


  const fields =
    candidateForm.fields ||
    [];


  const messageField =
    fields.find(
      (field) =>
        field.type ===
        "textarea"
    ) ||

    fields.find(
      (field) =>
        /message|comment|mtx/i
          .test(
            field.name ||
            ""
          )
    );


  if (
    !messageField?.name
  ) {
    return results;
  }


  const unique =
    `${Date.now()}_${Math.random()
      .toString(36)
      .slice(2, 8)}`;


  const token =
    `VULNSCAN_STORED_${unique}`;


  /*
   * Harmless HTML.
   *
   * No script.
   * No JavaScript.
   * No event handlers.
   */

  const marker =
    `<b data-vulnscan="${unique}">${token}</b>`;


  try {

    const action =
      new URL(
        candidateForm.action ||
        tabUrl,
        tabUrl
      );


    const body =
      new URLSearchParams();


    for (
      const field
      of fields
    ) {

      if (
        !field.name ||
        field.type ===
          "password" ||
        field.type ===
          "file"
      ) {
        continue;
      }


      let value =
        field.value ||
        "";


      if (
        field.name ===
        messageField.name
      ) {

        value =
          marker;

      } else if (
        !value &&
        /name|author/i.test(
          field.name
        )
      ) {

        value =
          "VulnScan";
      }


      body.set(
        field.name,
        value
      );
    }


    await labFetch(
      action.toString(),
      {
        method:
          "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body:
          body.toString()
      }
    );


    const verifyResponse =
      await labFetch(
        tabUrl
      );


    const verifyText =
      await verifyResponse.text();


    const detected =
      verifyText.includes(
        marker
      );


    results.push({

      param:
        messageField.name,

      storedXssDetected:
        detected
    });

  } catch (error) {

    results.push({

      param:
        messageField.name,

      storedXssDetected:
        false,

      error:
        error.message
    });
  }


  return results;
}


/* ============================================================
   MAIN ACTIVE SCAN
============================================================ */

async function runActiveScan(
  tab,
  options = {}
) {

  if (
    !tab?.id ||
    !tab?.url
  ) {

    throw new Error(
      "No valid browser tab selected."
    );
  }


  /*
   * Authorization check.
   */

  assertLocalLab(
    tab.url
  );


  const findings = [];

  const informational = [];


  const maxTargetsToTest =
    options.maxTargetsToTest ||
    options.maxParamsToTest ||
    5;


  const {
    forms,
    domData
  } =
    await discoverLabForms(
      tab
    );


  const surfaces =
    analyzeSurfaces(
      tab.url,
      forms,
      domData
    );


  const targets =
    buildTargets(
      tab.url,
      forms,
      maxTargetsToTest
    );


  /* ==========================================================
     REFLECTED XSS
  ========================================================== */

  const xssResults = [];


  for (
    const target
    of targets
  ) {

    xssResults.push(
      await checkReflectedParameter(
        target
      )
    );
  }


  const reflectedParameters =
    [
      ...new Set(

        xssResults

          .filter(
            (result) =>
              result
                .reflectedUnescaped
          )

          .map(
            (result) =>
              result.param
          )
      )
    ];


  if (
    reflectedParameters.length >
    0
  ) {

    findings.push({

      type:
        "XSS",

      severity:
        "high",

      status:
        "potential",

      message:
        `Unescaped input reflection detected for parameter(s): ${reflectedParameters.join(", ")}`
    });
  }


  /* ==========================================================
     SQL INJECTION
  ========================================================== */

  const sqlResults = [];


  for (
    const target
    of targets
  ) {

    sqlResults.push(
      await checkSqlErrorIndicator(
        target
      )
    );
  }


  const sqlParameters =
    [
      ...new Set(

        sqlResults

          .filter(
            (result) =>
              result
                .sqlErrorDetected
          )

          .map(
            (result) =>
              result.param
          )
      )
    ];


  if (
    sqlParameters.length >
    0
  ) {

    findings.push({

      type:
        "SQLI",

      severity:
        "critical",

      status:
        "potential",

      message:
        `Database error indicator detected for parameter(s): ${sqlParameters.join(", ")}`
    });
  }


  /* ==========================================================
     BLIND SQL INJECTION
  ========================================================== */

  const blindSqlResults = [];


  for (
    const target
    of targets
  ) {

    blindSqlResults.push(
      await checkBlindSqlIndicator(
        target
      )
    );
  }


  const blindParameters =
    [
      ...new Set(

        blindSqlResults

          .filter(
            (result) =>
              result
                .potentialBlindSql
          )

          .map(
            (result) =>
              result.param
          )
      )
    ];


  if (
    blindParameters.length >
    0
  ) {

    findings.push({

      type:
        "BLIND_SQLI",

      severity:
        "high",

      status:
        "potential",

      message:
        `Possible boolean-response difference detected for parameter(s): ${blindParameters.join(", ")}`
    });
  }


  /* ==========================================================
     COMMAND INJECTION
  ========================================================== */

  const commandInjectionResults =
    surfaces
      .commandInputSurface

      ? await checkCommandInjection(
          tab.url,
          forms
        )

      : [];


  const commandParameters =
    [
      ...new Set(

        commandInjectionResults

          .filter(
            (result) =>
              result
                .commandInjectionDetected
          )

          .map(
            (result) =>
              result.param
          )
      )
    ];


  if (
    commandParameters.length >
    0
  ) {

    findings.push({

      type:
        "COMMAND_INJECTION",

      severity:
        "critical",

      status:
        "potential",

      message:
        `Command execution evidence detected for parameter(s): ${commandParameters.join(", ")}`
    });
  }


  /* ==========================================================
     FILE INCLUSION
  ========================================================== */

  const fileInclusionResults =
    surfaces
      .filePathInputSurface

      ? await checkFileInclusion(
          tab.url,
          targets
        )

      : [];


  const inclusionParameters =
    [
      ...new Set(

        fileInclusionResults

          .filter(
            (result) =>
              result
                .fileInclusionDetected
          )

          .map(
            (result) =>
              result.param
          )
      )
    ];


  if (
    inclusionParameters.length >
    0
  ) {

    findings.push({

      type:
        "FILE_INCLUSION",

      severity:
        "high",

      status:
        "potential",

      message:
        `File inclusion/traversal evidence detected for parameter(s): ${inclusionParameters.join(", ")}`
    });
  }


  /* ==========================================================
     FILE UPLOAD
  ========================================================== */

  const unsafeUploadResults =
    surfaces
      .fileUploadSurface

      ? await checkUnsafeFileUpload(
          tab.url,
          forms
        )

      : [];


  const unsafeUploadDetected =
    unsafeUploadResults.some(
      (result) =>
        result
          .unsafeUploadDetected
    );


  if (
    unsafeUploadDetected
  ) {

    findings.push({

      type:
        "FILE_UPLOAD",

      severity:
        "high",

      status:
        "potential",

      message:
        "Unsafe file upload evidence detected: the application accepted a unique .php filename and made the harmless uploaded marker publicly accessible."
    });
  }


  /* ==========================================================
     STORED XSS
  ========================================================== */

  const storedXssResults =
    surfaces
      .storedInputSurface

      ? await checkStoredXss(
          tab.url,
          forms
        )

      : [];


  const storedXssParameters =
    [
      ...new Set(

        storedXssResults

          .filter(
            (result) =>
              result
                .storedXssDetected
          )

          .map(
            (result) =>
              result.param
          )
      )
    ];


  if (
    storedXssParameters.length >
    0
  ) {

    findings.push({

      type:
        "STORED_XSS",

      severity:
        "high",

      status:
        "potential",

      message:
        `Persistent unescaped HTML injection evidence detected for parameter(s): ${storedXssParameters.join(", ")}. This indicates potential Stored XSS.`
    });
  }


  /* ==========================================================
     INFORMATIONAL
  ========================================================== */

  if (
    surfaces.loginSurface
  ) {

    informational.push({

      type:
        "LOGIN_SURFACE",

      message:
        "Login/password form detected. This is an attack surface, not a brute-force vulnerability."
    });
  }


  if (
    surfaces.fileUploadSurface
  ) {

    informational.push({

      type:
        "FILE_UPLOAD_SURFACE",

      message:
        "File upload input detected. Upload functionality alone is not a vulnerability."
    });
  }


  /*
   * Not part of our current nine active/passive
   * vulnerability scope.
   */

  const directoryResults = [];

  const redirectFindings = [];


  /* ==========================================================
     RETURN
  ========================================================== */

  return {

    forms,

    surfaces,

    informational,

    targetsTested:
      targets.length,

    directoryResults,

    xssResults,

    sqlResults,

    blindSqlResults,

    redirectFindings,

    commandInjectionResults,

    fileInclusionResults,

    unsafeUploadResults,

    storedXssResults,


    indicators: {

      reflectedXss:
        reflectedParameters
          .length > 0,

      sqlError:
        sqlParameters
          .length > 0,

      blindSqli:
        blindParameters
          .length > 0,

      openRedirect:
        false,

      commandInjection:
        commandParameters
          .length > 0,

      fileInclusion:
        inclusionParameters
          .length > 0,

      unsafeUpload:
        unsafeUploadDetected,

      storedXss:
        storedXssParameters
          .length > 0
    },


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

    runActiveScan,

    assertLocalLab,

    checkReflectedParameter,

    checkSqlErrorIndicator,

    checkBlindSqlIndicator,

    checkCommandInjection,

    checkFileInclusion,

    checkUnsafeFileUpload,

    checkStoredXss
  };
}