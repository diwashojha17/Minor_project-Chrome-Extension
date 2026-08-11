/**
 * content.js
 * Read-only DOM inspection for the current page.
 */

function collectForms() {
  const tokenPattern =
    /csrf|xsrf|token|nonce|authenticity|verification/i;

  return Array.from(document.forms).map((form) => {
    const fields = Array.from(form.elements).map((el) => ({
      name: el.name || "",
      id: el.id || "",
      type: (el.type || el.tagName || "").toLowerCase(),
      required: Boolean(el.required),
      disabled: Boolean(el.disabled),
      accept: el.accept || "",
      autocomplete: el.autocomplete || "",
      hasValue:
        el.type === "password"
          ? Boolean(el.value)
          : Boolean(el.value)
    }));

    const hasCsrfToken = fields.some((field) =>
      tokenPattern.test(`${field.name} ${field.id}`)
    );

    return {
      action: form.action || location.href,
      method: (form.method || "GET").toUpperCase(),
      enctype: form.enctype || "",
      hasPasswordField: fields.some(
        (field) => field.type === "password"
      ),
      hasFileField: fields.some(
        (field) => field.type === "file"
      ),
      hasCsrfToken,
      fieldCount: fields.length,
      fields
    };
  });
}


function collectScripts() {
  const scripts = Array.from(document.scripts);

  const externalScripts = scripts
    .filter((script) => script.src)
    .map((script) => script.src);

  const inlineScripts = scripts
    .filter(
      (script) =>
        !script.src &&
        script.textContent.trim()
    )
    .map((script) => script.textContent);

  return {
    externalScripts,
    inlineScriptCount: inlineScripts.length
  };
}


function analyzeDomJavascript() {
  const source = Array.from(document.scripts)
    .filter((script) => !script.src)
    .map((script) => script.textContent)
    .join("\n")
    .toLowerCase();

  const sources = [
    "location.hash",
    "location.search",
    "location.href",
    "document.url",
    "document.location",
    "window.name"
  ];

  const sinks = [
    ".innerhtml",
    ".outerhtml",
    "document.write(",
    "document.writeln(",
    "eval(",
    "insertadjacenthtml("
  ];

  const sourceMatches = sources.filter(
    (item) => source.includes(item)
  );

  const sinkMatches = sinks.filter(
    (item) => source.includes(item)
  );

  return {
    sourceCount: sourceMatches.length,
    sinkCount: sinkMatches.length,
    sources: sourceMatches,
    sinks: sinkMatches,
    potentialDomXss:
      sourceMatches.length > 0 &&
      sinkMatches.length > 0
  };
}


function detectMixedContent() {
  if (location.protocol !== "https:") {
    return [];
  }

  return Array.from(
    document.querySelectorAll(
      "img, script, link, iframe, audio, video, source"
    )
  )
    .map((element) =>
      element.src || element.href || ""
    )
    .filter((url) =>
      url.startsWith("http://")
    );
}


function fingerprintTechnology() {
  const technologies = new Set();

  const generator =
    document.querySelector(
      'meta[name="generator"]'
    );

  if (generator?.content) {
    technologies.add(
      generator.content.trim()
    );
  }

  const assets = Array.from(
    document.querySelectorAll(
      "script[src], link[href]"
    )
  )
    .map((element) =>
      element.src || element.href || ""
    )
    .join(" ")
    .toLowerCase();

  if (assets.includes("jquery")) {
    technologies.add("jQuery");
  }

  if (assets.includes("bootstrap")) {
    technologies.add("Bootstrap");
  }

  if (assets.includes("lodash")) {
    technologies.add("Lodash");
  }

  if (
    assets.includes("/_next/") ||
    document.querySelector("#__next")
  ) {
    technologies.add("Next.js");
  }

  if (
    assets.includes("react") ||
    document.querySelector("[data-reactroot]")
  ) {
    technologies.add("React");
  }

  if (
    assets.includes("angular") ||
    document.querySelector(
      "[ng-app], [ng-version]"
    )
  ) {
    technologies.add("Angular");
  }

  if (
    assets.includes("vue.js") ||
    assets.includes("vue.min.js") ||
    document.querySelector("[data-v-app]")
  ) {
    technologies.add("Vue.js");
  }

  if (
    assets.includes("wp-content") ||
    assets.includes("wp-includes") ||
    generator?.content
      ?.toLowerCase()
      .includes("wordpress")
  ) {
    technologies.add("WordPress");
  }

  return Array.from(technologies);
}


function detectCaptchaSurface() {
  return Boolean(
    document.querySelector(
      '.g-recaptcha, iframe[src*="recaptcha"], input[name*="captcha" i]'
    )
  );
}


function collectLinks() {
  return Array.from(
    document.querySelectorAll("a[href]")
  )
    .slice(0, 200)
    .map((anchor) => anchor.href);
}


function gatherPassiveDomData() {
  return {
    url: location.href,
    origin: location.origin,
    title: document.title,

    isHttps:
      location.protocol === "https:",

    forms: collectForms(),

    scripts: collectScripts(),

    domAnalysis:
      analyzeDomJavascript(),

    mixedContent:
      detectMixedContent(),

    technologies:
      fingerprintTechnology(),

    captchaSurface:
      detectCaptchaSurface(),

    links:
      collectLinks(),

    linkCount:
      document.querySelectorAll("a[href]").length
  };
}


chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    if (
      message?.type !==
        "COLLECT_PASSIVE_DOM_DATA" &&
      message?.action !==
        "COLLECT_PAGE_DATA"
    ) {
      return false;
    }

    sendResponse(
      gatherPassiveDomData()
    );

    return false;
  }
);