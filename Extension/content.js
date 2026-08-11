/**
 * content.js
 * Injected into every page. Provides DOM-level inspection utilities that
 * the popup can invoke via chrome.scripting.executeScript or messaging.
 * Purely passive/read-only inspection of the current page's own DOM.
 */

/** Collect all <form> elements and whether they contain password fields. */
function collectForms() {
  const forms = Array.from(document.querySelectorAll("form"));
  return forms.map((form) => ({
    action: form.action || null,
    method: (form.method || "GET").toUpperCase(),
    hasPasswordField: !!form.querySelector('input[type="password"]'),
    fieldCount: form.querySelectorAll("input, textarea, select").length
  }));
}

/** Collect external and inline script information. */
function collectScripts() {
  const scripts = Array.from(document.querySelectorAll("script"));
  const external = scripts.filter((s) => s.src).map((s) => s.src);
  const inlineCount = scripts.filter((s) => !s.src && s.textContent.trim().length > 0).length;
  return { externalScripts: external, inlineScriptCount: inlineCount };
}

/** Detect mixed content: page is HTTPS but references HTTP resources. */
function detectMixedContent() {
  if (location.protocol !== "https:") return [];
  const resources = Array.from(document.querySelectorAll("img, script, link, iframe"));
  const mixed = resources
    .map((el) => el.src || el.href)
    .filter((url) => url && url.startsWith("http://"));
  return mixed;
}

/** Basic technology fingerprinting from meta tags and global variables. */
function fingerprintTechnology() {
  const generator = document.querySelector('meta[name="generator"]');
  const techHints = [];
  if (generator) techHints.push(generator.content);
  if (window.jQuery) techHints.push(`jQuery ${window.jQuery.fn.jquery}`);
  if (window.React) techHints.push("React");
  if (window.angular) techHints.push("AngularJS");
  if (document.querySelector('[data-reactroot], #__next')) techHints.push("React/Next.js");
  if (document.querySelector('meta[name="generator"][content*="WordPress"]')) techHints.push("WordPress");
  return techHints;
}

/** Gather a snapshot of page-level passive data. Triggered on demand via message. */
function gatherPassiveDomData() {
  return {
    url: location.href,
    isHttps: location.protocol === "https:",
    forms: collectForms(),
    scripts: collectScripts(),
    mixedContent: detectMixedContent(),
    technology: fingerprintTechnology(),
    linkCount: document.querySelectorAll("a[href]").length,
    title: document.title
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "COLLECT_PASSIVE_DOM_DATA") {
    sendResponse(gatherPassiveDomData());
    return true;
  }
  return false;
});
