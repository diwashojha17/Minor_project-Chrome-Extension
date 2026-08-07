/**
 * crawler.js
 * Lightweight same-origin crawler used during an active scan to discover
 * additional in-scope pages (depth-limited, same-origin only) so the scanner
 * can check more than just the current page. Only invoked when active scanning
 * is enabled by the user.
 */

const MAX_PAGES = 5;
const MAX_DEPTH = 1;

/** Extract same-origin links from an HTML string. */
function extractSameOriginLinks(html, origin) {
  const links = new Set();
  const regex = /href=["']([^"'#]+)["']/gi;
  let match;
  while ((match = regex.exec(html)) !== null) {
    try {
      const resolved = new URL(match[1], origin);
      if (resolved.origin === origin) {
        links.add(resolved.href);
      }
    } catch (e) {
      // ignore malformed hrefs
    }
  }
  return Array.from(links);
}

/**
 * Crawl same-origin pages starting from startUrl, up to MAX_PAGES and MAX_DEPTH.
 * Returns an array of { url, status } for discovered pages.
 */
async function crawlSameOrigin(startUrl) {
  const origin = new URL(startUrl).origin;
  const visited = new Set();
  const queue = [{ url: startUrl, depth: 0 }];
  const results = [];

  while (queue.length > 0 && results.length < MAX_PAGES) {
    const { url, depth } = queue.shift();
    if (visited.has(url) || depth > MAX_DEPTH) continue;
    visited.add(url);

    try {
      const response = await fetch(url, { method: "GET", credentials: "omit" });
      const html = await response.text();
      results.push({ url, status: response.status });

      if (depth < MAX_DEPTH) {
        const newLinks = extractSameOriginLinks(html, origin).filter((l) => !visited.has(l));
        newLinks.forEach((l) => queue.push({ url: l, depth: depth + 1 }));
      }
    } catch (e) {
      results.push({ url, error: e.message });
    }
  }

  return results;
}

if (typeof module !== "undefined") {
  module.exports = { crawlSameOrigin, extractSameOriginLinks };
}
