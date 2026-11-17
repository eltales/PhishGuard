"use strict";

const LINK_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
  "goo.gl", "short.link", "rebrand.ly", "is.gd", "cli.gs",
];

// (14) TLDs disproportionately abused for phishing / malware.
const ABUSED_TLDS = [
  "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "work", "click",
  "link", "country", "loan", "men", "download", "gdn", "kim", "rest", "fit",
];

function extractDomainFromUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function isIPUrl(url) {
  try {
    const u = new URL(url);
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(u.hostname);
  } catch {
    return false;
  }
}

function isLinkShortener(url) {
  const domain = extractDomainFromUrl(url);
  return domain ? LINK_SHORTENERS.includes(domain) : false;
}

function isPunycodeUrl(url) {
  const domain = extractDomainFromUrl(url);
  if (!domain) return false;
  return domain.split(".").some(l => l.startsWith("xn--"));
}

// (11) "@" trick: everything before @ is user-info; the real host follows it.
// https://example.com@evil.ru/ actually points to evil.ru.
function hasUserInfo(url) {
  try { return !!new URL(url).username; } catch { return false; }
}

// (13) Suspiciously deep subdomain nesting or an unusually long host.
function hasManySubdomains(url) {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return host.split(".").length >= 5 || host.length > 50;
  } catch { return false; }
}

// (14) Host uses a commonly abused TLD.
function isAbusedTld(url) {
  const domain = extractDomainFromUrl(url);
  if (!domain) return false;
  return ABUSED_TLDS.includes(domain.split(".").pop());
}

function extractLinksFromHtml(html) {
  const links = [];
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  doc.querySelectorAll("a[href]").forEach(a => {
    const href = a.getAttribute("href") || "";
    const text = a.textContent.trim();
    if (href && (href.startsWith("http://") || href.startsWith("https://"))) {
      links.push({ href, text });
    }
  });
  return links;
}

function detectLinkMismatch(href, visibleText) {
  const hrefDomain = extractDomainFromUrl(href);
  if (!hrefDomain) return false;
  // Check if visible text looks like a URL
  const cleanText = visibleText.trim();
  if (cleanText.startsWith("http://") || cleanText.startsWith("https://") || cleanText.includes(".")) {
    try {
      const textUrl = cleanText.startsWith("http") ? cleanText : "https://" + cleanText;
      const textDomain = extractDomainFromUrl(textUrl);
      if (textDomain && textDomain !== hrefDomain) return true;
    } catch {
      // not a URL, ignore
    }
  }
  return false;
}

function analyzeUrl(href, visibleText) {
  const reasons = [];
  let score = 0;

  if (isIPUrl(href)) { reasons.push("link_ip_address"); score += 25; }
  if (isLinkShortener(href)) { reasons.push("link_shortener"); score += 15; }
  if (isPunycodeUrl(href)) { reasons.push("link_punycode"); score += 30; }
  if (hasUserInfo(href)) { reasons.push("url_userinfo"); score += 30; }
  if (hasManySubdomains(href)) { reasons.push("url_many_subdomains"); score += 15; }
  if (isAbusedTld(href)) { reasons.push("url_abused_tld"); score += 15; }
  if (visibleText && detectLinkMismatch(href, visibleText)) {
    reasons.push("link_text_href_mismatch"); score += 35;
  }

  return { href, visibleText, score, reasons };
}

globalThis.PGUrlAnalyzer = {
  extractDomainFromUrl, isIPUrl, isLinkShortener, isPunycodeUrl,
  hasUserInfo, hasManySubdomains, isAbusedTld,
  extractLinksFromHtml, detectLinkMismatch, analyzeUrl,
};

if (typeof module !== "undefined") {
  module.exports = {
    extractDomainFromUrl, isIPUrl, isLinkShortener, isPunycodeUrl,
    hasUserInfo, hasManySubdomains, isAbusedTld,
    extractLinksFromHtml, detectLinkMismatch, analyzeUrl,
  };
}
