"use strict";

// Maps shared with constants.js — accessed via globals when loaded in the
// background page, via require() under Node (tests).
const PG_NORM_MAPS = (() => {
  if (typeof HOMOGLYPH_MAP !== "undefined") {
    return { homoglyphs: HOMOGLYPH_MAP, sequences: CONFUSABLE_SEQUENCES };
  }
  if (typeof require !== "undefined") {
    const c = require("./constants.js");
    return { homoglyphs: c.HOMOGLYPH_MAP, sequences: c.CONFUSABLE_SEQUENCES };
  }
  return { homoglyphs: {}, sequences: [] };
})();

function normalizeDomain(domain) {
  if (!domain) return "";
  let d = domain.toLowerCase().trim();
  if (d.endsWith(".")) d = d.slice(0, -1);
  return d;
}

function decodePunycode(domain) {
  try {
    const url = new URL("http://" + domain);
    return url.hostname;
  } catch {
    return domain;
  }
}

function isPunycode(domain) {
  return domain.split(".").some(label => label.startsWith("xn--"));
}

function toSkeleton(str) {
  let result = str.toLowerCase();
  for (const [char, replacement] of Object.entries(PG_NORM_MAPS.homoglyphs)) {
    result = result.split(char).join(replacement);
  }
  for (const [seq, replacement] of PG_NORM_MAPS.sequences) {
    result = result.split(seq).join(replacement);
  }
  return result;
}

function extractDomainParts(domain) {
  const normalized = normalizeDomain(domain);
  const labels = normalized.split(".");
  const tld = labels.length > 1 ? labels[labels.length - 1] : "";
  const sld = labels.length > 1 ? labels[labels.length - 2] : labels[0];
  return { domain: normalized, labels, sld, tld, skeleton: toSkeleton(normalized) };
}

function extractEmailDomain(email) {
  const parts = email.trim().toLowerCase().split("@");
  if (parts.length !== 2) return null;
  return normalizeDomain(parts[1]);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

globalThis.PGNormalization = {
  normalizeDomain, decodePunycode, isPunycode, toSkeleton,
  extractDomainParts, extractEmailDomain, isValidEmail,
};

if (typeof module !== "undefined") {
  module.exports = {
    normalizeDomain, decodePunycode, isPunycode, toSkeleton,
    extractDomainParts, extractEmailDomain, isValidEmail,
  };
}
