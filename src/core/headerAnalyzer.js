"use strict";

function extractHeaderDomain(headerValue) {
  if (!headerValue) return null;
  const match = headerValue.match(/@([\w.\-]+)/);
  return match ? match[1].toLowerCase() : null;
}

function parseFromHeader(from) {
  if (!from) return { email: null, domain: null };
  const emailMatch = from.match(/[\w.+\-]+@([\w.\-]+)/);
  if (!emailMatch) return { email: null, domain: null };
  return { email: emailMatch[0], domain: emailMatch[1].toLowerCase() };
}

// Parse a full address header into display name + email + domain.
// Handles: "Name" <a@b.com> | Name <a@b.com> | a@b.com
function parseAddress(raw) {
  if (!raw) return { name: "", email: null, domain: null };
  let name = "", email = null;
  const angle = raw.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  if (angle) {
    name = angle[1].trim().replace(/^["']|["']$/g, "");
    email = angle[2].trim();
  } else {
    const m = raw.match(/[\p{L}\p{N}\p{M}_.+\-]+@[\p{L}\p{N}\p{M}_.\-]+/u);
    email = m ? m[0] : null;
  }
  const domain = email && email.includes("@") ? email.split("@")[1].toLowerCase() : null;
  return { name, email, domain };
}

function detectReplyToMismatch(fromHeader, replyToHeader) {
  if (!replyToHeader) return false;
  const fromDomain = extractHeaderDomain(fromHeader);
  const replyDomain = extractHeaderDomain(replyToHeader);
  if (!fromDomain || !replyDomain) return false;
  return fromDomain !== replyDomain;
}

const PUBLIC_DOMAINS = [
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
  "protonmail.com", "icloud.com", "aol.com", "mail.com",
];

function isPublicDomain(domain) {
  return PUBLIC_DOMAINS.includes(domain.toLowerCase());
}

function detectUrgencyInText(text) {
  const keywords = [
    "pilne", "natychmiast", "blokada konta", "reset hasła", "zablokowane",
    "weryfikacja", "wygasa", "ostatnia szansa", "działaj teraz", "kliknij teraz",
    "potwierdź teraz", "twoje konto", "hasło wygasło", "zawieszone",
    "urgent", "immediately", "account blocked", "password reset", "suspended",
    "verify", "expires", "last chance", "act now", "click now",
  ];
  const lower = text.toLowerCase();
  return keywords.some(kw => lower.includes(kw));
}

// (15) Requests for credentials / sensitive data.
function detectCredentialRequest(text) {
  const keywords = [
    "hasło", "haslo", "password", "numer karty", "card number", "cvv", "cvc",
    "kod blik", "blik", "kod autoryzacyjny", "kod sms", "kod 2fa", "kod weryfikacyjny",
    "one-time", "one time", "otp", "verification code", "dane logowania",
    "zaloguj się", "zaloguj sie", "potwierdź dane", "potwierdz dane",
    "numer konta", "numer pesel", "pesel", "pin", "social security", "login i hasło",
  ];
  const lower = (text || "").toLowerCase();
  return keywords.some(keyword => {
    const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(^|[^\\p{L}\\p{N}])${escaped}($|[^\\p{L}\\p{N}])`, "u").test(lower);
  });
}

// (1) SPF / DKIM / DMARC results from the Authentication-Results header(s).
function parseAuthResults(headers) {
  const arr = (headers && headers["authentication-results"]) || [];
  const joined = (Array.isArray(arr) ? arr.join(" ; ") : String(arr)).toLowerCase();
  const grab = (re) => { const m = joined.match(re); return m ? m[1] : null; };
  return {
    spf: grab(/spf=(\w+)/),
    dkim: grab(/dkim=(\w+)/),
    dmarc: grab(/dmarc=(\w+)/),
  };
}

// (2,3) Display-name spoofing: the visible name lies about who sent it.
function analyzeDisplayName(name, actualDomain, companyDomains) {
  const reasons = [];
  if (!name) return reasons;
  const lname = name.toLowerCase();

  // (3) Display name itself contains an email address with a different domain.
  const emailInName = name.match(/[\w.+\-]+@([\w.\-]+\.[a-z]{2,})/i);
  if (emailInName) {
    const nameDomain = emailInName[1].toLowerCase();
    if (actualDomain && nameDomain !== actualDomain) reasons.push("display_name_is_email");
  } else {
    // (2) Display name mentions a bare domain that differs from the real one.
    const domainInName = name.match(/\b([\w\-]+\.(?:com|pl|net|org|eu|de|co|io|gov|edu|info|biz|us|uk))\b/i);
    if (domainInName) {
      const nameDomain = domainInName[1].toLowerCase();
      if (actualDomain && nameDomain !== actualDomain) reasons.push("display_name_domain_mismatch");
    }
  }

  // Display name impersonates a company while the real sender is not the company.
  if (companyDomains && companyDomains.length && actualDomain) {
    const isCompanySender = companyDomains.some(cd => {
      const c = cd.toLowerCase();
      return actualDomain === c || actualDomain.endsWith("." + c);
    });
    if (!isCompanySender) {
      for (const cd of companyDomains) {
        const c = cd.toLowerCase();
        const sld = c.split(".")[0];
        if (lname.includes(c) || (sld.length >= 4 && new RegExp(`\\b${sld}\\b`).test(lname))) {
          reasons.push("display_name_spoofs_company");
          break;
        }
      }
    }
  }
  return reasons;
}

const LATIN_TLDS = [
  "pl", "com", "net", "org", "eu", "de", "fr", "co", "uk", "io",
  "info", "biz", "es", "it", "nl", "cz", "sk", "se", "no", "dk",
];

// (17) Script/language mismatch: substantial Cyrillic text from a Latin-TLD sender.
function hasCyrillicMismatch(text, senderTld) {
  const cyr = ((text || "").match(/[Ѐ-ӿ]/g) || []).length;
  if (cyr < 6) return false;
  return LATIN_TLDS.includes((senderTld || "").toLowerCase());
}

globalThis.PGHeaderAnalyzer = {
  extractHeaderDomain, parseFromHeader, parseAddress, detectReplyToMismatch,
  isPublicDomain, detectUrgencyInText, detectCredentialRequest,
  parseAuthResults, analyzeDisplayName, hasCyrillicMismatch,
};

if (typeof module !== "undefined") {
  module.exports = {
    extractHeaderDomain, parseFromHeader, parseAddress, detectReplyToMismatch,
    isPublicDomain, detectUrgencyInText, detectCredentialRequest,
    parseAuthResults, analyzeDisplayName, hasCyrillicMismatch,
  };
}
