"use strict";

const DEFAULT_SETTINGS = {
  language: "en",
  companyEmail: "",
  companyDomains: [],
  domainProfiles: [],
  adminReportEmail: "",
  trustedDomains: ["microsoft.com", "google.com", "apple.com"],
  knownSenders: [],
  warnOnTaggedEmail: true,
  warnOnSuspiciousLink: true,
  reportButtonEnabled: true,
  reportMethod: "compose_email_report",
};

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function extractDomain(email) {
  const parts = email.trim().toLowerCase().split("@");
  return parts.length === 2 ? parts[1].replace(/\.$/, "") : null;
}

function buildDomainProfile(domain) {
  const labels = domain.split(".");
  const tld = labels.length > 1 ? labels[labels.length - 1] : "";
  const sld = labels.length > 1 ? labels[labels.length - 2] : labels[0];
  const skeleton = toSkeleton(domain);
  return { domain, sld, tld, normalized: domain, skeleton };
}

function toSkeleton(str) {
  const map = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x" };
  let r = str.toLowerCase();
  for (const [k, v] of Object.entries(map)) r = r.split(k).join(v);
  return r.replace(/rn/g, "m").replace(/vv/g, "w");
}

function showNotice(msg, type) {
  const el = document.getElementById(type === "error" ? "pg-error-notice" : "pg-save-notice");
  const other = document.getElementById(type === "error" ? "pg-save-notice" : "pg-error-notice");
  other.style.display = "none";
  el.textContent = msg;
  el.style.display = "block";
  if (type !== "error") setTimeout(() => { el.style.display = "none"; }, 3000);
}

async function loadSettings() {
  const stored = await browser.storage.local.get("phishguardSettings");
  return Object.assign({}, DEFAULT_SETTINGS, stored.phishguardSettings || {});
}

async function init() {
  const settings = await loadSettings();
  const language = PGI18n.normalize(settings.language);
  document.getElementById("language").value = language;
  PGI18n.localizeDocument(document, language);

  document.getElementById("companyEmail").value = settings.companyEmail || "";
  document.getElementById("companyDomains").value = (settings.companyDomains || []).join("\n");
  document.getElementById("adminReportEmail").value = settings.adminReportEmail || "";
  document.getElementById("trustedDomains").value = (settings.trustedDomains || []).join("\n");
  document.getElementById("knownSenders").value = (settings.knownSenders || []).join("\n");
  document.getElementById("warnOnTaggedEmail").checked = settings.warnOnTaggedEmail !== false;
  document.getElementById("warnOnSuspiciousLink").checked = settings.warnOnSuspiciousLink !== false;
  document.getElementById("reportButtonEnabled").checked = settings.reportButtonEnabled !== false;

  if (settings.companyEmail) {
    const domain = extractDomain(settings.companyEmail);
    if (domain) showDetectedDomain(domain);
  }

  document.getElementById("companyEmail").addEventListener("input", (e) => {
    const val = e.target.value.trim();
    if (isValidEmail(val)) {
      const domain = extractDomain(val);
      if (domain) {
        showDetectedDomain(domain);
        // Auto-add to domains list if not already there
        const current = document.getElementById("companyDomains").value
          .split("\n").map(d => d.trim()).filter(Boolean);
        if (!current.includes(domain)) {
          current.unshift(domain);
          document.getElementById("companyDomains").value = current.join("\n");
        }
      }
    } else {
      document.getElementById("pg-detected-domain").style.display = "none";
    }
  });

  document.getElementById("pg-save-btn").addEventListener("click", save);
}

function showDetectedDomain(domain) {
  const el = document.getElementById("pg-detected-domain");
  const t = PGI18n.forLanguage(document.documentElement.lang);
  el.textContent = t("detectedDomain", domain);
  el.style.display = "block";
}

async function save() {
  const language = PGI18n.normalize(document.getElementById("language").value);
  const t = PGI18n.forLanguage(document.documentElement.lang);
  const companyEmail = document.getElementById("companyEmail").value.trim();
  const adminReportEmail = document.getElementById("adminReportEmail").value.trim();

  if (companyEmail && !isValidEmail(companyEmail)) {
    showNotice(t("invalidCompanyEmail"), "error");
    return;
  }
  if (adminReportEmail && !isValidEmail(adminReportEmail)) {
    showNotice(t("invalidAdminEmail"), "error");
    return;
  }

  const companyDomains = document.getElementById("companyDomains").value
    .split("\n").map(d => d.trim().toLowerCase()).filter(Boolean);

  const trustedDomains = document.getElementById("trustedDomains").value
    .split("\n").map(d => d.trim().toLowerCase()).filter(Boolean);

  const previous = await loadSettings();
  const knownSenders = document.getElementById("knownSenders").value
    .split("\n").map(sender => sender.trim().toLowerCase()).filter(Boolean);
  const previousSenders = new Set((previous.knownSenders || []).map(sender => sender.toLowerCase()));
  const invalidSender = knownSenders.find(sender => !previousSenders.has(sender) && !isValidEmail(sender));
  if (invalidSender) {
    showNotice(t("invalidTrustedSender", invalidSender), "error");
    return;
  }
  const blockedSender = knownSenders.find(sender => !previousSenders.has(sender) && (
    PGDomainSimilarity.hasMixedScriptHomoglyphs(sender) ||
    PGDomainSimilarity.checkAgainstAllCompanyDomains(extractDomain(sender), companyDomains).score > 0
  ));
  if (blockedSender) {
    showNotice(t("blockedDomain", extractDomain(blockedSender)), "error");
    return;
  }
  const previouslyTrusted = new Set((previous.trustedDomains || []).map(domain => domain.toLowerCase()));
  const blockedDomain = trustedDomains.find(domain => !previouslyTrusted.has(domain) && (
    PGDomainSimilarity.hasMixedScriptHomoglyphs(domain) ||
    PGDomainSimilarity.checkAgainstAllCompanyDomains(domain, companyDomains).score > 0
  ));
  if (blockedDomain) {
    showNotice(t("blockedDomain", blockedDomain), "error");
    return;
  }

  const domainProfiles = companyDomains.map(buildDomainProfile);

  const settings = {
    ...previous,
    language,
    companyEmail,
    companyDomains,
    domainProfiles,
    adminReportEmail,
    trustedDomains,
    knownSenders,
    warnOnTaggedEmail: document.getElementById("warnOnTaggedEmail").checked,
    warnOnSuspiciousLink: document.getElementById("warnOnSuspiciousLink").checked,
    reportButtonEnabled: document.getElementById("reportButtonEnabled").checked,
    reportMethod: "compose_email_report",
  };

  await browser.storage.local.set({ phishguardSettings: settings });
  PGI18n.localizeDocument(document, language);
  if (companyEmail) showDetectedDomain(extractDomain(companyEmail));
  showNotice(PGI18n.forLanguage(language)("saved"), "success");
}

document.addEventListener("DOMContentLoaded", init);
