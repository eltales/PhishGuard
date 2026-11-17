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
  thresholdMedium: 30,
  thresholdHigh: 60,
  thresholdCritical: 90,
};

async function getSettings() {
  const stored = await browser.storage.local.get("phishguardSettings");
  return Object.assign({}, DEFAULT_SETTINGS, stored.phishguardSettings || {});
}

async function saveSettings(settings) {
  await browser.storage.local.set({ phishguardSettings: settings });
}

async function updateSettings(patch) {
  const current = await getSettings();
  await saveSettings(Object.assign(current, patch));
}
