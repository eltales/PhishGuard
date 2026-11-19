"use strict";

// End-to-end self-test: runs the real analyzeMessage() (the same code the
// background event page runs) against every .eml in ../test-emails and checks
// the detected risk level. Mocks the Thunderbird `browser.messages` API and
// provides a minimal DOMParser. Run: node tools/selftest.js

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const EML_DIR = path.join(ROOT, "test-emails");

// --- Minimal DOMParser sufficient for our selectors -------------------------
class FakeDoc {
  constructor(html) { this.html = html; }
  querySelectorAll(sel) {
    if (sel === "a[href]") {
      const out = [];
      const re = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
      let m;
      while ((m = re.exec(this.html))) {
        const hrefM = m[1].match(/href\s*=\s*["']?([^"'\s>]+)/i);
        const href = hrefM ? hrefM[1] : "";
        const text = m[2].replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
        out.push({ getAttribute: (k) => (k === "href" ? href : null), textContent: text });
      }
      return out;
    }
    if (sel === "img") return (this.html.match(/<img\b/gi) || []).map(() => ({}));
    return [];
  }
  get body() {
    const text = this.html
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ");
    return { textContent: text };
  }
}
class FakeDOMParser { parseFromString(html) { return new FakeDoc(html); } }

// --- Minimal .eml parser ----------------------------------------------------
function splitHeadersBody(raw) {
  const idx = raw.indexOf("\n\n");
  if (idx === -1) return { headers: raw, body: "" };
  return { headers: raw.slice(0, idx), body: raw.slice(idx + 2) };
}
function toHeaderMap(headerBlock) {
  const map = {};
  const unfolded = headerBlock.replace(/\n[ \t]+/g, " ");
  for (const line of unfolded.split("\n")) {
    const m = line.match(/^([\w\-]+):\s?(.*)$/);
    if (!m) continue;
    const name = m[1].toLowerCase();
    (map[name] = map[name] || []).push(m[2]);
  }
  return map;
}
function getH(map, name) { return map[name] ? map[name][0] : ""; }

function parseEntity(headerMap, body, parts, attachments) {
  const ct = getH(headerMap, "content-type") || "text/plain";
  const ctLower = ct.toLowerCase();
  const disp = (getH(headerMap, "content-disposition") || "").toLowerCase();

  if (ctLower.startsWith("multipart/")) {
    const b = (ct.match(/boundary="?([^";]+)"?/i) || [])[1];
    if (!b) return;
    const marker = "--" + b;
    const segs = body.split(marker);
    for (let seg of segs) {
      seg = seg.replace(/^\r?\n/, "");
      if (!seg.trim() || seg.startsWith("--")) continue; // preamble / closing
      const { headers, body: sb } = splitHeadersBody(seg);
      parseEntity(toHeaderMap(headers), sb, parts, attachments);
    }
    return;
  }

  const nameM = disp.match(/filename="?([^";]+)"?/i) || ct.match(/name="?([^";]+)"?/i);
  if (disp.includes("attachment") || nameM) {
    attachments.push({ name: nameM ? nameM[1] : "", contentType: ctLower.split(";")[0].trim() });
    return;
  }
  parts.push({ contentType: ctLower.split(";")[0].trim(), body });
}

function parseEml(raw) {
  raw = raw.replace(/\r\n/g, "\n");
  const { headers, body } = splitHeadersBody(raw);
  const headerMap = toHeaderMap(headers);
  const parts = [];
  const attachments = [];
  parseEntity(headerMap, body, parts, attachments);
  return { full: { headers: headerMap, parts }, attachments };
}

// --- Load core + analyzer into a sandbox (mirrors the background page) -------
const FILES = [
  "src/core/domainSimilarity.js",
  "src/core/urlAnalyzer.js",
  "src/core/headerAnalyzer.js",
  "src/core/attachmentAnalyzer.js",
  "src/core/riskScoring.js",
  "src/background/messageAnalyzer.js",
];

let current = { full: { headers: {}, parts: [] }, attachments: [] };
const sandbox = {
  console,
  URL,                 // present in Thunderbird; the URL-based link checks need it
  URLSearchParams,
  DOMParser: FakeDOMParser,
  browser: {
    messages: {
      getFull: async () => current.full,
      listAttachments: async () => current.attachments,
    },
  },
};
sandbox.globalThis = sandbox;
sandbox.global = sandbox;
vm.createContext(sandbox);
for (const f of FILES) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, f), "utf8"), sandbox, { filename: f });
}

// --- Test settings (matches README) -----------------------------------------
const settings = {
  companyDomains: ["example.com"],
  trustedDomains: ["trusted-service.test", "microsoft.com", "google.com", "apple.com"],
  knownSenders: [],
  adminReportEmail: "security@example.com",
  warnOnTaggedEmail: true,
  warnOnSuspiciousLink: true,
};

// file -> minimum expected risk (ordinal). Trusted must stay low.
const LEVEL = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const EXPECT = {
  "test-phishing-lookalike.eml": { min: "high" },
  "test-medium-risk.eml": { min: "medium" },
  "test-trusted-domain.eml": { max: "low" },
  "test-auth-fail.eml": { min: "high" },
  "test-display-name-spoof.eml": { min: "high" },
  "test-display-name-email.eml": { min: "medium" },
  "test-url-tricks.eml": { min: "high" },
  "test-attachments.eml": { min: "medium" },
  "test-image-only.eml": { min: "medium" },
  "test-cyrillic.eml": { min: "medium" },
};

(async () => {
  let pass = 0, fail = 0;
  for (const file of Object.keys(EXPECT)) {
    const raw = fs.readFileSync(path.join(EML_DIR, file), "utf8");
    current = parseEml(raw);
    const result = await sandbox.analyzeMessage(1, settings);
    const risk = result ? result.risk : "none";
    const score = result ? result.score : 0;
    const exp = EXPECT[file];

    let ok = true;
    if (exp.min && LEVEL[risk] < LEVEL[exp.min]) ok = false;
    if (exp.max && LEVEL[risk] > LEVEL[exp.max]) ok = false;

    const want = exp.min ? `>= ${exp.min}` : `<= ${exp.max}`;
    console.log(
      `${ok ? "PASS" : "FAIL"}  ${file.padEnd(30)} risk=${risk.padEnd(8)} score=${String(score).padStart(3)}  (oczekiwano ${want})`
    );
    if (!ok) console.log("        powody:", (result ? result.reasons : []).join(", "));
    ok ? pass++ : fail++;
  }
  const trustCases = [
    { name: "similar sender domain", sender: "exarnple.com" },
    { name: "Unicode sender domain", sender: "exаmple.com" },
    { name: "mixed scripts in the subject", sender: "vendor.example", subject: "Dаta" },
    { name: "double extension", sender: "vendor.example", attachment: "document.pdf.exe" },
    { name: "executable script", sender: "vendor.example", attachment: "test.js" },
    { name: "benign trusted sender", sender: "vendor.example", subject: "Dane і дані", allowed: true },
  ];
  for (const { name, sender, subject, attachment, allowed = false } of trustCases) {
    current = {
      full: { headers: { from: [`sender@${sender}`], subject: [subject || "Status"] }, parts: [] },
      attachments: attachment ? [{ name: attachment }] : [],
    };
    const result = await sandbox.analyzeMessage(1, {
      ...settings,
      trustedDomains: [sender],
      knownSenders: [sender],
    });
    const discounted = result.reasons.includes("trusted_domain") || result.reasons.includes("known_sender");
    const ok = result.details.trustRestricted === !allowed && discounted === allowed &&
      (allowed ? result.risk === "low" : LEVEL[result.risk] >= LEVEL.medium);
    console.log(`${ok ? "PASS" : "FAIL"}  Trust: ${name}`);
    ok ? pass++ : fail++;
  }

  const regressionCases = [
    {
      name: "trusted Atlassian subdomains and repeated tracking links",
      sender: "updates@po.atlassian.com",
      body: "Shipping update. Summarize outstanding tasks and blockers for this week.",
      links: Array.from({ length: 12 }, (_, i) => ({
        href: `https://track.atlassian.com/tracking/${i}`, text: "Read the update",
      })),
      trustedDomains: ["atlassian.com"], max: "low",
    },
    {
      name: "company sender with a large signature",
      sender: "manager@example.com", body: "Password policy expires this week.",
      links: Array.from({ length: 12 }, (_, i) => ({
        href: `https://intranet.example.com/page/${i}`, text: "Documentation",
      })),
      max: "low",
    },
    {
      name: "internal URL under the configured company domain",
      sender: "manager@example.com", body: "Shipping package updates.",
      companyDomains: ["example.com", "example.lan"],
      links: [{ href: "http://nuget.example.lan:8080/", text: "http://nuget.example.lan:8080/" }],
      max: "low",
    },
    {
      name: "link count alone does not raise the score",
      sender: "news@vendor.test", body: "Monthly update.",
      links: Array.from({ length: 12 }, (_, i) => ({ href: `https://vendor.test/${i}`, text: "Read" })),
      exactScore: 0, max: "low",
    },
    {
      name: "same-host repeated indicators are scored once",
      sender: "news@vendor.test", body: "Monthly update.",
      links: Array.from({ length: 12 }, (_, i) => ({ href: `http://192.0.2.1/${i}`, text: "Read" })),
      exactScore: 25,
    },
    {
      name: "trusted sibling tracking must warn when displayed and actual hosts differ",
      sender: "updates@id.atlassian.com", body: "Your profile update.",
      trustedDomains: ["atlassian.com"],
      links: [{ href: "https://track.atlassian.com/tracking/test", text: "https://id.atlassian.com/manage-profile" }],
      min: "medium", restricted: true,
    },
    {
      name: "unrelated destination still flags misleading text",
      sender: "updates@id.atlassian.com", body: "Your profile update.",
      trustedDomains: ["atlassian.com"],
      links: [{ href: "https://attacker.test/", text: "https://id.atlassian.com/manage-profile" }],
      min: "medium", restricted: true,
    },
    {
      name: "trusted company sender cannot hide authentication failures",
      sender: "manager@example.com", body: "Monthly update.",
      auth: "mx.example; spf=fail; dkim=fail; dmarc=fail", min: "high",
    },
    {
      name: "trusted company sender cannot hide dangerous attachments",
      sender: "manager@example.com", body: "Monthly update.",
      attachment: "invoice.pdf.exe", min: "medium", restricted: true,
    },
    {
      name: "compromised company sender with a hidden external destination",
      sender: "manager@example.com", body: "Monthly update.",
      links: [{ href: "https://attacker.test/", text: "https://portal.example.com/" }],
      min: "medium", restricted: true,
    },
    {
      name: "compromised company sender with a lookalike link",
      sender: "manager@example.com", body: "Monthly update.",
      links: [{ href: "https://exarnple.com/", text: "View document" }],
      min: "medium", restricted: true,
    },
    {
      name: "trusted sender address cannot hide double extensions",
      sender: "contact@vendor.test", body: "Monthly update.",
      knownSenders: ["contact@vendor.test"],
      attachment: "invoice.pdf.exe", min: "medium", restricted: true,
    },
    {
      name: "trust a full sender address",
      sender: "contact@vendor.test", body: "Password reset expires soon.",
      knownSenders: ["contact@vendor.test"], max: "low",
    },
    {
      name: "a trusted sender does not trust the entire domain",
      sender: "other@vendor.test", body: "Password reset expires soon.",
      knownSenders: ["contact@vendor.test"], min: "medium",
    },
    {
      name: "a different Atlassian TLD is not automatically trusted",
      sender: "updates@po.atlassian.net", body: "Monthly update.",
      companyDomains: ["atlassian.com"], trustedDomains: ["atlassian.com"],
      links: Array.from({ length: 12 }, (_, i) => ({ href: `https://track.atlassian.com/${i}`, text: "Read" })),
      exactScore: 30, restricted: true, max: "medium",
    },
    {
      name: "trusted address still cannot hide a lookalike",
      sender: "contact@exarnple.com", body: "Password reset expires soon.",
      knownSenders: ["contact@exarnple.com"], min: "medium", restricted: true,
    },
    {
      name: "a trusted root never trusts a deceptive suffix",
      sender: "contact@atlassian.com.attacker.test", body: "Password reset expires soon.",
      trustedDomains: ["atlassian.com"], min: "medium",
    },
  ];
  for (const test of regressionCases) {
    current = {
      full: {
        headers: {
          from: [test.sender], subject: ["Status"],
          "authentication-results": [test.auth || ""],
        },
        parts: [{ contentType: "text/html", body: `<p>${test.body}</p>` +
          (test.links || []).map(link => `<a href="${link.href}">${link.text}</a>`).join("") }],
      },
      attachments: test.attachment ? [{ name: test.attachment }] : [],
    };
    const result = await sandbox.analyzeMessage(1, {
      ...settings,
      companyDomains: test.companyDomains || settings.companyDomains,
      trustedDomains: test.trustedDomains || [],
      knownSenders: test.knownSenders || [],
    });
    const ok = (!test.min || LEVEL[result.risk] >= LEVEL[test.min]) &&
      (!test.max || LEVEL[result.risk] <= LEVEL[test.max]) &&
      (test.exactScore === undefined || result.score === test.exactScore) &&
      (test.restricted === undefined || result.details.trustRestricted === test.restricted);
    console.log(`${ok ? "PASS" : "FAIL"}  Regression: ${test.name} (${result.risk}, ${result.score})`);
    if (!ok) console.log("        reasons:", result.reasons.join(", "));
    ok ? pass++ : fail++;
  }

  const check = (name, ok) => {
    console.log(`${ok ? "PASS" : "FAIL"}  Regression: ${name}`);
    ok ? pass++ : fail++;
  };
  check("credential keywords match whole words",
    !sandbox.PGHeaderAnalyzer.detectCredentialRequest("Shipping grouping pinning") &&
    sandbox.PGHeaderAnalyzer.detectCredentialRequest("Enter your PIN.") &&
    sandbox.PGHeaderAnalyzer.detectCredentialRequest("Podaj hasło"));
  check("a genuine subdomain is not a TLD swap",
    sandbox.PGDomainSimilarity.checkSimilarity("id.atlassian.com", "atlassian.com").score === 0);

  // Run the actual background message handler and storage listeners.
  const stored = { phishguardSettings: { ...settings, trustedDomains: [] } };
  let onStorageChanged;
  let storageUpdate = Promise.resolve();
  sandbox.browser.storage = {
    local: {
      async get(key) { return { [key]: stored[key] }; },
      async set(values) {
        const changes = Object.fromEntries(Object.entries(values).map(([key, newValue]) =>
          [key, { oldValue: stored[key], newValue }]));
        Object.assign(stored, values);
        storageUpdate = onStorageChanged(changes, "local");
      },
    },
    onChanged: { addListener(listener) { onStorageChanged = listener; } },
  };
  sandbox.browser.scripting = { messageDisplay: {
    getRegisteredScripts: async () => [{ id: "pg-display-script", js: ["src/i18n.js"] }],
    registerScripts: async () => {},
  } };
  sandbox.browser.messageDisplay = { onMessagesDisplayed: { addListener() {} } };
  sandbox.browser.tabs = { query: async () => [], sendMessage: async () => {} };
  sandbox.browser.runtime = { onMessage: { addListener(listener) { this.handle = listener; } } };
  for (const file of ["src/i18n.js", "src/background/settingsService.js", "src/background/background.js"]) {
    vm.runInContext(fs.readFileSync(path.join(ROOT, file), "utf8"), sandbox, { filename: file });
  }
  const dispatch = msg => sandbox.browser.runtime.onMessage.handle(msg, {});
  current = { full: { headers: { from: ["Contact <contact@vendor.test>"], subject: ["Password reset expires"] }, parts: [] }, attachments: [] };
  const beforeTrust = await dispatch({ type: "pg_get_analysis", messageId: 20 });
  const trust = await dispatch({ type: "pg_mark_safe", messageId: 20 });
  await storageUpdate;
  const afterTrust = await dispatch({ type: "pg_get_analysis", messageId: 20 });
  check("trust action persists the full address and refreshes cached analysis",
    beforeTrust.result.risk === "medium" && trust.ok &&
    stored.phishguardSettings.knownSenders.includes("contact@vendor.test") &&
    afterTrust.result.risk === "low" && !stored.pgSafe_20);
  vm.runInContext("analysisCache.clear()", sandbox);
  const reopened = await dispatch({ type: "pg_get_analysis", messageId: 21 });
  check("sender trust survives a cache reset and a new message ID", reopened.result.risk === "low");
  const revoked = { ...stored.phishguardSettings, knownSenders: [] };
  await sandbox.browser.storage.local.set({ phishguardSettings: revoked });
  await storageUpdate;
  const afterRevoke = await dispatch({ type: "pg_get_analysis", messageId: 20 });
  check("removing sender trust restores warnings", afterRevoke.result.risk === "medium");
  current.attachments = [{ name: "document.pdf.exe" }];
  const blocked = await dispatch({ type: "pg_mark_safe", messageId: 22 });
  check("trust action rejects dangerous attachments", Boolean(blocked.error) && !stored.phishguardSettings.knownSenders.length);
  current.attachments = [];
  const concurrent = await Promise.all([
    dispatch({ type: "pg_mark_safe", messageId: 23 }),
    dispatch({ type: "pg_mark_safe", messageId: 24 }),
  ]);
  await storageUpdate;
  check("repeated trust actions do not duplicate entries",
    concurrent.every(response => response.ok) && stored.phishguardSettings.knownSenders.length === 1);

  const getFull = sandbox.browser.messages.getFull;
  const snapshot = current.full;
  let finishRead;
  sandbox.browser.messages.getFull = () => new Promise(resolve => { finishRead = resolve; });
  const stale = dispatch({ type: "pg_get_analysis", messageId: 30 });
  await new Promise(resolve => setImmediate(resolve));
  await sandbox.browser.storage.local.set({ phishguardSettings: revoked });
  await storageUpdate;
  finishRead(snapshot);
  await stale;
  sandbox.browser.messages.getFull = getFull;
  const refreshed = await dispatch({ type: "pg_get_analysis", messageId: 30 });
  check("an in-flight analysis cannot restore an outdated trust decision", refreshed.result.risk === "medium");

  console.log(`\n${pass}/${pass + fail} testów przeszło` + (fail ? ` — ${fail} BŁĄD` : " — OK"));
  process.exit(fail ? 1 : 0);
})();
