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

  console.log(`\n${pass}/${pass + fail} testów przeszło` + (fail ? ` — ${fail} BŁĄD` : " — OK"));
  process.exit(fail ? 1 : 0);
})();
