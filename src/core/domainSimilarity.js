"use strict";

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i]);
  for (let j = 1; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

function damerauLevenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 2 }, () => new Array(n + 2).fill(0));
  const maxDist = m + n;
  dp[0][0] = maxDist;
  for (let i = 0; i <= m; i++) { dp[i + 1][0] = maxDist; dp[i + 1][1] = i; }
  for (let j = 0; j <= n; j++) { dp[0][j + 1] = maxDist; dp[1][j + 1] = j; }

  const da = {};
  for (const c of a + b) da[c] = 0;

  for (let i = 1; i <= m; i++) {
    let db = 0;
    for (let j = 1; j <= n; j++) {
      const i1 = da[b[j - 1]] || 0;
      const j1 = db;
      let cost = 1;
      if (a[i - 1] === b[j - 1]) { cost = 0; db = j; }
      dp[i + 1][j + 1] = Math.min(
        dp[i][j] + cost,
        dp[i + 1][j] + 1,
        dp[i][j + 1] + 1,
        dp[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1)
      );
    }
    da[a[i - 1]] = i;
  }
  return dp[m + 1][n + 1];
}

function toSkeleton(str) {
  const map = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "8": "b",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "α": "a", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "χ": "x",
  };
  let result = str.toLowerCase();
  for (const [k, v] of Object.entries(map)) result = result.split(k).join(v);
  result = result.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d");
  return result;
}

function hasMixedScriptHomoglyphs(text) {
  for (const [word] of text.matchAll(/[\p{L}\p{M}\p{N}]+/gu)) {
    if (!/\p{Script=Latin}/u.test(word)) continue;
    const otherLetters = word.match(/[\p{Script=Cyrillic}\p{Script=Greek}]/gu) || [];
    if (otherLetters.some(letter => /[a-z]/.test(toSkeleton(letter)))) return true;
  }
  return false;
}

function isPunycode(domain) {
  return domain.split(".").some(l => l.startsWith("xn--"));
}

function extractSLD(domain) {
  const parts = domain.split(".");
  return parts.length >= 2 ? parts[parts.length - 2] : domain;
}

function checkSimilarity(inputDomain, companyDomain) {
  const reasons = [];
  let score = 0;

  const input = inputDomain.toLowerCase();
  const company = companyDomain.toLowerCase();

  if (input === company) {
    return { risk: "none", score: 0, reasons: [], inputDomain, matchedCompanyDomain: companyDomain };
  }

  // Pure TLD swap: identical name, only the TLD differs (example.pl vs
  // example.com). Treat as a single weak signal, not a lookalike — the
  // edit-distance "noise" from the differing TLD would otherwise inflate it.
  const stripTld = (d) => d.includes(".") ? d.slice(0, d.lastIndexOf(".")) : d;
  if (stripTld(input) === stripTld(company) && input !== company) {
    return {
      inputDomain, matchedCompanyDomain: companyDomain,
      risk: "low", score: 10, reasons: ["tld_swap"],
      explanation: `Domena ${inputDomain} ma inną końcówkę niż ${companyDomain}.`,
    };
  }

  // Company's full domain used as a deceptive prefix/segment of a different
  // registrable domain (adresfirmy.com.attacker.com). Genuine subdomains are
  // already short-circuited as trusted before this function is reached.
  if (input.startsWith(company + ".") || input.includes("." + company + ".")) {
    return {
      inputDomain, matchedCompanyDomain: companyDomain,
      risk: "high", score: 45, reasons: ["brand_substring_abuse"],
      explanation: `Domena ${inputDomain} podszywa się pod ${companyDomain}, ale prowadzi do innej domeny.`,
    };
  }

  const inputSkeleton = toSkeleton(input);
  const companySkeleton = toSkeleton(company);

  if (inputSkeleton === companySkeleton && input !== company) {
    reasons.push("homoglyph_exact_match");
    score += 45;
  }

  const lev = levenshtein(input, company);
  const levSLD = levenshtein(extractSLD(input), extractSLD(company));

  if (lev === 1) { reasons.push("levenshtein_distance_1"); score += 40; }
  else if (lev === 2) { reasons.push("levenshtein_distance_2"); score += 25; }
  else if (lev <= 3 && input.length > 5) { reasons.push("levenshtein_distance_3"); score += 15; }

  if (levSLD === 1 && !reasons.includes("levenshtein_distance_1")) {
    reasons.push("levenshtein_sld_distance_1"); score += 35;
  }

  const dlev = damerauLevenshtein(input, company);
  if (dlev === 1 && !reasons.some(r => r.includes("levenshtein"))) {
    reasons.push("transposition_detected"); score += 35;
  }

  const inputSkeletonSLD = toSkeleton(extractSLD(input));
  const companySkeletonSLD = toSkeleton(extractSLD(company));
  if (inputSkeletonSLD === companySkeletonSLD && extractSLD(input) !== extractSLD(company)) {
    if (!reasons.includes("homoglyph_exact_match")) {
      reasons.push("homoglyph_sld_match"); score += 40;
    }
  }

  if (isPunycode(input)) {
    reasons.push("punycode_domain"); score += 30;
  }

  const inputSLD = extractSLD(input);
  const companySLD = extractSLD(company);
  const companyParts = company.split(".");
  const inputSLDLower = inputSLD.toLowerCase();
  const companySLDLower = companySLD.toLowerCase();

  if (
    input !== company &&
    inputSLDLower !== companySLDLower &&
    (inputSLDLower.includes(companySLDLower) || input.includes(companySLD + "-") || input.includes("-" + companySLD))
  ) {
    reasons.push("brand_substring_abuse"); score += 35;
  }

  if (inputSLD === companySLD && input !== company) {
    reasons.push("tld_swap"); score += 10;
  }

  const risk = score >= 60 ? "high" : score >= 30 ? "medium" : score > 0 ? "low" : "none";
  const explanation = buildExplanation(reasons, inputDomain, companyDomain);

  return { inputDomain, matchedCompanyDomain: companyDomain, risk, score, reasons, explanation };
}

function buildExplanation(reasons, input, company) {
  if (reasons.length === 0) return "";
  const parts = [];
  if (reasons.some(r => r.includes("homoglyph"))) parts.push(`Domena ${input} zawiera znaki łudząco podobne do ${company}.`);
  if (reasons.some(r => r.includes("levenshtein"))) parts.push(`Domena ${input} jest bardzo podobna literowo do ${company}.`);
  if (reasons.includes("punycode_domain")) parts.push(`Domena ${input} używa kodowania punycode.`);
  if (reasons.includes("brand_substring_abuse")) parts.push(`Domena ${input} zawiera nazwę firmy jako fragment.`);
  if (reasons.includes("tld_swap")) parts.push(`Domena ${input} ma inną końcówkę niż ${company}.`);
  return parts.join(" ") || `Domena ${input} jest bardzo podobna do firmowej domeny ${company}.`;
}

function isCompanyDomainOrSubdomain(input, companyDomain) {
  const i = (input || "").toLowerCase();
  const c = (companyDomain || "").toLowerCase();
  // Exact match, or a genuine subdomain (e.g. usluga.adresfirmy.com under
  // adresfirmy.com). endsWith on ".company" prevents matching lookalikes like
  // adresfirmy.com.attacker.com, which ends in ".attacker.com".
  return i === c || i.endsWith("." + c);
}

function checkAgainstAllCompanyDomains(inputDomain, companyDomains) {
  const input = (inputDomain || "").toLowerCase();
  // Exact match or legitimate subdomain of a company domain → trusted. It must
  // not be flagged as a lookalike of a sibling company domain or its own base.
  const matched = companyDomains.find(cd => isCompanyDomainOrSubdomain(input, cd));
  if (matched) {
    return { risk: "none", score: 0, reasons: [], inputDomain, matchedCompanyDomain: matched.toLowerCase() };
  }
  let best = null;
  for (const cd of companyDomains) {
    const result = checkSimilarity(inputDomain, cd);
    if (!best || result.score > best.score) best = result;
  }
  return best || { risk: "none", score: 0, reasons: [], inputDomain };
}

globalThis.PGDomainSimilarity = { checkSimilarity, checkAgainstAllCompanyDomains, levenshtein, toSkeleton, isCompanyDomainOrSubdomain, hasMixedScriptHomoglyphs };

if (typeof module !== "undefined") {
  module.exports = { checkSimilarity, checkAgainstAllCompanyDomains, levenshtein, toSkeleton, isCompanyDomainOrSubdomain };
}
