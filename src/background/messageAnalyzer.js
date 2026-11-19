"use strict";

// Inline dependencies (loaded via background scripts in order)
// Assumes: domainSimilarity.js, urlAnalyzer.js, headerAnalyzer.js, attachmentAnalyzer.js, riskScoring.js loaded first

async function analyzeMessage(messageId, settings) {
  const companyDomains = settings.companyDomains || [];
  const trustedDomains = settings.trustedDomains || [];
  const knownSenders = settings.knownSenders || [];

  let score = 0;
  let contentScore = 0;
  const reasons = [];
  const details = { links: [], attachments: [], headers: {} };

  let full;
  try {
    full = await browser.messages.getFull(messageId);
  } catch (e) {
    return null;
  }

  const headers = full.headers || {};
  const fromRaw = (headers.from || [""])[0];
  const replyToRaw = (headers["reply-to"] || [""])[0];
  const subject = (headers.subject || [""])[0];

  details.headers = { from: fromRaw, replyTo: replyToRaw, subject };

  const fromParsed = PGHeaderAnalyzer.parseAddress(fromRaw);
  const senderDomain = fromParsed.domain;
  const replyToDomain = replyToRaw ? PGHeaderAnalyzer.extractHeaderDomain(replyToRaw) : null;

  // (1) SPF / DKIM / DMARC verdicts from Authentication-Results.
  const auth = PGHeaderAnalyzer.parseAuthResults(headers);
  if (auth.dmarc === "fail") { score += 35; reasons.push("auth_dmarc_fail"); }
  if (auth.spf === "fail") { score += 20; reasons.push("auth_spf_fail"); }
  if (auth.dkim === "fail") { score += 15; reasons.push("auth_dkim_fail"); }

  // (2,3) Display-name spoofing.
  const dnReasons = PGHeaderAnalyzer.analyzeDisplayName(fromParsed.name, senderDomain, companyDomains);
  for (const r of dnReasons) {
    if (reasons.includes(r)) continue;
    if (r === "display_name_spoofs_company") score += 45;
    else if (r === "display_name_domain_mismatch") score += 30;
    else if (r === "display_name_is_email") score += 25;
    reasons.push(r);
  }

  if (senderDomain) {
    if (companyDomains.length > 0) {
      const sim = PGDomainSimilarity.checkAgainstAllCompanyDomains(senderDomain, companyDomains);
      if (sim && sim.score > 0) {
        details.senderSimilarity = sim;
        if (isOnlyTldSwap(sim)) {
          score += 10;
          if (!reasons.includes("tld_swap")) reasons.push("tld_swap");
        } else {
          score += 45;
          reasons.push("sender_lookalike_domain");
        }
      }
    }
  }

  // Reply-To mismatch
  if (replyToDomain && senderDomain && replyToDomain !== senderDomain) {
    score += 25;
    reasons.push("reply_to_mismatch");
    if (PGHeaderAnalyzer.isPublicDomain(replyToDomain)) {
      score += 5;
      reasons.push("reply_to_public_domain");
    }
  }

  // Urgency in subject
  if (PGHeaderAnalyzer.detectUrgencyInText(subject)) {
    score += 10;
    contentScore += 10;
    reasons.push("urgency_subject");
  }

  // Collect all readable text once (plain + HTML) for the content heuristics.
  const allText = getAllText(full);
  const hasHomoglyphs = PGDomainSimilarity.hasMixedScriptHomoglyphs(
    [fromParsed.name, fromParsed.email, subject, allText].join(" ")
  );
  if (hasHomoglyphs) reasons.push("mixed_script_homoglyphs");

  // Urgency in body.
  if (allText && PGHeaderAnalyzer.detectUrgencyInText(allText)) {
    if (!reasons.includes("urgency_subject")) {
      score += 10;
      contentScore += 10;
      reasons.push("urgency_body");
    }
  }

  // (15) Requests for credentials / sensitive data.
  if (PGHeaderAnalyzer.detectCredentialRequest(subject + " " + allText)) {
    score += 20;
    contentScore += 20;
    reasons.push("credential_request");
  }

  // (17) Script/language mismatch (e.g. Cyrillic body from a .pl/.com sender).
  const senderTld = senderDomain ? senderDomain.split(".").pop() : "";
  if (PGHeaderAnalyzer.hasCyrillicMismatch(allText, senderTld)) {
    score += 15;
    reasons.push("language_mismatch");
  }

  // (16) Body is essentially one image with almost no text.
  const htmlStruct = analyzeHtmlStructure(full);
  if (htmlStruct.hasHtml && htmlStruct.imgCount >= 1 && htmlStruct.textLen < 25) {
    score += 15;
    reasons.push("image_only_body");
  }

  const links = extractLinksFromParts(full);
  details.links = links;

  // Use the highest URL score per host, even when a signature or newsletter
  // repeats the same destination across many tracking URLs.
  const scoredLinks = new Map();
  const scoredSimilarDomains = new Set();
  for (const link of links) {
    const urlResult = PGUrlAnalyzer.analyzeUrl(link.href, link.text);
    link.analysis = urlResult;
    const linkDomain = PGUrlAnalyzer.extractDomainFromUrl(link.href);
    const previousScore = scoredLinks.get(linkDomain) || 0;
    const domainScore = Math.max(previousScore, urlResult.score);
    score += domainScore - previousScore;
    scoredLinks.set(linkDomain, domainScore);
    reasons.push(...urlResult.reasons.filter(r => !reasons.includes(r)));

    if (companyDomains.length > 0) {
      if (linkDomain) {
        const linkSim = PGDomainSimilarity.checkAgainstAllCompanyDomains(linkDomain, companyDomains);
        if (linkSim && linkSim.score > 0) {
          link.similarity = linkSim;
          if (scoredSimilarDomains.has(linkDomain)) continue;
          scoredSimilarDomains.add(linkDomain);
          if (isOnlyTldSwap(linkSim)) {
            score += 10;
            if (!reasons.includes("tld_swap")) reasons.push("tld_swap");
          } else {
            score += 45;
            if (!reasons.includes("link_domain_lookalike")) reasons.push("link_domain_lookalike");
          }
        }
      }
    }
  }

  // Attachments — listAttachments exposes name + contentType (getFull does not
  // provide a flat attachments list).
  let attachments = [];
  try {
    attachments = await browser.messages.listAttachments(messageId);
  } catch (e) {
    attachments = [];
  }
  if (attachments.length > 0) {
    const attResults = PGAttachmentAnalyzer.analyzeAttachments(attachments);
    details.attachments = attResults;

    let attScore = 0;
    const attReasons = new Set();
    for (const a of attResults) {
      if (a.code === "double_extension") { attScore = Math.max(attScore, 35); attReasons.add("double_extension"); }
      else if (a.code === "mime_extension_mismatch") { attScore = Math.max(attScore, 30); attReasons.add("mime_extension_mismatch"); }
      else if (a.risk !== "low") { attScore = Math.max(attScore, 20); attReasons.add("suspicious_attachment"); }
    }
    score += attScore;
    attReasons.forEach(r => { if (!reasons.includes(r)) reasons.push(r); });
  }

  details.trustRestricted = Boolean(
    hasHomoglyphs || details.senderSimilarity || dnReasons.length ||
    details.links.some(link => link.similarity) ||
    reasons.includes("link_text_href_mismatch") ||
    details.attachments.some(attachment => attachment.risk === "high")
  );
  if (details.trustRestricted) {
    score = Math.max(score, 30);
  } else if (senderDomain) {
    const authFailed = auth.dmarc === "fail" || auth.spf === "fail" || auth.dkim === "fail";
    const knownSender = knownSenders.some(sender =>
      sender.toLowerCase() === fromParsed.email?.toLowerCase() ||
      sender.toLowerCase() === senderDomain
    );
    if (!authFailed && isTrusted(senderDomain, [...companyDomains, ...trustedDomains])) {
      reasons.push("trusted_domain");
    }
    if (!authFailed && knownSender) {
      reasons.push("known_sender");
    }
    if (reasons.includes("trusted_domain") || reasons.includes("known_sender")) {
      score -= Math.min(20, contentScore);
    }
  }

  return PGRiskScoring.buildRiskResult(score, reasons, details);
}

// A bare TLD swap (example.pl vs example.com) is a weak signal worth +10, not
// the full +45 lookalike. Anything stronger (homoglyph, edit distance, brand
// abuse, punycode) keeps the full weight.
function isOnlyTldSwap(sim) {
  return sim.reasons.length === 1 && sim.reasons[0] === "tld_swap";
}

// A domain is trusted if it equals, or is a subdomain of, any whitelisted
// domain (so trusting example.pl also trusts mail.example.pl).
function isTrusted(domain, trustedDomains) {
  return (trustedDomains || []).some(t => PGDomainSimilarity.isCompanyDomainOrSubdomain(domain, t));
}

function extractBodyText(full) {
  if (!full.parts) return "";
  for (const part of full.parts) {
    if (part.contentType === "text/plain" && part.body) return part.body;
    if (part.parts) {
      for (const sub of part.parts) {
        if (sub.contentType === "text/plain" && sub.body) return sub.body;
      }
    }
  }
  return "";
}

// All readable text (plain-text parts + visible text of HTML parts).
function getAllText(full) {
  let text = "";
  function walk(parts) {
    for (const p of parts || []) {
      if (p.contentType === "text/plain" && p.body) text += " " + p.body;
      if (p.contentType === "text/html" && p.body) {
        try {
          const doc = new DOMParser().parseFromString(p.body, "text/html");
          text += " " + (doc.body ? doc.body.textContent : "");
        } catch (e) { /* ignore */ }
      }
      if (p.parts) walk(p.parts);
    }
  }
  walk(full.parts);
  return text;
}

// Image vs text balance of the HTML body (for "image-only" detection).
function analyzeHtmlStructure(full) {
  let textLen = 0, imgCount = 0, hasHtml = false;
  function walk(parts) {
    for (const p of parts || []) {
      if (p.contentType === "text/html" && p.body) {
        hasHtml = true;
        try {
          const doc = new DOMParser().parseFromString(p.body, "text/html");
          imgCount += doc.querySelectorAll("img").length;
          const t = doc.body ? doc.body.textContent : "";
          textLen += t.replace(/\s+/g, " ").trim().length;
        } catch (e) { /* ignore */ }
      }
      if (p.parts) walk(p.parts);
    }
  }
  walk(full.parts);
  return { textLen, imgCount, hasHtml };
}

function extractLinksFromParts(full) {
  const links = [];
  if (!full.parts) return links;

  function processHtml(html) {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, "text/html");
      doc.querySelectorAll("a[href]").forEach(a => {
        const href = a.getAttribute("href") || "";
        const text = a.textContent.trim();
        if (href && (href.startsWith("http://") || href.startsWith("https://"))) {
          links.push({ href, text });
        }
      });
    } catch (e) {
      // DOM parsing failed, extract with regex
      const re = /href=["']?(https?:\/\/[^\s"'>]+)["']?/gi;
      let m;
      while ((m = re.exec(html)) !== null) {
        links.push({ href: m[1], text: "" });
      }
    }
  }

  function walkParts(parts) {
    for (const p of parts) {
      if (p.contentType === "text/html" && p.body) processHtml(p.body);
      if (p.parts) walkParts(p.parts);
    }
  }

  walkParts(full.parts);
  return links;
}
