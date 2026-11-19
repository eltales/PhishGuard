"use strict";

function linkHost(href) { try { return new URL(href).hostname.replace(/^www\./, ""); } catch { return ""; } }

function createDomainHint(text) {
  const hint = document.createElement("span");
  hint.textContent = text;
  hint.style.color = "#2563eb";
  hint.style.fontWeight = "600";
  return hint;
}

async function getCurrentMessageId() {
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tabs.length) return null;
    const { id, messages } = await browser.messageDisplay.getDisplayedMessages(tabs[0].id);
    return !id && messages.length === 1 ? messages[0].id : null;
  } catch { return null; }
}

async function init() {
  // Check URL params for error passed from background
  const params = new URLSearchParams(window.location.search);
  const urlMessageId = params.get("messageId");
  const urlError = params.get("error");

  const settings = await browser.runtime.sendMessage({ type: "pg_get_settings" });
  const t = PGI18n.forLanguage(settings?.language);
  PGI18n.localizeDocument(document, settings?.language);
  if (!settings || !settings.companyDomains || settings.companyDomains.length === 0) {
    document.getElementById("pg-not-configured").style.display = "block";
    document.getElementById("pg-open-options").addEventListener("click", (e) => {
      e.preventDefault();
      browser.runtime.openOptionsPage();
    });
    return;
  }

  const messageId = urlMessageId
    ? parseInt(urlMessageId, 10)
    : await getCurrentMessageId();

  if (!messageId) {
    document.getElementById("pg-no-analysis").style.display = "block";
    return;
  }

  const resp = await browser.runtime.sendMessage({ type: "pg_get_analysis", messageId });
  const result = resp && resp.result;

  if (!result) {
    document.getElementById("pg-no-analysis").style.display = "block";
    return;
  }
  if (result.risk === "low") {
    document.getElementById("pg-no-analysis").style.display = "block";
    document.getElementById("pg-no-analysis").querySelector("p").textContent =
      t("noSignals");
  }

  const { risk, score, reasons, details } = result;
  document.getElementById("pg-analysis-result").style.display = "block";

  const badge = document.getElementById("pg-risk-badge");
  const riskLabel = t(risk);
  badge.textContent = riskLabel;
  badge.className = `pg-badge pg-badge-${risk}`;
  document.getElementById("pg-score").textContent = score;

  const reasonsList = document.getElementById("pg-reasons-list");
  const senderSim = details?.senderSimilarity;
  const visibleReasons = reasons.filter(r => r !== "trusted_domain" && r !== "known_sender");
  if (!visibleReasons.length) document.getElementById("pg-reasons-block").style.display = "none";
  visibleReasons.forEach(r => {
    const li = document.createElement("li");
    li.textContent = "✓ " + t(r);
    if ((r === "sender_lookalike_domain" || r === "tld_swap") && senderSim?.inputDomain) {
      li.append(" ", createDomainHint(t("senderDomainHint", senderSim.inputDomain)));
    }
    reasonsList.appendChild(li);
  });

  if (details?.links?.length > 0) {
    const suspicious = details.links.filter(l => (l.analysis && l.analysis.score > 0) || l.similarity);
    if (suspicious.length > 0) {
      document.getElementById("pg-links-block").style.display = "block";
      const list = document.getElementById("pg-links-list");
      suspicious.forEach((l, i) => {
        const li = document.createElement("li");
        const host = (l.similarity && l.similarity.inputDomain) || linkHost(l.href);
        const linkReasons = (l.analysis?.reasons || []).map(reason => t(reason));
        if (l.similarity) {
          const onlyTldSwap = l.similarity.reasons.length === 1 && l.similarity.reasons[0] === "tld_swap";
          linkReasons.push(t(onlyTldSwap ? "tld_swap" : "link_domain_lookalike"));
        }
        const linkText = document.createElement("strong");
        linkText.textContent = l.text || t("none");
        const url = document.createElement("code");
        url.textContent = l.href;
        url.style.fontSize = "11px";
        url.style.wordBreak = "break-all";
        li.append(`${i + 1}. `, linkText, document.createElement("br"), url);
        if (host) {
          const hint = createDomainHint(t("linkDomainHint", host));
          hint.style.fontSize = "11px";
          li.append(document.createElement("br"), hint);
        }
        const explanation = document.createElement("em");
        explanation.textContent = linkReasons.join(", ");
        explanation.style.fontSize = "11px";
        li.append(document.createElement("br"), explanation);
        list.appendChild(li);
      });
    }
  }

  if (details?.attachments?.length > 0) {
    const suspicious = details.attachments.filter(a => a.risk !== "low");
    if (suspicious.length > 0) {
      document.getElementById("pg-attachments-block").style.display = "block";
      const list = document.getElementById("pg-attachments-list");
      suspicious.forEach(a => {
        const li = document.createElement("li");
        li.textContent = `${a.filename} — ${a.code ? t(a.code) : ""}`;
        list.appendChild(li);
      });
    }
  }

  if (urlError) {
    const errEl = document.getElementById("pg-error-msg");
    errEl.textContent = decodeURIComponent(urlError);
    errEl.style.display = "block";
  }

  const reportBtn = document.getElementById("pg-btn-report");
  if (settings.reportButtonEnabled === false) {
    reportBtn.style.display = "none";
    return;
  }
  reportBtn.addEventListener("click", async () => {
    reportBtn.disabled = true;
    reportBtn.textContent = t("preparing");
    try {
      const resp = await browser.runtime.sendMessage({ type: "pg_report_to_admin", messageId });
      if (!resp?.ok) throw new Error(resp?.error || t("reportFailed"));
      document.getElementById("pg-error-msg").style.display = "none";
      reportBtn.textContent = t("prepared");
    } catch (error) {
      const errEl = document.getElementById("pg-error-msg");
      errEl.textContent = error.message;
      errEl.style.display = "block";
      reportBtn.textContent = t("report");
    } finally {
      reportBtn.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", init);
