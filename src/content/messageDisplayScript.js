"use strict";

(function () {
  if (window.__pgLoaded) return;
  let language = "en";
  let t = PGI18n.forLanguage(language);

  // CSS is injected by the background script (scripting.messageDisplay /
  // scripting.insertCSS).

  function removeBanner() {
    const old = document.getElementById("pg-banner");
    if (old) old.remove();
  }

  function removeLinkInterceptors() {
    document.querySelectorAll("a[data-pg-intercepted]").forEach(a => {
      const original = a.getAttribute("data-pg-original-href");
      if (original) a.href = original;
      a.removeAttribute("data-pg-intercepted");
      a.removeEventListener("click", a.__pgClickHandler);
    });
  }

  function showBanner(result, messageId, settings) {
    removeBanner();
    const { risk, score, reasons } = result;

    const banner = document.createElement("div");
    banner.id = "pg-banner";
    banner.className = `pg-banner-${risk}`;

    const icons = { medium: "⚠️", high: "🚨", critical: "🚨" };
    const reportBtnHtml = settings && settings.reportButtonEnabled === false
      ? ""
      : `<button class="pg-btn pg-btn-danger" id="pg-btn-report">${t("report")}</button>`;

    banner.innerHTML = `
      <div class="pg-banner-title">${icons[risk] || "⚠️"} ${t(`warning_${risk}`)}</div>
      <div class="pg-banner-msg">${t(`advice_${risk}`)}</div>
      <div class="pg-banner-actions">
        ${reportBtnHtml}
        <button class="pg-btn pg-btn-neutral" id="pg-btn-details">${t("details")}</button>
        ${risk !== "critical" && !result.details?.trustRestricted ? `<button class="pg-btn pg-btn-safe" id="pg-btn-safe">${t("markSafe")}</button>` : ""}
      </div>
    `;

    // Insert as first child of body (before message content)
    const target = document.body || document.documentElement;
    target.insertBefore(banner, target.firstChild);

    document.getElementById("pg-btn-report")?.addEventListener("click", (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      btn.textContent = t("preparing");
      browser.runtime.sendMessage({ type: "pg_report_to_admin", messageId })
        .then(resp => {
          // alert()/confirm() are unreliable in the message display context, so
          // we reflect the result inline on the button instead.
          if (resp?.ok) {
            btn.textContent = t("prepared");
          } else {
            btn.textContent = `${t("error")}: ${resp?.error || t("reportFailed")}`;
          }
        })
        .catch(() => { btn.textContent = t("report"); })
        .finally(() => { btn.disabled = false; });
    });

    document.getElementById("pg-btn-details")?.addEventListener("click", () => {
      showDetailsModal(result, messageId);
    });

    document.getElementById("pg-btn-safe")?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const response = await browser.runtime.sendMessage({ type: "pg_mark_safe", messageId });
        if (!response?.ok) throw new Error(response?.error || t("markSafeFailed"));
        removeBanner();
        applyBodyRisk("low");
      } catch (error) {
        button.textContent = error.message;
        button.disabled = false;
      }
    });
  }

  function applyBodyRisk(risk) {
    document.body.classList.remove("pg-risk-low", "pg-risk-medium", "pg-risk-high", "pg-risk-critical");
    if (risk && risk !== "low") {
      document.body.classList.add(`pg-risk-${risk}`);
    }
  }

  function showDetailsModal(result, messageId) {
    const existing = document.getElementById("pg-details-modal-overlay");
    if (existing) existing.remove();

    const { risk, score, reasons, details } = result;
    const riskLabel = t(risk);

    const senderSim = details?.senderSimilarity;
    let reasonsHtml = "<ul>" + reasons.map(r => {
      let extra = "";
      if ((r === "sender_lookalike_domain" || r === "tld_swap") && senderSim?.inputDomain) {
        extra = ` <span class="pg-domain-hint">${escHtml(t("senderDomainHint", senderSim.inputDomain))}</span>`;
      }
      return `<li>✓ ${escHtml(t(r))}${extra}</li>`;
    }).join("") + "</ul>";

    let linksHtml = "";
    if (details?.links?.length > 0) {
      const suspicious = details.links.filter(l => (l.analysis && l.analysis.score > 0) || l.similarity);
      if (suspicious.length > 0) {
        linksHtml = `<div><strong>${t("links")}:</strong><ul>` +
          suspicious.map((l, i) => {
            const host = l.similarity?.inputDomain || linkHost(l.href);
            const ocena = (l.analysis?.reasons || []).map(reason => t(reason));
            if (l.similarity) ocena.push(t("link_domain_lookalike"));
            const domainHint = host ? `<br><span class="pg-domain-hint">${escHtml(t("linkDomainHint", host))}</span>` : "";
            return `<li>${i + 1}. ${t("linkText")}: ${escHtml(l.text || t("none"))}<br>URL: <code>${escHtml(l.href)}</code>${domainHint}<br>${t("reason")}: ${escHtml(ocena.join(", "))}</li>`;
          }).join("") +
          `</ul></div>`;
      }
    }

    let attachHtml = "";
    if (details?.attachments?.length > 0) {
      const suspicious = details.attachments.filter(a => a.risk !== "low");
      if (suspicious.length > 0) {
        attachHtml = `<div><strong>${t("attachments")}:</strong><ul>` +
          suspicious.map(a => `<li>${escHtml(a.filename)} — ${escHtml(a.code ? t(a.code) : "")}</li>`).join("") +
          `</ul></div>`;
      }
    }

    const overlay = document.createElement("div");
    overlay.id = "pg-details-modal-overlay";
    overlay.innerHTML = `
      <div id="pg-details-modal">
        <h2>${t("detailsTitle")}</h2>
        <div class="pg-detail-row"><span class="pg-detail-label">${t("risk")}:</span><span>${riskLabel}</span></div>
        <div class="pg-detail-row"><span class="pg-detail-label">${t("score")}:</span><span>${score}</span></div>
        <div><strong>${t("reasons")}:</strong>${reasonsHtml}</div>
        ${linksHtml}
        ${attachHtml}
        <button class="pg-close-btn" id="pg-details-close">${t("close")}</button>
      </div>
    `;
    document.body.appendChild(overlay);
    overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
    document.getElementById("pg-details-close")?.addEventListener("click", () => overlay.remove());
  }

  // Fire-and-forget message; the pane may already be gone.
  function sendQuiet(message) {
    try {
      browser.runtime.sendMessage(message).catch(() => {});
    } catch (e) { /* context unloaded */ }
  }

  function escHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function linkHost(href) {
    try { return new URL(href).hostname.replace(/^www\./, ""); } catch { return ""; }
  }

  function isSuspiciousLink(link, result) {
    if (link.analysis && link.analysis.score > 0) return { suspicious: true, reasons: link.analysis.reasons };
    return { suspicious: false, reasons: [] };
  }

  function showLinkModal(url, reasons, onConfirm, onCancel) {
    const existing = document.getElementById("pg-link-modal-overlay");
    if (existing) existing.remove();

    const reasonText = reasons.map(reason => t(reason)).join(", ") || t("tagged_email");

    const overlay = document.createElement("div");
    overlay.id = "pg-link-modal-overlay";
    overlay.innerHTML = `
      <div id="pg-link-modal">
        <h2>${t("linkWarning")}</h2>
        <p>${t("linkWarningBody")}</p>
        <p><strong>${t("destination")}:</strong></p>
        <div class="pg-modal-url">${escHtml(url)}</div>
        <p class="pg-modal-reason"><strong>${t("reason")}:</strong> ${escHtml(reasonText)}</p>
        <p>${t("openLinkQuestion")}</p>
        <div class="pg-modal-actions">
          <button class="pg-btn-modal-no" id="pg-modal-no">${t("cancel")}</button>
          <button class="pg-btn-modal-yes" id="pg-modal-yes">${t("openLink")}</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    document.getElementById("pg-modal-no").addEventListener("click", () => {
      overlay.remove();
      onCancel && onCancel();
    });
    document.getElementById("pg-modal-yes").addEventListener("click", () => {
      overlay.remove();
      onConfirm && onConfirm();
    });
  }

  function interceptLinks(result, settings) {
    const { risk, details } = result;
    const isTaggedEmail = risk === "medium" || risk === "high" || risk === "critical";
    const warnOnTagged = settings && settings.warnOnTaggedEmail !== false;
    const warnOnSuspicious = settings && settings.warnOnSuspiciousLink !== false;

    document.querySelectorAll("a[href]").forEach(a => {
      const href = a.href;
      if (!href || (!href.startsWith("http://") && !href.startsWith("https://"))) return;
      if (a.getAttribute("data-pg-intercepted")) return;

      a.setAttribute("data-pg-intercepted", "1");
      a.setAttribute("data-pg-original-href", href);

      // a.href is URL-normalized by the DOM, the analyzer stored the raw
      // attribute value — compare both forms.
      const rawHref = a.getAttribute("href");
      const linkData = details?.links?.find(l => l.href === href || l.href === rawHref) || null;
      const isLinkSuspicious = linkData && linkData.analysis && linkData.analysis.score > 0;
      const linkReasons = linkData?.analysis?.reasons || [];

      if ((isTaggedEmail && warnOnTagged) || (isLinkSuspicious && warnOnSuspicious)) {
        const handler = (e) => {
          e.preventDefault();
          e.stopPropagation();
          const reasons = linkReasons.length > 0 ? linkReasons : ["tagged_email"];
          showLinkModal(href, reasons, () => {
            sendQuiet({ type: "pg_open_link", url: href });
            sendQuiet({ type: "pg_log_event", event: "user_confirmed_suspicious_link", url: href });
          }, () => {
            sendQuiet({ type: "pg_log_event", event: "user_cancelled_link", url: href });
          });
        };
        a.__pgClickHandler = handler;
        a.addEventListener("click", handler, true);
      }
    });
  }

  function render(data) {
    if (!data) return;
    const { messageId, result, settings } = data;
    const nextLanguage = PGI18n.normalize(settings?.language);
    if (nextLanguage !== language) {
      language = nextLanguage;
      t = PGI18n.forLanguage(language);
      document.getElementById("pg-details-modal-overlay")?.remove();
      document.getElementById("pg-link-modal-overlay")?.remove();
    }
    removeBanner();
    removeLinkInterceptors();
    applyBodyRisk("low");

    if (!result) {
      // Not configured or low risk — nothing visible.
      return;
    }

    const { risk } = result;
    if (risk === "low") return;

    applyBodyRisk(risk);
    showBanner(result, messageId, settings);
    interceptLinks(result, settings);
  }

  // Guard against double-injection into the same document.
  window.__pgLoaded = true;

  let unloaded = false;
  let analysisRequestId;
  window.addEventListener("pagehide", () => { unloaded = true; }, { once: true });

  browser.runtime.onMessage.addListener((msg) => {
    if (unloaded || !msg) return;
    if (msg.type === "pg_refresh_analysis") requestAnalysis();
    if (msg.type === "pg_render" && msg.requestId === analysisRequestId) render(msg.data);
  });

  function requestAnalysis() {
    if (unloaded) return;
    analysisRequestId = crypto.getRandomValues(new Uint32Array(4)).join("-");
    sendQuiet({ type: "pg_content_ready", requestId: analysisRequestId });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", requestAnalysis);
  } else {
    requestAnalysis();
  }
})();
