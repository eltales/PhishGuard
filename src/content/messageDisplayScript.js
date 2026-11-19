"use strict";

(function () {
  if (window.__pgLoaded) return;
  let language = "en";
  let t = PGI18n.forLanguage(language);

  // CSS is injected by the background script (scripting.messageDisplay /
  // scripting.insertCSS).

  function element(tag, { id, className } = {}, ...children) {
    const node = document.createElement(tag);
    if (id) node.id = id;
    if (className) node.className = className;
    node.append(...children);
    return node;
  }

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
    const { risk } = result;

    const icons = { medium: "⚠️", high: "🚨", critical: "🚨" };
    const actions = element("div", { className: "pg-banner-actions" });
    const reportButton = settings?.reportButtonEnabled === false ? null
      : element("button", { id: "pg-btn-report", className: "pg-btn pg-btn-danger" }, t("report"));
    if (reportButton) actions.append(reportButton);
    const detailsButton = element("button", { id: "pg-btn-details", className: "pg-btn pg-btn-neutral" }, t("details"));
    actions.append(detailsButton);
    const safeButton = risk !== "critical" && !result.details?.trustRestricted
      ? element("button", { id: "pg-btn-safe", className: "pg-btn pg-btn-safe" }, t("markSafe"))
      : null;
    if (safeButton) actions.append(safeButton);

    const banner = element("div", { id: "pg-banner", className: `pg-banner-${risk}` },
      element("div", { className: "pg-banner-title" }, `${icons[risk] || "⚠️"} ${t(`warning_${risk}`)}`),
      element("div", { className: "pg-banner-msg" }, t(`advice_${risk}`)),
      actions
    );

    // Insert as first child of body (before message content)
    const target = document.body || document.documentElement;
    target.insertBefore(banner, target.firstChild);

    reportButton?.addEventListener("click", (e) => {
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

    detailsButton.addEventListener("click", () => {
      showDetailsModal(result);
    });

    safeButton?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const response = await browser.runtime.sendMessage({ type: "pg_mark_safe", messageId });
        if (!response?.ok) throw new Error(response?.error || t("markSafeFailed"));
        requestAnalysis();
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

  function showDetailsModal(result) {
    document.getElementById("pg-details-modal-overlay")?.remove();
    const { risk, score, reasons, details } = result;
    const modal = element("div", { id: "pg-details-modal" }, element("h2", {}, t("detailsTitle")));
    const overlay = element("div", { id: "pg-details-modal-overlay" }, modal);
    for (const [label, value] of [["risk", t(risk)], ["score", String(score)]]) {
      modal.append(element("div", { className: "pg-detail-row" },
        element("span", { className: "pg-detail-label" }, `${t(label)}:`),
        element("span", {}, value)
      ));
    }

    const senderDomain = details?.senderSimilarity?.inputDomain;
    const reasonItems = reasons.map(reason => {
      const item = element("li", {}, `✓ ${t(reason)}`);
      if ((reason === "sender_lookalike_domain" || reason === "tld_swap") && senderDomain) {
        item.append(" ", element("span", { className: "pg-domain-hint" }, t("senderDomainHint", senderDomain)));
      }
      return item;
    });
    modal.append(element("div", {}, element("strong", {}, `${t("reasons")}:`), element("ul", {}, ...reasonItems)));

    const suspiciousLinks = (details?.links || []).filter(link => link.analysis?.score > 0 || link.similarity);
    if (suspiciousLinks.length) {
      const items = suspiciousLinks.map((link, index) => {
        const host = link.similarity?.inputDomain || linkHost(link.href);
        const linkReasons = (link.analysis?.reasons || []).map(reason => t(reason));
        if (link.similarity) {
          const onlyTldSwap = link.similarity.reasons.length === 1 && link.similarity.reasons[0] === "tld_swap";
          linkReasons.push(t(onlyTldSwap ? "tld_swap" : "link_domain_lookalike"));
        }
        const item = element("li", {}, `${index + 1}. ${t("linkText")}: ${link.text || t("none")}`,
          element("br"), "URL: ", element("code", {}, link.href)
        );
        if (host) item.append(element("br"), element("span", { className: "pg-domain-hint" }, t("linkDomainHint", host)));
        item.append(element("br"), `${t("reason")}: ${linkReasons.join(", ")}`);
        return item;
      });
      modal.append(element("div", {}, element("strong", {}, `${t("links")}:`), element("ul", {}, ...items)));
    }

    const suspiciousAttachments = (details?.attachments || []).filter(attachment => attachment.risk !== "low");
    if (suspiciousAttachments.length) {
      const items = suspiciousAttachments.map(attachment =>
        element("li", {}, `${attachment.filename} — ${attachment.code ? t(attachment.code) : ""}`)
      );
      modal.append(element("div", {}, element("strong", {}, `${t("attachments")}:`), element("ul", {}, ...items)));
    }

    const closeButton = element("button", { id: "pg-details-close", className: "pg-close-btn" }, t("close"));
    modal.append(closeButton);
    document.body.appendChild(overlay);
    overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
    closeButton.addEventListener("click", () => overlay.remove());
  }

  // Fire-and-forget message; the pane may already be gone.
  function sendQuiet(message) {
    try {
      browser.runtime.sendMessage(message).catch(() => {});
    } catch (e) { /* context unloaded */ }
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

    const cancelButton = element("button", { id: "pg-modal-no", className: "pg-btn-modal-no" }, t("cancel"));
    const openButton = element("button", { id: "pg-modal-yes", className: "pg-btn-modal-yes" }, t("openLink"));
    const modal = element("div", { id: "pg-link-modal" },
      element("h2", {}, t("linkWarning")),
      element("p", {}, t("linkWarningBody")),
      element("p", {}, element("strong", {}, `${t("destination")}:`)),
      element("div", { className: "pg-modal-url" }, url),
      element("p", { className: "pg-modal-reason" }, element("strong", {}, `${t("reason")}:`), ` ${reasonText}`),
      element("p", {}, t("openLinkQuestion")),
      element("div", { className: "pg-modal-actions" }, cancelButton, openButton)
    );
    const overlay = element("div", { id: "pg-link-modal-overlay" }, modal);
    document.body.appendChild(overlay);

    cancelButton.addEventListener("click", () => {
      overlay.remove();
      onCancel && onCancel();
    });
    openButton.addEventListener("click", () => {
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
