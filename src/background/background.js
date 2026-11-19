"use strict";

const PG_LOG = "[PhishGuard]";

// messageId -> analysis result
const analysisCache = new Map();

const PG_SCRIPT_ID = "pg-display-script";

// Register a persistent message-display content script + CSS via the MV3
// scripting.messageDisplay API. Report whether per-message injection is needed.
async function registerDisplayScript() {
  try {
    const sd = browser.scripting && browser.scripting.messageDisplay;
    if (!sd || !sd.registerScripts) {
      console.warn(PG_LOG, "scripting.messageDisplay niedostępne — używam fallbacku executeScript");
      return false;
    }
    // The background is a non-persistent event page; on wake it may already be
    // registered. Avoid the "id already exists" error.
    const existing = await sd.getRegisteredScripts().catch(() => []);
    const registered = existing.find(s => s.id === PG_SCRIPT_ID);
    if (registered?.js?.includes("src/i18n.js")) return true;
    if (registered) await sd.unregisterScripts({ ids: [PG_SCRIPT_ID] });
    await sd.registerScripts([{
      id: PG_SCRIPT_ID,
      js: ["src/i18n.js", "src/content/messageDisplayScript.js"],
      css: ["src/content/riskStyles.css"],
    }]);
    console.log(PG_LOG, "messageDisplayScript zarejestrowany");
    return true;
  } catch (e) {
    console.warn(PG_LOG, "Rejestracja display script nieudana, fallback executeScript:", e);
    return false;
  }
}
const displayScriptRegistration = registerDisplayScript();

// Fallback when automatic injection is unavailable.
async function injectDisplayScript(tabId) {
  if (!browser.scripting) return;
  try {
    await browser.scripting.insertCSS({ target: { tabId }, files: ["src/content/riskStyles.css"] });
  } catch (e) { /* This tab may not support injection. */ }
  try {
    await browser.scripting.executeScript({ target: { tabId }, files: ["src/i18n.js", "src/content/messageDisplayScript.js"] });
  } catch (e) { /* This tab may not support injection. */ }
}

function contentSettings(settings) {
  return {
    language: PGI18n.normalize(settings.language),
    warnOnTaggedEmail: settings.warnOnTaggedEmail !== false,
    warnOnSuspiciousLink: settings.warnOnSuspiciousLink !== false,
    reportButtonEnabled: settings.reportButtonEnabled !== false,
  };
}

// Show or grey out the "Zgłoś phishing" toolbar button per the user's setting.
async function applyReportButtonState() {
  try {
    const s = await getSettings();
    const action = browser.action;
    if (!action) return;
    await action.setTitle({ title: PGI18n.forLanguage(s.language)("toolbar") });
    if (s.reportButtonEnabled === false) await action.disable();
    else await action.enable();
  } catch (e) {
    console.warn(PG_LOG, "Nie udało się ustawić przycisku zgłaszania:", e);
  }
}
applyReportButtonState();

// Share analyses already in progress, including requests from the toolbar.
const analysisInFlight = new Map();
let settingsRevision = 0;
let senderTrustUpdate = Promise.resolve();

async function getOrComputeAnalysis(messageId, settings) {
  const cached = analysisCache.get(messageId);
  if (cached) return cached;
  const pending = analysisInFlight.get(messageId);
  if (pending) return pending;
  const revision = settingsRevision;
  const run = (async () => {
    settings = settings || await getSettings();
    if (!settings.companyDomains || settings.companyDomains.length === 0) return null;
    const result = await analyzeMessage(messageId, settings);
    if (result && revision === settingsRevision) analysisCache.set(messageId, result);
    console.log(PG_LOG, "Analiza wiadomości", messageId, "->", result ? `${result.risk} (${result.score})` : "brak");
    return result;
  })();
  analysisInFlight.set(messageId, run);
  try {
    return await run;
  } finally {
    if (analysisInFlight.get(messageId) === run) analysisInFlight.delete(messageId);
  }
}

async function getDisplayedSingleMessage(tabId) {
  const { id, messages } = await browser.messageDisplay.getDisplayedMessages(tabId);
  return !id && messages.length === 1 ? messages[0] : null;
}

async function buildMessageAnalysis(message) {
  const messageId = message.id;
  const settings = await getSettings();

  if (!settings.companyDomains || settings.companyDomains.length === 0) {
    console.warn(PG_LOG, "Brak skonfigurowanych domen firmowych — analiza pominięta. Uzupełnij opcje dodatku.");
    return { messageId, result: null, settings: contentSettings(settings), notConfigured: true };
  }

  const result = await getOrComputeAnalysis(messageId, settings);

  return { messageId, result, settings: contentSettings(settings) };
}

browser.messageDisplay.onMessagesDisplayed.addListener(async (tab, { id, messages }) => {
  if (id || messages.length !== 1 || await displayScriptRegistration) return;
  try {
    const current = await getDisplayedSingleMessage(tab.id);
    if (current?.id === messages[0].id) await injectDisplayScript(tab.id);
  } catch (e) {
    // The selected message or tab may have already been closed.
  }
});

async function handleContentReady(tabId, requestId) {
  const displayed = await getDisplayedSingleMessage(tabId).catch(() => null);
  if (!displayed) return;
  const data = await buildMessageAnalysis(displayed);
  const current = await getDisplayedSingleMessage(tabId).catch(() => null);
  if (current?.id === displayed.id) {
    await browser.tabs.sendMessage(tabId, { type: "pg_render", requestId, data }).catch(() => {});
  }
}

browser.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || typeof msg.type !== "string" || !msg.type.startsWith("pg_")) return undefined;
  if (msg.type === "pg_content_ready") {
    // An async reply can outlive the message document during fast navigation.
    // Send the result separately and let the requesting document match it.
    const tabId = sender.tab?.id;
    if (tabId != null) {
      handleContentReady(tabId, msg.requestId)
        .catch(e => console.error(PG_LOG, "pg_content_ready błąd:", e));
    }
    return undefined;
  }
  return handleRuntimeMessage(msg).catch(e => {
    console.error(PG_LOG, `Błąd obsługi ${msg.type}:`, e);
    return { error: e?.message || String(e) };
  });
});

async function handleRuntimeMessage(msg) {
  if (msg.type === "pg_get_analysis") {
    return { result: await getOrComputeAnalysis(msg.messageId) };
  }

  if (msg.type === "pg_report_to_admin") {
    try {
      const settings = await getSettings();
      const result = await getOrComputeAnalysis(msg.messageId, settings);
      if (!result) return { error: PGI18n.forLanguage(settings.language)("noAnalysis") };
      await reportToAdmin(msg.messageId, result, settings);
      return { ok: true };
    } catch (e) {
      return { error: e.message };
    }
  }

  if (msg.type === "pg_get_settings") {
    return getSettings();
  }

  if (msg.type === "pg_mark_safe") {
    const update = senderTrustUpdate.then(async () => {
      const settings = await getSettings();
      const result = await analyzeMessage(msg.messageId, settings);
      const sender = PGHeaderAnalyzer.parseAddress(result?.details.headers.from).email?.toLowerCase();
      if (!sender || result.details.trustRestricted || result.risk === "critical" ||
          result.reasons.some(reason => /^auth_.*_fail$/.test(reason))) {
        return { error: PGI18n.forLanguage(settings.language)("trustRestricted") };
      }
      const knownSenders = [...new Set([...(settings.knownSenders || []), sender])];
      await saveSettings({ ...settings, knownSenders });
      analysisCache.delete(msg.messageId);
      return { ok: true };
    });
    senderTrustUpdate = update.catch(() => {});
    return update;
  }

  if (msg.type === "pg_open_link") {
    try {
      await browser.windows.openDefaultBrowser(msg.url);
      return { ok: true };
    } catch (e) {
      return { error: e.message };
    }
  }

  if (msg.type === "pg_log_event") {
    // Local event log only — no telemetry (see security requirements).
    const stored = await browser.storage.local.get("pgEventLog");
    const log = stored.pgEventLog || [];
    log.push({ event: msg.event, url: msg.url, at: new Date().toISOString() });
    if (log.length > 200) log.splice(0, log.length - 200);
    await browser.storage.local.set({ pgEventLog: log });
    return { ok: true };
  }

  return undefined;
}

// When settings change (Options page or "add to trusted"), drop the cached
// analyses and re-render every open message so warnings update live without a
// manual reload.
browser.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local" || !changes.phishguardSettings) return;
  settingsRevision++;
  analysisCache.clear();
  analysisInFlight.clear();
  await applyReportButtonState();
  try {
    const tabs = await browser.tabs.query({});
    for (const t of tabs) {
      await browser.tabs.sendMessage(t.id, { type: "pg_refresh_analysis" }).catch(() => {});
    }
  } catch (e) {
    console.error(PG_LOG, "Re-render po zmianie ustawień nieudany:", e);
  }
});
