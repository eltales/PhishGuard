"use strict";

async function reportToAdmin(messageId, analysisResult, settings) {
  const t = PGI18n.forLanguage(settings.language);
  const adminEmail = settings.adminReportEmail;
  if (!adminEmail) {
    throw new Error(t("missingAdmin"));
  }

  let msgHeader;
  try {
    msgHeader = await browser.messages.get(messageId);
  } catch (e) {
    throw new Error(t("readHeadersFailed"));
  }

  const from = msgHeader.author || t("unknown");
  const subject = msgHeader.subject || t("noSubject");
  const date = msgHeader.date ? new Date(msgHeader.date).toISOString() : new Date().toISOString();
  const { score, risk, reasons, details } = analysisResult;

  const riskLabel = t(risk);
  const replyTo = details?.headers?.replyTo || "";

  let reasonsText = reasons.map(r => `- ${t(r)}`).join("\n");

  let linksText = "";
  if (details?.links?.length > 0) {
    const suspicious = details.links.filter(l => l.analysis && l.analysis.score > 0);
    if (suspicious.length > 0) {
      linksText = `\n${t("links")}:\n` + suspicious.map(l =>
        `- ${t("linkText")}: ${l.text || t("none")}\n  ${t("destination")}: ${l.href}\n  ${t("reason")}: ${l.analysis.reasons.map(reason => t(reason)).join(", ")}`
      ).join("\n");
    }
  }

  let attachText = "";
  if (details?.attachments?.length > 0) {
    const suspicious = details.attachments.filter(a => a.risk !== "low");
    if (suspicious.length > 0) {
      attachText = `\n${t("attachments")}:\n` + suspicious.map(a =>
        `- ${a.filename} — ${a.code ? t(a.code) : ""}`
      ).join("\n");
    }
  }

  const body = `${t("reportTitle")}

${t("reportDate")}: ${new Date().toISOString()}
${t("originalSender")}: ${from}
Reply-To: ${replyTo || t("none")}
${t("subject")}: ${subject}
${t("messageDate")}: ${date}
${t("risk")}: ${riskLabel}
${t("score")}: ${score}

${t("reasons")}:
${reasonsText}
${linksText}
${attachText}

---
${t("reportFooter")}`;

  let original;
  try {
    original = await browser.messages.getRaw(messageId, { data_format: "File", decrypt: false });
  } catch {
    throw new Error(t("attachFailed"));
  }

  await browser.compose.beginNew({
    to: [adminEmail],
    subject: `PhishGuard: ${msgHeader.subject || ""}`,
    plainTextBody: body,
    attachments: [{ file: original, name: t("originalFilename") }],
  });
}
