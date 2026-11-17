"use strict";

const SUSPICIOUS_EXTENSIONS = [
  ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".vbe",
  ".js", ".jse", ".wsf", ".wsh", ".ps1", ".ps2", ".msi", ".hta",
  ".docm", ".xlsm", ".pptm", ".xlam", ".xll", ".dotm",
  ".zip", ".rar", ".7z", ".iso", ".img",
];

const MACRO_EXTENSIONS = [".docm", ".xlsm", ".pptm", ".xlam", ".xll", ".dotm"];
const EXECUTABLE_EXTENSIONS = [
  ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".vbe", ".ps1", ".ps2",
  ".js", ".jse", ".wsf", ".wsh", ".hta", ".msi", ".jar", ".lnk", ".reg", ".cpl",
];
const ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z", ".iso", ".img"];

// (6) Benign-looking inner extension followed by a dangerous one (faktura.pdf.exe).
const DOUBLE_EXTENSION_RE = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|csv|zip|html?)\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|jar|msi|hta|ps1|wsf)$/i;

// (7) Content-Type values that denote an executable / installer.
const EXECUTABLE_MIME = [
  "application/x-msdownload", "application/x-msdos-program", "application/x-executable",
  "application/vnd.microsoft.portable-executable", "application/x-dosexec",
  "application/x-ms-installer", "application/x-elf",
];
const BENIGN_LOOKING_EXTENSIONS = [
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".jpg", ".jpeg", ".png", ".gif", ".txt", ".rtf", ".csv",
];

function analyzeAttachment(filename, contentType) {
  const lower = (filename || "").toLowerCase();
  const ext = "." + lower.split(".").pop();
  const ct = (contentType || "").toLowerCase().split(";")[0].trim();

  if (DOUBLE_EXTENSION_RE.test(lower)) {
    return { risk: "high", code: "double_extension", reason: "Podwójne rozszerzenie pliku (np. .pdf.exe) — bardzo wysokie ryzyko", filename };
  }
  if (ct && EXECUTABLE_MIME.includes(ct) && BENIGN_LOOKING_EXTENSIONS.includes(ext)) {
    return { risk: "high", code: "mime_extension_mismatch", reason: "Typ pliku nie zgadza się z rozszerzeniem (plik wykonywalny udający dokument)", filename };
  }
  if (EXECUTABLE_EXTENSIONS.includes(ext)) {
    return { risk: "high", code: "plik_wykonywalny", reason: "Plik wykonywalny — wysokie ryzyko", filename };
  }
  if (MACRO_EXTENSIONS.includes(ext)) {
    return { risk: "high", code: "dokument_z_makrami", reason: "Dokument Office z makrami — możliwy złośliwy kod", filename };
  }
  if (ARCHIVE_EXTENSIONS.includes(ext)) {
    return { risk: "medium", code: "archiwum", reason: "Archiwum — może zawierać ukryte pliki", filename };
  }
  if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
    return { risk: "medium", code: "podejrzane_rozszerzenie", reason: "Podejrzane rozszerzenie pliku", filename };
  }
  return { risk: "low", code: null, reason: null, filename };
}

function analyzeAttachments(attachments) {
  const results = [];
  for (const att of attachments) {
    const name = att.name || att.filename || "";
    if (name) results.push(analyzeAttachment(name, att.contentType));
  }
  return results;
}

function hasSuspiciousAttachments(attachments) {
  return analyzeAttachments(attachments).some(a => a.risk !== "low");
}

globalThis.PGAttachmentAnalyzer = { analyzeAttachment, analyzeAttachments, hasSuspiciousAttachments };

if (typeof module !== "undefined") {
  module.exports = { analyzeAttachment, analyzeAttachments, hasSuspiciousAttachments };
}
