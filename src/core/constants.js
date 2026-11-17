"use strict";

const RISK_LEVELS = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

const RISK_THRESHOLDS = {
  MEDIUM: 30,
  HIGH: 60,
  CRITICAL: 90,
};

const SCORES = {
  SENDER_LOOKALIKE: 45,
  LINK_DOMAIN_LOOKALIKE: 45,
  LINK_TEXT_HREF_MISMATCH: 35,
  PUNYCODE_IDN: 30,
  REPLY_TO_MISMATCH: 25,
  LINK_IP: 25,
  SUSPICIOUS_ATTACHMENT: 20,
  FIRST_TIME_SENDER: 15,
  LINK_SHORTENER: 15,
  URGENCY_KEYWORDS: 10,
  TLD_SWAP: 10,
  TRUSTED_DOMAIN: -20,
  KNOWN_SENDER: -10,
};

const URGENCY_KEYWORDS_PL = [
  "pilne", "natychmiast", "blokada konta", "reset hasła", "zablokowane",
  "weryfikacja", "wygasa", "ostatnia szansa", "działaj teraz", "kliknij teraz",
  "potwierdź teraz", "twoje konto", "hasło wygasło", "zawieszone",
];

const URGENCY_KEYWORDS_EN = [
  "urgent", "immediately", "account blocked", "password reset", "suspended",
  "verify", "expires", "last chance", "act now", "click now",
  "confirm now", "your account", "password expired",
];

const LINK_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
  "goo.gl", "short.link", "rebrand.ly", "is.gd", "cli.gs",
];

const SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
  ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".vbe",
  ".js", ".jse", ".wsf", ".wsh", ".ps1", ".ps2", ".msi", ".hta",
  ".docm", ".xlsm", ".pptm", ".xlam", ".xll", ".dotm",
  ".zip", ".rar", ".7z", ".iso", ".img",
];

const HOMOGLYPH_MAP = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
  "6": "b", "8": "b", "@": "a",
  // Cyrillic lookalikes
  "а": "a", "е": "e", "о": "o", "р": "p",
  "с": "c", "у": "y", "х": "x",
  "і": "i", "А": "a", "Е": "e", "О": "o",
};

const CONFUSABLE_SEQUENCES = [
  ["rn", "m"], ["vv", "w"], ["cl", "d"], ["ii", "u"],
];

if (typeof module !== "undefined") {
  module.exports = {
    RISK_LEVELS, RISK_THRESHOLDS, SCORES, URGENCY_KEYWORDS_PL,
    URGENCY_KEYWORDS_EN, LINK_SHORTENERS, SUSPICIOUS_ATTACHMENT_EXTENSIONS,
    HOMOGLYPH_MAP, CONFUSABLE_SEQUENCES,
  };
}
