"use strict";

function scoreToRisk(score) {
  if (score >= 90) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function buildRiskResult(score, reasons, details) {
  return {
    score: Math.max(0, score),
    risk: scoreToRisk(Math.max(0, score)),
    reasons,
    details: details || {},
  };
}

globalThis.PGRiskScoring = { scoreToRisk, buildRiskResult };

if (typeof module !== "undefined") {
  module.exports = { scoreToRisk, buildRiskResult };
}
