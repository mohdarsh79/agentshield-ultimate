import { SecurityFinding, SecurityScoreReport, Severity, SecurityCategory } from "../types";

export class RiskEngine {
  private static readonly WEIGHTS: Record<Severity, number> = {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 5,
    LOW: 1,
    INFORMATIONAL: 0
  };

  public static calculateReport(findings: SecurityFinding[]): SecurityScoreReport {
    const bySeverity: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFORMATIONAL: 0
    };

    const byCategory: Record<SecurityCategory, number> = {
      CREDENTIAL: 0,
      PROMPT_INJECTION: 0,
      BROWSER: 0,
      FILESYSTEM: 0,
      NETWORK: 0,
      COMMAND: 0,
      MCP: 0,
      SKILL: 0,
      DOWNLOAD: 0,
      SUPPLY_CHAIN: 0,
      CONFIGURATION: 0,
      APPROVAL: 0
    };

    let totalPenalty = 0;

    for (const f of findings) {
      if (f.remediationStatus !== "REMEDIATED") {
        bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
        byCategory[f.category] = (byCategory[f.category] || 0) + 1;
        totalPenalty += this.WEIGHTS[f.severity];
      }
    }

    const score = Math.max(0, 100 - totalPenalty);
    const grade = this.computeGrade(score, bySeverity);

    return {
      score,
      grade,
      totalFindings: findings.length,
      bySeverity,
      byCategory,
      findings,
      timestamp: new Date().toISOString()
    };
  }

  private static computeGrade(score: number, counts: Record<Severity, number>): "A+" | "A" | "B" | "C" | "D" | "F" {
    if (counts.CRITICAL > 0) return "F";
    if (counts.HIGH > 1) return "D";
    if (counts.HIGH === 1) return "C";
    if (score >= 97) return "A+";
    if (score >= 90) return "A";
    if (score >= 80) return "B";
    if (score >= 70) return "C";
    if (score >= 60) return "D";
    return "F";
  }
}
