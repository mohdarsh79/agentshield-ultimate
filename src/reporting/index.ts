import { SecurityScoreReport, SecurityFinding } from "../types";

export class SecurityReporter {
  public static toJson(report: SecurityScoreReport): string {
    return JSON.stringify(report, null, 2);
  }

  public static toMarkdown(report: SecurityScoreReport): string {
    let md = `# AgentShield Ultimate Security Report\n\n`;
    md += `**Security Score**: ${report.score} / 100\n`;
    md += `**Grade**: ${report.grade}\n`;
    md += `**Generated**: ${report.timestamp}\n`;
    md += `**Total Findings**: ${report.totalFindings}\n\n`;

    md += `## Severity Summary\n\n`;
    md += `| Severity | Count |\n| :--- | :--- |\n`;
    for (const [sev, count] of Object.entries(report.bySeverity)) {
      md += `| ${sev} | ${count} |\n`;
    }

    md += `\n## Detailed Findings\n\n`;
    if (report.findings.length === 0) {
      md += `No security vulnerabilities or policy violations detected.\n`;
    } else {
      for (const f of report.findings) {
        md += `### [${f.severity}] ${f.title} (${f.id})\n\n`;
        md += `- **Category**: ${f.category}\n`;
        md += `- **Affected Resource**: \`${f.affectedResource}\`\n`;
        md += `- **Evidence**: ${f.evidence}\n`;
        md += `- **Impact**: ${f.impact}\n`;
        md += `- **Mitigation**: ${f.mitigation}\n`;
        md += `- **Standard Reference**: ${f.standardReference}\n\n`;
      }
    }

    return md;
  }

  public static toSarif(report: SecurityScoreReport): string {
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "AgentShield Ultimate",
              version: "1.0.0",
              informationUri: "https://github.com/affaan-m/agentshield-ultimate",
              rules: report.findings.map(f => ({
                id: f.id,
                name: f.title,
                shortDescription: { text: f.title },
                fullDescription: { text: f.impact },
                help: { text: f.mitigation },
                defaultConfiguration: {
                  level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : "warning"
                }
              }))
            }
          },
          results: report.findings.map(f => ({
            ruleId: f.id,
            level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : "warning",
            message: { text: `${f.title}: ${f.evidence}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.affectedResource }
                }
              }
            ]
          }))
        }
      ]
    };

    return JSON.stringify(sarif, null, 2);
  }

  public static toAnsi(report: SecurityScoreReport): string {
    const lines: string[] = [];
    lines.push("\n=======================================================");
    lines.push(` AGENTSHIELD ULTIMATE SECURITY REPORT`);
    lines.push("=======================================================");
    lines.push(` Security Score : ${report.score} / 100   [Grade: ${report.grade}]`);
    lines.push(` Total Findings : ${report.totalFindings}`);
    lines.push(` CRITICAL: ${report.bySeverity.CRITICAL} | HIGH: ${report.bySeverity.HIGH} | MEDIUM: ${report.bySeverity.MEDIUM} | LOW: ${report.bySeverity.LOW}`);
    lines.push("-------------------------------------------------------");

    if (report.findings.length === 0) {
      lines.push(" [OK] No vulnerabilities or policy violations detected.");
    } else {
      for (const f of report.findings) {
        lines.push(` [${f.severity}] ${f.title}`);
        lines.push(`   Target: ${f.affectedResource}`);
        lines.push(`   Evidence: ${f.evidence}`);
        lines.push(`   Mitigation: ${f.mitigation}`);
        lines.push("");
      }
    }
    lines.push("=======================================================\n");
    return lines.join("\n");
  }
}
