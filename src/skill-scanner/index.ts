import * as fs from "fs";
import * as path from "path";
import { SecurityFinding, Severity } from "../types";

export interface SkillScanSummary {
  targetPath: string;
  filesScanned: number;
  findings: SecurityFinding[];
  isSafe: boolean;
}

export class SkillScanner {
  private static readonly DANGEROUS_SHELL_PATTERNS: Array<{ regex: RegExp; name: string; severity: Severity; impact: string }> = [
    { regex: /curl\s+[^|\n`]+\|\s*(ba|z)?sh/i, name: "Remote Script Piped to Shell", severity: "CRITICAL", impact: "Arbitrary uninspected remote code execution." },
    { regex: /wget\s+[^|\n`]+\|\s*(ba|z)?sh/i, name: "Remote Script Piped to Shell", severity: "CRITICAL", impact: "Arbitrary uninspected remote code execution." },
    { regex: /(?:bash|sh|cmd|powershell|exec|run|command)[^\n]*?rm\s+(-rf|-fr)\s+(\/|~|\$HOME)/i, name: "Destructive Root/Home Directory Deletion", severity: "CRITICAL", impact: "Irreversible loss of operating system or user data." },
    { regex: /nc\s+.*-e\s+\/bin\/(ba)?sh/i, name: "Netcat Reverse Shell Execution", severity: "CRITICAL", impact: "Backdoor shell exfiltrating local command control." },
    { regex: /chmod\s+(-R\s+)?777/i, name: "Dangerous Overly Permissive File Permissions", severity: "HIGH", impact: "Exposes local files to read/write by any local user." },
    { regex: /eval\s*\(\s*(\$|process\.env|Buffer\.from)/i, name: "Dynamic Unsafe Eval Execution", severity: "HIGH", impact: "Executes unvalidated runtime strings." }
  ];

  private static readonly HIDDEN_PROMPT_PATTERNS: Array<{ regex: RegExp; name: string }> = [
    { regex: /<!--[\s\S]*?(system\s+prompt|ignore\s+all|override)[\s\S]*?-->/i, name: "Hidden Prompt Injection in HTML Comment" },
    { regex: /\[\/\/\]:\s*#\s*\((.*?)(jailbreak|leak|exfiltrate|secret).*?\)/i, name: "Hidden Adversarial Markdown Directive" }
  ];

  public static scanFile(filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    if (!fs.existsSync(filePath)) return findings;

    const content = fs.readFileSync(filePath, "utf-8");
    const filename = path.basename(filePath);

    // 1. Check for Dangerous Shell Execution Patterns
    for (const pat of this.DANGEROUS_SHELL_PATTERNS) {
      const match = content.match(pat.regex);
      if (match) {
        findings.push({
          id: `FIND-SKILL-CMD-${Date.now().toString(36)}`,
          severity: pat.severity,
          confidence: "CERTAIN",
          category: "SKILL",
          title: `Dangerous Command in Skill: ${pat.name}`,
          evidence: `Found pattern: "${match[0]}" in ${filename}`,
          affectedResource: filePath,
          impact: pat.impact,
          mitigation: "Replace unsafe shell executions with secure, bounded API calls.",
          standardReference: "CWE-78 / OWASP-LLM03",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
      }
    }

    // 2. Check for Hidden Prompts in Documentation/Skill Files
    for (const pat of this.HIDDEN_PROMPT_PATTERNS) {
      const match = content.match(pat.regex);
      if (match) {
        findings.push({
          id: `FIND-SKILL-HID-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "HIGH",
          category: "SKILL",
          title: pat.name,
          evidence: `Suspicious hidden markdown payload: "${match[0].substring(0, 100)}" in ${filename}`,
          affectedResource: filePath,
          impact: "Hidden instructions that attempt to alter agent behavior when skill is indexed.",
          mitigation: "Strip hidden comments and verify skill text transparency.",
          standardReference: "OWASP-LLM01 / Supply-Chain Security",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  public static scanDirectory(dirPath: string): SkillScanSummary {
    const findings: SecurityFinding[] = [];
    let filesScanned = 0;

    const traverse = (current: string) => {
      if (!fs.existsSync(current)) return;
      const entries = fs.readdirSync(current, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(current, entry.name);
        if (entry.isDirectory()) {
          if (!["node_modules", ".git", "dist", "src", "tests", ".agentshield_backup"].includes(entry.name)) {
            traverse(fullPath);
          }
        } else if (entry.isFile()) {
          // If it's documentation or markdown describing security rules, skip pure text descriptions
          if (["README.md", "SECURITY_TESTING.md"].includes(entry.name)) {
            continue;
          }
          const ext = path.extname(entry.name).toLowerCase();
          if ([".md", ".json", ".yaml", ".yml", ".sh"].includes(ext)) {
            filesScanned++;
            findings.push(...this.scanFile(fullPath));
          }
        }
      }
    };

    traverse(dirPath);

    return {
      targetPath: dirPath,
      filesScanned,
      findings,
      isSafe: findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length === 0
    };
  }
}
