import * as fs from "fs";
import * as path from "path";
import { SecurityFinding, SecurityScoreReport } from "../types";
import { SkillScanner } from "../skill-scanner";
import { McpGuard } from "../mcp-guard";
import { DownloadGuard } from "../download-guard";
import { SecretGuard } from "../secret-guard";
import { CommandGuard } from "../command-guard";
import { RiskEngine } from "../core/risk-engine";

export interface WorkspaceScanOptions {
  maxDepth?: number;
  maxFileSizeMb?: number;
  skipHidden?: boolean;
}

export class WorkspaceScanner {
  private static readonly IGNORED_DIRS = new Set([
    "node_modules",
    ".git",
    "dist",
    "build",
    "out",
    ".agentshield",
    ".next",
    ".cache",
    "coverage",
    ".terraform"
  ]);

  private static readonly IGNORED_EXTENSIONS = new Set([
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pdf", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi"
  ]);

  private static readonly SHELL_SCRIPT_EXTENSIONS = new Set([
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1"
  ]);

  public static scan(workspaceRoot: string, options: WorkspaceScanOptions = {}): SecurityScoreReport {
    const startTime = performance.now();
    const findings: SecurityFinding[] = [];
    const maxDepth = options.maxDepth ?? 10;
    const maxFileSizeBytes = (options.maxFileSizeMb ?? 5) * 1024 * 1024;

    let filesInspected = 0;
    let filesSkipped = 0;

    // 1. Skill Scanner
    const skillRes = SkillScanner.scanDirectory(workspaceRoot);
    findings.push(...skillRes.findings);

    // 2. MCP Configurations Audit (.mcp.json, mcp-servers.json, claude_desktop_config.json)
    const mcpCandidateFiles = [
      path.join(workspaceRoot, ".mcp.json"),
      path.join(workspaceRoot, "mcp-servers.json"),
      path.join(workspaceRoot, "mcp.json"),
      path.join(workspaceRoot, ".claude", "mcp-servers.json")
    ];
    for (const mcpFile of mcpCandidateFiles) {
      if (fs.existsSync(mcpFile)) {
        findings.push(...McpGuard.auditConfigFile(mcpFile));
      }
    }

    // 3. Package Lifecycle Hook & Dependencies Audit (package.json)
    const pkgPath = path.join(workspaceRoot, "package.json");
    if (fs.existsSync(pkgPath)) {
      findings.push(...DownloadGuard.auditPackageJson(pkgPath));
    }

    // 4. Recursive Workspace Traversal (Secret Detection, Sensitive Files, Shell Scripts)
    const walk = (dir: string, depth: number) => {
      if (depth > maxDepth) return;

      let entries: fs.Dirent[] = [];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (this.IGNORED_DIRS.has(entry.name)) {
            filesSkipped++;
            continue;
          }
          walk(fullPath, depth + 1);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (this.IGNORED_EXTENSIONS.has(ext)) {
            filesSkipped++;
            continue;
          }

          // Check for exposed credential / .env files
          if (entry.name.startsWith(".env") || entry.name.includes("id_rsa") || entry.name.includes("credentials.json")) {
            findings.push({
              id: `FIND-WS-SENS-${Date.now().toString(36)}-${filesInspected}`,
              severity: "CRITICAL",
              confidence: "CERTAIN",
              category: "CREDENTIAL",
              title: "Exposed Sensitive Credential File",
              evidence: `Sensitive environment or credential file present in workspace: ${path.relative(workspaceRoot, fullPath)}`,
              affectedResource: fullPath,
              impact: "Accidental commit or agent exfiltration of active API tokens and credentials.",
              mitigation: "Add sensitive file to .gitignore and use environment secret managers.",
              standardReference: "CWE-200 / OWASP-LLM02",
              remediationStatus: "OPEN",
              timestamp: new Date().toISOString()
            });
          }

          try {
            const stat = fs.statSync(fullPath);
            if (stat.size > maxFileSizeBytes) {
              filesSkipped++;
              continue;
            }

            // Inspect text files for hardcoded secrets and dangerous script commands
            // Exclude reports, test output, and node_modules
            const rel = path.relative(workspaceRoot, fullPath);
            const isDocOrAudit = rel.startsWith("security-audit") || rel.startsWith("docs") || rel.includes(".test.") || rel.endsWith(".md");

            if (!isDocOrAudit) {
              const content = fs.readFileSync(fullPath, "utf-8");

              // Secret scanning
              const secretRes = SecretGuard.scanAndRedact(content, fullPath);
              findings.push(...secretRes.findings);

              // Script / Command audit for shell files
              if (this.SHELL_SCRIPT_EXTENSIONS.has(ext)) {
                this.auditScriptFile(fullPath, content, findings);
              }
            }

            filesInspected++;
          } catch {
            filesSkipped++;
          }
        }
      }
    };

    walk(workspaceRoot, 0);

    const report = RiskEngine.calculateReport(findings);
    const durationMs = Math.round(performance.now() - startTime);

    report.coverage = {
      filesInspected,
      filesSkipped,
      durationMs,
      scannersActive: ["SkillScanner", "McpGuard", "DownloadGuard", "SecretGuard", "CommandGuard", "FilesystemGuard"]
    };

    return report;
  }

  private static auditScriptFile(filePath: string, content: string, findings: SecurityFinding[]): void {
    const dangerousPatterns = [
      { pattern: /curl\s+.*\|\s*(ba)?sh/i, title: "Remote Script Piped to Shell", severity: "CRITICAL" as const },
      { pattern: /wget\s+.*\|\s*(ba)?sh/i, title: "Remote Script Piped to Shell", severity: "CRITICAL" as const },
      { pattern: /rm\s+-rf\s+(\/|~|\$HOME|\*)/i, title: "Destructive Root/Home Directory Deletion", severity: "CRITICAL" as const },
      { pattern: /nc\s+-[el].*\/(ba)?sh/i, title: "Netcat Reverse Shell Execution", severity: "CRITICAL" as const },
      { pattern: /chmod\s+777\b/i, title: "Dangerous Overly Permissive File Permissions", severity: "HIGH" as const }
    ];

    for (const rule of dangerousPatterns) {
      if (rule.pattern.test(content)) {
        findings.push({
          id: `FIND-SCRIPT-CMD-${Date.now().toString(36)}-${findings.length}`,
          severity: rule.severity,
          confidence: "HIGH",
          category: "COMMAND",
          title: `Dangerous Command in Workspace Script: ${rule.title}`,
          evidence: `Found dangerous command pattern matching ${rule.pattern} in ${filePath}`,
          affectedResource: filePath,
          impact: "Uncontrolled arbitrary code execution or host filesystem destruction.",
          mitigation: "Replace unbounded shell commands with validated, isolated routines.",
          standardReference: "CWE-78 / OWASP-LLM06",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
      }
    }
  }
}
