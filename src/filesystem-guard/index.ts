import * as path from "path";
import * as fs from "fs";
import { SecurityFinding, AgentActionContext, SecurityEvaluationResult } from "../types";

export class FilesystemGuard {
  private static readonly SENSITIVE_PATTERNS = [
    /\.ssh[/\\]/i,
    /id_rsa/i,
    /id_ed25519/i,
    /\.aws[/\\]credentials/i,
    /\.env($|\.)/i,
    /\.git[/\\]config/i,
    /\/etc\/(passwd|shadow)/i,
    /C:\\Windows\\System32\\config/i
  ];

  // Windows Reserved Device Names
  private static readonly WINDOWS_DEVICE_NAMES = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i;

  public static evaluateFileAccess(ctx: AgentActionContext, workspaceRoot: string = process.cwd()): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    let targetPath = ctx.target;

    // 1. Decode potential nested URL encodings (%252e%252e -> %2e%2e -> ..)
    let decoded = targetPath;
    for (let i = 0; i < 3; i++) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        break;
      }
    }

    // 2. Path Traversal Detection (checking decoded path for .. or encoded variations)
    if (decoded.includes("..") || /%2e%2e/i.test(decoded)) {
      const finding: SecurityFinding = {
        id: `FIND-FS-TRAV-${Date.now().toString(36)}`,
        severity: "CRITICAL",
        confidence: "CERTAIN",
        category: "FILESYSTEM",
        title: "Path Traversal Attempt Detected",
        evidence: `Raw or decoded path contains directory traversal sequences: '${targetPath}'`,
        affectedResource: targetPath,
        impact: "Allows arbitrary access to files outside designated workspace boundaries.",
        mitigation: "Normalize paths and strictly verify root confinement.",
        standardReference: "CWE-22 / OWASP-LLM06",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      };
      findings.push(finding);
      return {
        allowed: false,
        blockedReason: `Path traversal sequence detected in file operation: ${targetPath}`,
        findings,
        scorePenalty: 25
      };
    }

    // 3. Windows Reserved Device Name Check
    const baseName = path.basename(decoded);
    if (this.WINDOWS_DEVICE_NAMES.test(baseName)) {
      const finding: SecurityFinding = {
        id: `FIND-FS-DEVNAME-${Date.now().toString(36)}`,
        severity: "HIGH",
        confidence: "CERTAIN",
        category: "FILESYSTEM",
        title: "Windows Reserved Device Name Access Blocked",
        evidence: `Filename '${baseName}' is a reserved OS device name (CON, PRN, AUX, NUL, COM1-9).`,
        affectedResource: targetPath,
        impact: "Accessing reserved device names can cause hang, denial of service, or driver faults.",
        mitigation: "Deny access to MS-DOS legacy device namespaces.",
        standardReference: "CWE-400 / Windows Device Protection",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      };
      findings.push(finding);
      return {
        allowed: false,
        blockedReason: `Access denied to Windows reserved device name: ${baseName}`,
        findings,
        scorePenalty: 15
      };
    }

    // 4. Sensitive Credential File Check
    const normalizedTarget = path.normalize(decoded);
    for (const pat of this.SENSITIVE_PATTERNS) {
      if (pat.test(normalizedTarget)) {
        const finding: SecurityFinding = {
          id: `FIND-FS-SENS-${Date.now().toString(36)}`,
          severity: "CRITICAL",
          confidence: "CERTAIN",
          category: "FILESYSTEM",
          title: "Sensitive Credential File Access Blocked",
          evidence: `File target '${targetPath}' matches protected sensitive path pattern.`,
          affectedResource: targetPath,
          impact: "Exposure or modification of private keys, environment secrets, or identity stores.",
          mitigation: "Exclude sensitive system and credential directories from agent access.",
          standardReference: "CWE-200 / OWASP-LLM02",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Access denied to sensitive credential file: ${targetPath}`,
          findings,
          scorePenalty: 25
        };
      }
    }

    // 5. Workspace Boundary Confinement & Symlink Resolution
    try {
      const resolvedWorkspace = path.resolve(workspaceRoot);
      const resolvedTarget = path.resolve(workspaceRoot, decoded);

      // Check if path escapes workspace root
      const relative = path.relative(resolvedWorkspace, resolvedTarget);
      if (relative.startsWith("..") || path.isAbsolute(relative)) {
        const finding: SecurityFinding = {
          id: `FIND-FS-ESCAPE-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "CERTAIN",
          category: "FILESYSTEM",
          title: "Workspace Boundary Escape Blocked",
          evidence: `Resolved target '${resolvedTarget}' escapes workspace root '${resolvedWorkspace}'`,
          affectedResource: targetPath,
          impact: "Agent operating on unauthorized host system directories.",
          mitigation: "Confine agent filesystem operations to explicit project directory.",
          standardReference: "CWE-22 / Least-Privilege Sandboxing",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Target path escapes workspace boundaries: ${targetPath}`,
          findings,
          scorePenalty: 15
        };
      }

      // Check real path for symlink escapes if file exists
      if (fs.existsSync(resolvedTarget)) {
        const real = fs.realpathSync(resolvedTarget);
        const realRelative = path.relative(resolvedWorkspace, real);
        if (realRelative.startsWith("..") || path.isAbsolute(realRelative)) {
          const finding: SecurityFinding = {
            id: `FIND-FS-SYMLINK-${Date.now().toString(36)}`,
            severity: "CRITICAL",
            confidence: "CERTAIN",
            category: "FILESYSTEM",
            title: "Symlink Escape to External File Blocked",
            evidence: `Target symlink '${targetPath}' points to external location '${real}'`,
            affectedResource: targetPath,
            impact: "Bypasses workspace boundary via symlink redirection.",
            mitigation: "Deny traversal of symlinks that target paths outside workspace.",
            standardReference: "CWE-59 / Symlink Verification",
            remediationStatus: "OPEN",
            timestamp: new Date().toISOString()
          };
          findings.push(finding);
          return {
            allowed: false,
            blockedReason: `Symlink escape detected pointing outside workspace: ${real}`,
            findings,
            scorePenalty: 25
          };
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        allowed: false,
        blockedReason: `Filesystem safety check failure (fail-closed): ${msg}`,
        findings,
        scorePenalty: 10
      };
    }

    return { allowed: true, findings, scorePenalty: 0 };
  }
}
