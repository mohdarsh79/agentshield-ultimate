import * as fs from "fs";
import * as path from "path";
import { SecurityFinding, AgentActionContext, SecurityEvaluationResult } from "../types";

export class FilesystemGuard {
  private static readonly SENSITIVE_DIRECTORIES = [
    "/etc",
    "/root",
    "/var/run",
    "/boot",
    "/proc",
    "/sys",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\ProgramData",
    "C:\\Users\\Default"
  ];

  private static readonly SENSITIVE_FILES = [
    ".env",
    ".git/config",
    "id_rsa",
    "id_ed25519",
    "id_dsa",
    "authorized_keys",
    "known_hosts",
    ".aws/credentials",
    ".aws/config",
    ".bash_history",
    ".zsh_history",
    "passwd",
    "shadow",
    "sam",
    "system32"
  ];

  private static readonly SENSITIVE_EXTENSIONS = [
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".kdbx",
    ".sqlite",
    ".db"
  ];

  public static evaluateFileAccess(ctx: AgentActionContext, workspaceRoot: string = process.cwd()): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    const targetPath = String(ctx.parameters?.path || ctx.target);

    // 1. Path Traversal Lexical Heuristic Detection
    let decoded: string;
    try {
      decoded = decodeURIComponent(targetPath);
    } catch {
      decoded = targetPath;
    }

    if (decoded.includes("..") || decoded.includes("%2e%2e") || decoded.includes("..\\") || decoded.includes("../")) {
      const finding: SecurityFinding = {
        id: `FIND-FS-TRAV-${Date.now().toString(36)}`,
        severity: "CRITICAL",
        confidence: "CERTAIN",
        category: "FILESYSTEM",
        title: "Directory Traversal Sequence Detected",
        evidence: `Target path '${targetPath}' contains directory traversal sequence ('..')`,
        affectedResource: targetPath,
        impact: "Arbitrary host filesystem access outside designated workspace sandbox.",
        mitigation: "Strictly normalize target paths and verify confinement to workspace boundary.",
        standardReference: "CWE-22 / Path Traversal",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      };
      findings.push(finding);
      return {
        allowed: false,
        blockedReason: `Path traversal / Directory traversal attack detected in path: ${targetPath}`,
        findings,
        scorePenalty: 25
      };
    }

    // 1b. Windows Reserved Device Names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    const baseName = path.basename(decoded).toUpperCase();
    if (/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i.test(baseName)) {
      const finding: SecurityFinding = {
        id: `FIND-FS-DEV-${Date.now().toString(36)}`,
        severity: "HIGH",
        confidence: "CERTAIN",
        category: "FILESYSTEM",
        title: "Windows Reserved Device Name Blocked",
        evidence: `Target file '${targetPath}' uses Windows reserved device name ('${baseName}').`,
        affectedResource: targetPath,
        impact: "Denial of service or hang when opening reserved device files on Windows host.",
        mitigation: "Block access to Windows reserved device names.",
        standardReference: "CWE-22 / Device Name Injection",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      };
      findings.push(finding);
      return {
        allowed: false,
        blockedReason: `Access to Windows reserved device name '${baseName}' is prohibited`,
        findings,
        scorePenalty: 20
      };
    }

    // 2. Sensitive System Directories Blocklist
    const normalizedTarget = path.normalize(decoded);
    for (const sensDir of this.SENSITIVE_DIRECTORIES) {
      if (normalizedTarget.toLowerCase().startsWith(sensDir.toLowerCase())) {
        const finding: SecurityFinding = {
          id: `FIND-FS-SYSDIR-${Date.now().toString(36)}`,
          severity: "CRITICAL",
          confidence: "CERTAIN",
          category: "FILESYSTEM",
          title: "Sensitive Operating System Directory Access Blocked",
          evidence: `Attempted access to critical system path: ${normalizedTarget}`,
          affectedResource: targetPath,
          impact: "Unauthorized modification or disclosure of operating system files.",
          mitigation: "Prevent autonomous agents from accessing host system directories.",
          standardReference: "CWE-284 / Access Control",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Access to sensitive system directory is prohibited: ${sensDir}`,
          findings,
          scorePenalty: 25
        };
      }
    }

    // 3. Sensitive Files (Credentials & Keys)
    for (const sensFile of this.SENSITIVE_FILES) {
      if (normalizedTarget.toLowerCase().includes(sensFile.toLowerCase())) {
        const finding: SecurityFinding = {
          id: `FIND-FS-CRED-${Date.now().toString(36)}`,
          severity: "CRITICAL",
          confidence: "HIGH",
          category: "FILESYSTEM",
          title: "Sensitive Credential File Access Blocked",
          evidence: `Target path '${targetPath}' matches credential signature: ${sensFile}`,
          affectedResource: targetPath,
          impact: "Exfiltration of developer SSH keys, AWS credentials, or system account passwords.",
          mitigation: "Deny agent read/write permissions to credential files and keystores.",
          standardReference: "OWASP-LLM02 / Credential Protection",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Access to sensitive credential file blocked: ${sensFile}`,
          findings,
          scorePenalty: 25
        };
      }
    }

    // 4. Sensitive Extension Blocklist
    const ext = path.extname(normalizedTarget).toLowerCase();
    if (this.SENSITIVE_EXTENSIONS.includes(ext)) {
      const finding: SecurityFinding = {
        id: `FIND-FS-EXT-${Date.now().toString(36)}`,
        severity: "HIGH",
        confidence: "CERTAIN",
        category: "FILESYSTEM",
        title: "Restricted File Extension Blocked",
        evidence: `File extension '${ext}' indicates cryptographic keys or private database files.`,
        affectedResource: targetPath,
        impact: "Potential exfiltration of cryptographic secrets or private databases.",
        mitigation: "Restrict agent access to approved code and text file extensions.",
        standardReference: "CWE-200 / Information Exposure",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      };
      findings.push(finding);
      return {
        allowed: false,
        blockedReason: `Access to files with extension '${ext}' is restricted by security policy`,
        findings,
        scorePenalty: 15
      };
    }

    // 5. Workspace Boundary Confinement & Canonical Symlink Validation
    try {
      const resolvedWorkspace = path.resolve(workspaceRoot);
      const resolvedTarget = path.isAbsolute(decoded) ? path.resolve(decoded) : path.resolve(resolvedWorkspace, decoded);

      // Lexical check
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

      // Canonical realpath check: walk all existing ancestors to block symlink parent escapes (AS-01)
      const realWorkspace = fs.existsSync(resolvedWorkspace) ? fs.realpathSync(resolvedWorkspace) : resolvedWorkspace;
      
      // Determine nearest existing ancestor
      let ancestorToCheck = resolvedTarget;
      while (!fs.existsSync(ancestorToCheck) && ancestorToCheck !== path.dirname(ancestorToCheck)) {
        ancestorToCheck = path.dirname(ancestorToCheck);
      }

      if (fs.existsSync(ancestorToCheck)) {
        const realAncestor = fs.realpathSync(ancestorToCheck);
        const relToWorkspace = path.relative(realWorkspace, realAncestor);

        if (relToWorkspace.startsWith("..") || path.isAbsolute(relToWorkspace)) {
          const finding: SecurityFinding = {
            id: `FIND-FS-SYMLINK-${Date.now().toString(36)}`,
            severity: "CRITICAL",
            confidence: "CERTAIN",
            category: "FILESYSTEM",
            title: "Symlink Escape to External Path Blocked",
            evidence: `Target path '${targetPath}' resolves via symlink ancestor to external host location '${realAncestor}' outside '${realWorkspace}'`,
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
            blockedReason: `Target path or its parent resolves via symlink to outside the workspace: ${realAncestor}`,
            findings,
            scorePenalty: 25
          };
        }
      }

      return { allowed: true, findings, scorePenalty: 0 };
    } catch {
      return { allowed: true, findings, scorePenalty: 0 };
    }
  }
}
