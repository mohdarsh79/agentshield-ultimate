import * as fs from "fs";
import * as crypto from "crypto";
import * as path from "path";
import { SecurityFinding, Severity, AgentActionContext, SecurityEvaluationResult } from "../types";

export interface FileAnalysisResult {
  isSafe: boolean;
  mimeTypeEstimate: string;
  sha256: string;
  findings: SecurityFinding[];
}

export class DownloadGuard {
  // Magic byte signatures for dangerous binary executables
  private static readonly EXECUTABLE_SIGNATURES: Array<{ magic: Buffer; name: string; severity: Severity }> = [
    { magic: Buffer.from([0x4D, 0x5A]), name: "Windows PE Executable (.exe, .dll)", severity: "CRITICAL" },
    { magic: Buffer.from([0x7F, 0x45, 0x4C, 0x46]), name: "Linux ELF Executable Binary", severity: "CRITICAL" },
    { magic: Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]), name: "Mach-O Universal Binary", severity: "CRITICAL" },
    { magic: Buffer.from([0xCF, 0xFA, 0xED, 0xFE]), name: "Mach-O 64-bit Binary", severity: "CRITICAL" }
  ];

  private static readonly RESTRICTED_EXTENSIONS = new Set([
    ".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".bat", ".cmd", ".vbs", ".ps1"
  ]);

  // Runtime Download Interception (AS-06)
  public static evaluateDownload(ctx: AgentActionContext): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    const targetUrlOrPath = String(ctx.parameters?.url || ctx.parameters?.path || ctx.target);
    const ext = path.extname(targetUrlOrPath.split("?")[0]).toLowerCase();

    // 1. Extension inspection
    if (this.RESTRICTED_EXTENSIONS.has(ext)) {
      const finding: SecurityFinding = {
        id: `FIND-DL-EXT-${Date.now().toString(36)}`,
        severity: "CRITICAL",
        confidence: "CERTAIN",
        category: "DOWNLOAD",
        title: `Restricted Binary/Script Download Blocked: ${ext}`,
        evidence: `Download destination or URL '${targetUrlOrPath}' specifies prohibited executable extension '${ext}'`,
        affectedResource: targetUrlOrPath,
        impact: "Arbitrary binary execution or malicious script delivery into host workspace.",
        mitigation: "Block download of compiled executables and shell scripts.",
        standardReference: "CWE-434 / Download of Dangerous File Type",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      };
      findings.push(finding);
      return {
        allowed: false,
        blockedReason: `Download of executable binary or script with extension '${ext}' is prohibited`,
        findings,
        scorePenalty: 25
      };
    }

    // 2. If target is a local file already downloaded, inspect magic bytes
    if (fs.existsSync(targetUrlOrPath)) {
      const analysis = this.inspectDownloadedFile(targetUrlOrPath);
      if (!analysis.isSafe) {
        return {
          allowed: false,
          blockedReason: "Downloaded file contains dangerous executable magic bytes signature",
          findings: analysis.findings,
          scorePenalty: 25
        };
      }
    }

    return { allowed: true, findings, scorePenalty: 0 };
  }

  public static inspectDownloadedFile(filePath: string): FileAnalysisResult {
    const findings: SecurityFinding[] = [];
    if (!fs.existsSync(filePath)) {
      return { isSafe: false, mimeTypeEstimate: "unknown", sha256: "", findings };
    }

    const buffer = fs.readFileSync(filePath);
    const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
    let mimeTypeEstimate = "application/octet-stream";
    let isSafe = true;

    // 1. Check Magic Byte Executable Signatures
    for (const sig of this.EXECUTABLE_SIGNATURES) {
      if (buffer.length >= sig.magic.length && buffer.subarray(0, sig.magic.length).equals(sig.magic)) {
        mimeTypeEstimate = "application/x-executable";
        isSafe = false;
        findings.push({
          id: `FIND-DL-EXEC-${Date.now().toString(36)}`,
          severity: sig.severity,
          confidence: "CERTAIN",
          category: "DOWNLOAD",
          title: `Executable Binary Download Detected: ${sig.name}`,
          evidence: `File header matches executable magic bytes. SHA256: ${sha256}`,
          affectedResource: filePath,
          impact: "Autonomous download of compiled binary files risks arbitrary local execution.",
          mitigation: "Prohibit agents from downloading or executing compiled binary artifacts.",
          standardReference: "CWE-434 / Supply-Chain Security",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
        break;
      }
    }

    return { isSafe, mimeTypeEstimate, sha256, findings };
  }

  // Audit package.json lifecycle scripts for supply-chain backdoors
  public static auditPackageJson(packageJsonPath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    if (!fs.existsSync(packageJsonPath)) return findings;

    try {
      const data = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
      const scripts = data.scripts || {};

      for (const hook of ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"]) {
        if (scripts[hook]) {
          const scriptBody = String(scripts[hook]);
          if (/curl|wget|nc\s+|bash|sh|eval/i.test(scriptBody)) {
            findings.push({
              id: `FIND-DEP-LIFECYCLE-${Date.now().toString(36)}`,
              severity: "HIGH",
              confidence: "HIGH",
              category: "SUPPLY_CHAIN",
              title: `Suspicious Lifecycle Script Hook: ${hook}`,
              evidence: `Hook '${hook}' executes network or shell pipeline: "${scriptBody}"`,
              affectedResource: packageJsonPath,
              impact: "Automatic remote execution during package installation (npm install).",
              mitigation: "Inspect lifecycle scripts and run installations with '--ignore-scripts'.",
              standardReference: "OWASP-LLM03 / Supply-Chain Attack",
              remediationStatus: "OPEN",
              timestamp: new Date().toISOString()
            });
          }
        }
      }
    } catch {
      // Graceful error ignore on unparseable JSON
    }

    return findings;
  }
}
