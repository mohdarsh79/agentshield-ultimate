import { PolicyProfile, AgentActionContext, SecurityEvaluationResult, SecurityScoreReport, SecurityFinding } from "../types";
import { PolicyEngine } from "../core/policy-engine";
import { RiskEngine } from "../core/risk-engine";
import { AuditLogger } from "../core/audit-logger";
import { PromptGuard, PromptScanResult } from "../prompt-guard";
import { BrowserGuard, BrowserValidationResult } from "../browser-guard";
import { SkillScanner, SkillScanSummary } from "../skill-scanner";
import { McpGuard } from "../mcp-guard";
import { FilesystemGuard } from "../filesystem-guard";
import { NetworkGuard, NetworkPolicyOptions } from "../network-guard";
import { SecretGuard, SecretScanResult } from "../secret-guard";
import { CommandGuard } from "../command-guard";
import { DownloadGuard, FileAnalysisResult } from "../download-guard";
import { ApprovalEngine, ApprovalRequest } from "../approval-engine";
import { RemediationEngine, RemediationResult } from "../remediation";
import { SecurityReporter } from "../reporting";

export interface AgentShieldConfig {
  profile?: PolicyProfile;
  workspaceRoot?: string;
  auditLogPath?: string;
}

export class AgentShield {
  public policyEngine: PolicyEngine;
  public auditLogger: AuditLogger;
  public approvalEngine: ApprovalEngine;
  public remediationEngine: RemediationEngine;
  public workspaceRoot: string;

  constructor(config: AgentShieldConfig = {}) {
    this.workspaceRoot = config.workspaceRoot || process.cwd();
    this.auditLogger = new AuditLogger(config.auditLogPath);
    this.policyEngine = new PolicyEngine(config.profile || "strict", this.auditLogger);
    this.approvalEngine = new ApprovalEngine(300);
    this.remediationEngine = new RemediationEngine(this.workspaceRoot);
  }

  // Action Interception Gate
  public interceptAction(ctx: AgentActionContext): SecurityEvaluationResult {
    // 1. Filesystem Guard check if file action
    if (ctx.actionType.startsWith("file_")) {
      const fsRes = FilesystemGuard.evaluateFileAccess(ctx, this.workspaceRoot);
      if (!fsRes.allowed) return fsRes;
    }

    // 2. Browser Guard check if browser action
    if (ctx.actionType.startsWith("browser_")) {
      const brwRes = BrowserGuard.evaluateBrowserAction(ctx);
      if (!brwRes.allowed) return brwRes;
    }

    // 3. Command Guard check if command execution
    if (ctx.actionType === "command_execute") {
      const cmdRes = CommandGuard.evaluateCommand(ctx);
      if (!cmdRes.allowed) return cmdRes;
    }

    // 4. Network Guard check if network request
    if (ctx.actionType === "network_request") {
      const netRes = NetworkGuard.evaluateRequest(ctx);
      if (!netRes.allowed) return netRes;
    }

    // 4. Central Policy Engine Evaluation
    return this.policyEngine.evaluateAction(ctx);
  }

  // Prompt scanning
  public scanPrompt(text: string, source: string = "user_input"): PromptScanResult {
    return PromptGuard.scan(text, source);
  }

  // Secret scanning & redacting
  public scanSecrets(text: string, resource: string = "stream"): SecretScanResult {
    return SecretGuard.scanAndRedact(text, resource);
  }

  // Full scan of directory (skills, configs, secrets)
  public scanWorkspace(): SecurityScoreReport {
    const findings: SecurityFinding[] = [];

    // Scan skills and scripts
    const skillRes = SkillScanner.scanDirectory(this.workspaceRoot);
    findings.push(...skillRes.findings);

    // Scan MCP configs
    const mcpConfigPath = `${this.workspaceRoot}/.mcp.json`;
    findings.push(...McpGuard.auditConfigFile(mcpConfigPath));

    // Audit package.json lifecycle hooks
    const pkgPath = `${this.workspaceRoot}/package.json`;
    findings.push(...DownloadGuard.auditPackageJson(pkgPath));

    return RiskEngine.calculateReport(findings);
  }
}
