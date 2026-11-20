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
import { WorkspaceScanner } from "../workspace-scanner";
import { SecurityReporter } from "../reporting";

export interface AgentShieldConfig {
  profile?: PolicyProfile;
  workspaceRoot?: string;
  auditLogPath?: string;
  defaultApprovalTtlSeconds?: number;
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
    this.approvalEngine = new ApprovalEngine(config.defaultApprovalTtlSeconds || 300);
    this.remediationEngine = new RemediationEngine(this.workspaceRoot);
  }

  // Central Action Interception Gate with Human Approval Workflow
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

    // 5. Central Policy Engine Evaluation
    const policyRes = this.policyEngine.evaluateAction(ctx);

    // 6. Integrated Cryptographic Human Approval Gate (F-002 Resolution)
    if (policyRes.requiresApproval) {
      if (ctx.approvalToken) {
        // Verify provided approval token against exact action parameters
        const verifyRes = this.approvalEngine.verifyApproval(ctx.approvalToken, ctx);
        if (verifyRes.valid) {
          this.auditLogger.logAction(ctx, {
            allowed: true,
            findings: policyRes.findings,
            scorePenalty: 0
          });
          return {
            allowed: true,
            requiresApproval: false,
            findings: policyRes.findings,
            scorePenalty: 0
          };
        } else {
          return {
            allowed: false,
            requiresApproval: true,
            blockedReason: `Human approval verification failed: ${verifyRes.reason}`,
            findings: policyRes.findings,
            scorePenalty: 20
          };
        }
      } else {
        // Generate new cryptographic approval challenge
        const approvalReq = this.approvalEngine.createRequest(
          ctx, 
          policyRes.blockedReason || "Action requires explicit human authorization"
        );
        return {
          allowed: false,
          requiresApproval: true,
          approvalToken: approvalReq.token,
          approvalRequest: approvalReq,
          blockedReason: `Action halted: Requires human approval. Approval Request ID: ${approvalReq.id}`,
          findings: policyRes.findings,
          scorePenalty: 15
        };
      }
    }

    return policyRes;
  }

  // Asynchronous Interception Gate with Live DNS Resolution (F-003 Resolution)
  public async interceptActionAsync(ctx: AgentActionContext): Promise<SecurityEvaluationResult> {
    if (ctx.actionType === "network_request") {
      const netRes = await NetworkGuard.evaluateRequestAsync(ctx);
      if (!netRes.allowed) return netRes;
    }
    return this.interceptAction(ctx);
  }

  // Prompt scanning
  public scanPrompt(text: string, source: string = "user_input"): PromptScanResult {
    return PromptGuard.scan(text, source);
  }

  // Secret scanning & redacting
  public scanSecrets(text: string, resource: string = "stream"): SecretScanResult {
    return SecretGuard.scanAndRedact(text, resource);
  }

  // Comprehensive Multi-Vector Workspace Scan (F-004 Resolution)
  public scanWorkspace(): SecurityScoreReport {
    return WorkspaceScanner.scan(this.workspaceRoot);
  }
}
