import * as fs from "fs";
import * as path from "path";
import { PolicyEngine } from "../core/policy-engine";
import { AuditLogger } from "../core/audit-logger";
import { EventBus } from "../core/event-bus";
import { FilesystemGuard } from "../filesystem-guard";
import { BrowserGuard } from "../browser-guard";
import { CommandGuard } from "../command-guard";
import { NetworkGuard } from "../network-guard";
import { McpGuard } from "../mcp-guard";
import { DownloadGuard } from "../download-guard";
import { PromptGuard, PromptScanResult } from "../prompt-guard";
import { SecretGuard, SecretScanResult } from "../secret-guard";
import { ApprovalEngine } from "../approval-engine";
import { RemediationEngine } from "../remediation";
import { WorkspaceScanner } from "../workspace-scanner";
import {
  AgentShieldConfig,
  AgentActionContext,
  SecurityEvaluationResult,
  SecurityScoreReport
} from "../types";

export class AgentShield {
  public policyEngine: PolicyEngine;
  public auditLogger: AuditLogger;
  public approvalEngine: ApprovalEngine;
  public remediationEngine: RemediationEngine;
  public eventBus: EventBus;
  public workspaceRoot: string;

  constructor(config: AgentShieldConfig = {}) {
    this.workspaceRoot = path.resolve(config.workspaceRoot || process.cwd());
    this.eventBus = EventBus.getInstance();

    // AS-14: Automatically load .agentshield/config.json if present
    const loadedConfig = this.loadWorkspaceConfig();
    const mergedConfig: AgentShieldConfig = { ...loadedConfig, ...config };

    this.auditLogger = new AuditLogger(mergedConfig.auditLogPath);
    this.policyEngine = new PolicyEngine(mergedConfig.profile || "strict", this.auditLogger);
    this.approvalEngine = new ApprovalEngine(
      mergedConfig.defaultApprovalTtlSeconds || 300,
      1000,
      path.join(this.workspaceRoot, ".agentshield")
    );
    this.remediationEngine = new RemediationEngine(this.workspaceRoot);
  }

  private loadWorkspaceConfig(): Partial<AgentShieldConfig> {
    try {
      const configPath = path.join(this.workspaceRoot, ".agentshield", "config.json");
      if (fs.existsSync(configPath)) {
        return JSON.parse(fs.readFileSync(configPath, "utf-8"));
      }
    } catch {
      // Return empty if unparseable
    }
    return {};
  }

  public scanPrompt(prompt: string, contextName: string = "runtime_prompt"): PromptScanResult {
    return PromptGuard.scan(prompt, contextName);
  }

  public scanSecret(text: string, resourceName: string = "runtime_stream"): SecretScanResult {
    return SecretGuard.scanAndRedact(text, resourceName);
  }

  // Central Action Interception Gate with Complete Audit & Human Approval Lifecycle
  public interceptAction(ctx: AgentActionContext): SecurityEvaluationResult {
    // 1. Filesystem Guard check if file action
    if (ctx.actionType.startsWith("file_")) {
      const fsRes = FilesystemGuard.evaluateFileAccess(ctx, this.workspaceRoot);
      if (!fsRes.allowed) return this.finalizeDenial(ctx, fsRes);
    }

    // 2. Browser Guard check if browser action
    if (ctx.actionType.startsWith("browser_")) {
      const brwRes = BrowserGuard.evaluateBrowserAction(ctx);
      if (!brwRes.allowed) return this.finalizeDenial(ctx, brwRes);
    }

    // 3. Command Guard check if command execution
    if (ctx.actionType === "command_execute") {
      const cmdRes = CommandGuard.evaluateCommand(ctx);
      if (!cmdRes.allowed) return this.finalizeDenial(ctx, cmdRes);
    }

    // 4. Network Guard check if network request
    if (ctx.actionType === "network_request") {
      const netRes = NetworkGuard.evaluateRequest(ctx, { allowLocalhost: this.policyEngine.getProfile() === "dev" });
      if (!netRes.allowed) return this.finalizeDenial(ctx, netRes);
    }

    // 5. MCP Tool Call Guard check (AS-06)
    if (ctx.actionType === "mcp_tool_call") {
      const mcpRes = McpGuard.evaluateToolCall(ctx);
      if (!mcpRes.allowed) return this.finalizeDenial(ctx, mcpRes);
    }

    // 6. Download Guard check (AS-06)
    if (ctx.actionType === "download") {
      const dlRes = DownloadGuard.evaluateDownload(ctx);
      if (!dlRes.allowed) return this.finalizeDenial(ctx, dlRes);
    }

    // 7. Central Policy Engine Evaluation
    const policyRes = this.policyEngine.evaluateAction(ctx);

    // 8. Integrated Cryptographic Human Approval Gate (AS-05)
    if (policyRes.requiresApproval) {
      if (ctx.approvalToken) {
        // Verify provided approval token and enforce single-use consumption
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
          const failRes: SecurityEvaluationResult = {
            allowed: false,
            requiresApproval: true,
            blockedReason: `Human approval verification failed: ${verifyRes.reason}`,
            findings: policyRes.findings,
            scorePenalty: 20
          };
          return this.finalizeDenial(ctx, failRes);
        }
      } else {
        // Generate new cryptographic approval challenge
        const approvalReq = this.approvalEngine.createRequest(
          ctx, 
          policyRes.blockedReason || "Action requires explicit human authorization"
        );
        const approvalPendingRes: SecurityEvaluationResult = {
          allowed: false,
          requiresApproval: true,
          approvalToken: approvalReq.token,
          approvalRequest: approvalReq,
          blockedReason: `Action halted: Requires human approval. Approval Request ID: ${approvalReq.id}`,
          findings: policyRes.findings,
          scorePenalty: 15
        };
        return this.finalizeDenial(ctx, approvalPendingRes);
      }
    }

    if (!policyRes.allowed) {
      return this.finalizeDenial(ctx, policyRes);
    }

    // Action successfully cleared
    this.auditLogger.logAction(ctx, policyRes);
    return policyRes;
  }

  // Asynchronous Interception with Live DNS Resolution & Pinning
  public async interceptActionAsync(ctx: AgentActionContext): Promise<SecurityEvaluationResult> {
    if (ctx.actionType === "network_request") {
      const netRes = await NetworkGuard.evaluateRequestAsync(ctx, { allowLocalhost: this.policyEngine.getProfile() === "dev" });
      if (!netRes.allowed) return this.finalizeDenial(ctx, netRes);
    }
    return this.interceptAction(ctx);
  }

  // AS-07: Unify all guard denials through audit logging and event emission
  private finalizeDenial(ctx: AgentActionContext, res: SecurityEvaluationResult): SecurityEvaluationResult {
    this.auditLogger.logAction(ctx, res);

    // Emit finding event for each finding attached
    if (res.findings && res.findings.length > 0) {
      for (const finding of res.findings) {
        this.eventBus.emitSecurityFinding(finding);
      }
    } else {
      // Emit fallback finding event for audit visibility
      this.eventBus.emitSecurityFinding({
        id: `FIND-DENY-${Date.now().toString(36)}`,
        severity: "HIGH",
        confidence: "CERTAIN",
        category: "COMMAND",
        title: res.blockedReason || "Action denied by security boundary",
        evidence: `Action ${ctx.actionType} denied on target '${ctx.target}'`,
        affectedResource: ctx.target,
        impact: "Execution halted by security guard policy.",
        mitigation: "Check security policies or obtain required approval.",
        standardReference: "Zero-Trust Enforcement",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      });
    }

    return res;
  }

  public scanWorkspace(): SecurityScoreReport {
    return WorkspaceScanner.scan(this.workspaceRoot);
  }
}
