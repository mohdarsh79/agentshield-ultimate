import { PolicyProfile, PolicyRule, AgentActionContext, SecurityEvaluationResult, SecurityFinding, Severity } from "../types";
import { EventBus } from "./event-bus";
import { AuditLogger } from "./audit-logger";

export class PolicyEngine {
  private rules: PolicyRule[] = [];
  private profile: PolicyProfile;
  public eventBus: EventBus;
  public auditLogger: AuditLogger;

  constructor(profile: PolicyProfile = "strict", auditLogger?: AuditLogger) {
    this.profile = profile;
    this.eventBus = EventBus.getInstance();
    this.auditLogger = auditLogger || new AuditLogger();
    this.registerDefaultRules();
  }

  public setProfile(profile: PolicyProfile): void {
    this.profile = profile;
  }

  public getProfile(): PolicyProfile {
    return this.profile;
  }

  public addRule(rule: PolicyRule): void {
    this.rules.push(rule);
  }

  private registerDefaultRules(): void {
    // 1. Critical Financial / Transfer Rule
    this.addRule({
      id: "POL-FIN-001",
      name: "Financial Transfer Protection",
      category: "COMMAND",
      severity: "CRITICAL",
      description: "Any financial transaction, wallet transfer, or purchase requires human approval.",
      enforceAction: "require_approval",
      evaluate: (ctx) => {
        const targetStr = (ctx.target + " " + JSON.stringify(ctx.parameters)).toLowerCase();
        const triggers = ["stripe", "paypal", "buy", "purchase", "wire", "transfer_funds", "crypto_send", "stripe_charge"];
        const matched = triggers.some(t => targetStr.includes(t));
        return { matched, details: matched ? "Financial keyword detected in action target/parameters" : undefined };
      }
    });

    // 2. Sensitive File Access Protection
    this.addRule({
      id: "POL-FS-001",
      name: "Sensitive Credential File Isolation",
      category: "FILESYSTEM",
      severity: "CRITICAL",
      description: "Reading or writing to credential stores (.ssh, .env, id_rsa, aws credentials) is prohibited.",
      enforceAction: "block",
      evaluate: (ctx) => {
        if (!ctx.actionType.startsWith("file_")) return { matched: false };
        const norm = ctx.target.toLowerCase().replace(/\\/g, "/");
        const sensitive = [".ssh/", "id_rsa", ".aws/credentials", ".env", "id_ed25519", "shadow", "passwd"];
        const matched = sensitive.some(s => norm.includes(s));
        return { matched, details: matched ? `Blocked access to sensitive filesystem target: ${ctx.target}` : undefined };
      }
    });

    // 3. Destructive File Deletion Approval Rule (AS-05 / AS-17)
    this.addRule({
      id: "POL-FS-DEL-001",
      name: "File Deletion Safeguard",
      category: "FILESYSTEM",
      severity: "HIGH",
      description: "Deleting files requires explicit human authorization.",
      enforceAction: "require_approval",
      evaluate: (ctx) => {
        if (ctx.actionType === "file_delete" || (ctx.actionType.startsWith("file_") && ctx.target.includes("delete"))) {
          return { matched: true, details: `File deletion requested on target: ${ctx.target}` };
        }
        return { matched: false };
      }
    });

    // 4. Software Installation & Package Manager Approval Rule (AS-05 / AS-17)
    this.addRule({
      id: "POL-CMD-INSTALL-001",
      name: "Package Installation Safeguard",
      category: "COMMAND",
      severity: "HIGH",
      description: "Installing packages or running software installers requires human authorization.",
      enforceAction: "require_approval",
      evaluate: (ctx) => {
        if (ctx.actionType === "command_execute") {
          const cmd = String(ctx.parameters?.command || ctx.target).toLowerCase();
          const isInstall = /\b(npm\s+(i|install|add)|pip\s+install|apt(-get)?\s+install|brew\s+install|yarn\s+add)\b/.test(cmd);
          if (isInstall) {
            return { matched: true, details: `Software package installation detected: ${cmd}` };
          }
        }
        return { matched: false };
      }
    });

    // 5. Ad and Sponsored Link Click Protection
    this.addRule({
      id: "POL-BRW-001",
      name: "Advertisement and Sponsored Result Prevention",
      category: "BROWSER",
      severity: "HIGH",
      description: "Autonomous browser interactions with advertising or sponsored elements are strictly forbidden.",
      enforceAction: "block",
      evaluate: (ctx) => {
        if (ctx.actionType !== "browser_click") return { matched: false };
        const target = (ctx.target + " " + JSON.stringify(ctx.parameters)).toLowerCase();
        const adMarkers = ["ad-container", "sponsored", "commercial_unit", "googleads", "doubleclick", "promo-card", "ads-ad"];
        const matched = adMarkers.some(m => target.includes(m));
        return { matched, details: matched ? "Attempted browser click on advertising or sponsored element" : undefined };
      }
    });
  }

  public evaluateAction(ctx: AgentActionContext): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    let allowed = true;
    let blockedReason: string | undefined;
    let requiresApproval = false;
    let scorePenalty = 0;

    for (const rule of this.rules) {
      try {
        const evalResult = rule.evaluate(ctx);
        if (evalResult.matched) {
          const finding: SecurityFinding = {
            id: `FIND-${rule.id}-${Date.now().toString(36)}`,
            severity: rule.severity,
            confidence: "HIGH",
            category: rule.category,
            title: rule.name,
            evidence: evalResult.details || rule.description,
            affectedResource: ctx.target,
            impact: `Unauthorized operation violating policy ${rule.id}`,
            mitigation: "Adhere to least-privilege boundary or request operator approval.",
            standardReference: "OWASP-LLM06 / MITRE-AML.T0043",
            remediationStatus: "OPEN",
            timestamp: new Date().toISOString()
          };

          findings.push(finding);
          this.eventBus.emitSecurityFinding(finding);

          if (rule.enforceAction === "block") {
            allowed = false;
            blockedReason = evalResult.details || `Blocked by rule ${rule.name}`;
            scorePenalty += this.getSeverityPenalty(rule.severity);
            break; // Immediate fail-closed
          } else if (rule.enforceAction === "require_approval") {
            // Under dev profile, still enforce approval for financial actions or warn explicitly
            if (this.profile === "strict" || this.profile === "balanced" || rule.id === "POL-FIN-001") {
              requiresApproval = true;
              allowed = false;
              blockedReason = evalResult.details || "Requires human-in-the-loop cryptographic approval";
            }
          }
        }
      } catch (err: unknown) {
        // Fail-closed invariant on evaluator exception
        const msg = err instanceof Error ? err.message : String(err);
        return {
          allowed: false,
          blockedReason: `Policy evaluation error (fail-closed triggered): ${msg}`,
          findings,
          scorePenalty: 50
        };
      }
    }

    const result: SecurityEvaluationResult = {
      allowed,
      blockedReason,
      requiresApproval,
      findings,
      scorePenalty
    };

    return result;
  }

  private getSeverityPenalty(severity: Severity): number {
    switch (severity) {
      case "CRITICAL": return 25;
      case "HIGH": return 15;
      case "MEDIUM": return 10;
      case "LOW": return 5;
      default: return 0;
    }
  }
}
