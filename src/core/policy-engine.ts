import { 
  PolicyProfile, 
  PolicyRule, 
  AgentActionContext, 
  SecurityEvaluationResult, 
  SecurityFinding,
  Severity 
} from "../types";
import { SecurityEventBus } from "./event-bus";
import { AuditLogger } from "./audit-logger";

export class PolicyEngine {
  private profile: PolicyProfile;
  private rules: PolicyRule[] = [];
  private eventBus: SecurityEventBus;
  private auditLogger: AuditLogger;

  constructor(profile: PolicyProfile = "strict", customLogger?: AuditLogger) {
    this.profile = profile;
    this.eventBus = SecurityEventBus.getInstance();
    this.auditLogger = customLogger || new AuditLogger();
    this.registerDefaultRules();
  }

  public setProfile(profile: PolicyProfile): void {
    this.profile = profile;
    this.eventBus.emit("policy:reloaded", { profile });
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
        const triggers = ["stripe", "paypal", "buy", "purchase", "wire", "transfer_funds", "crypto_send"];
        const matched = triggers.some(t => targetStr.includes(t));
        return { matched, details: matched ? "Financial keyword detected in action target/parameters" : undefined };
      }
    });

    // 2. Secret File Access Protection
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

    // 3. Ad and Sponsored Link Click Protection
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
            if (this.profile === "strict" || this.profile === "balanced") {
              requiresApproval = true;
              allowed = false;
              blockedReason = "Requires human-in-the-loop cryptographic approval";
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

    this.auditLogger.logAction(ctx, result);
    this.eventBus.emitActionEvaluation(ctx, result);

    return result;
  }

  private getSeverityPenalty(sev: Severity): number {
    switch (sev) {
      case "CRITICAL": return 25;
      case "HIGH": return 15;
      case "MEDIUM": return 5;
      case "LOW": return 1;
      default: return 0;
    }
  }
}
