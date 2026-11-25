import { EventEmitter } from "events";
import { SecurityFinding, AgentActionContext, SecurityEvaluationResult } from "../types";

export type SecurityEventType = 
  | "finding:detected"
  | "action:blocked"
  | "action:allowed"
  | "approval:requested"
  | "approval:resolved"
  | "policy:reloaded";

export class SecurityEventBus extends EventEmitter {
  private static instance: SecurityEventBus;

  public static getInstance(): SecurityEventBus {
    if (!SecurityEventBus.instance) {
      SecurityEventBus.instance = new SecurityEventBus();
    }
    return SecurityEventBus.instance;
  }

  public emitSecurityFinding(finding: SecurityFinding): void {
    this.emit("finding:detected", finding);
  }

  public emitActionEvaluation(ctx: AgentActionContext, result: SecurityEvaluationResult): void {
    if (!result.allowed) {
      this.emit("action:blocked", { ctx, result });
    } else {
      this.emit("action:allowed", { ctx, result });
    }
  }
}

export { SecurityEventBus as EventBus };
