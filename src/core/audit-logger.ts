import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { AgentActionContext, SecurityEvaluationResult } from "../types";

export interface AuditRecord {
  id: string;
  timestamp: string;
  actor: string;
  actionType: string;
  target: string;
  allowed: boolean;
  blockedReason?: string;
  findingsCount: number;
  prevHash: string;
  hash: string;
}

export class AuditLogger {
  private logPath: string;
  private lastHash: string = "0000000000000000000000000000000000000000000000000000000000000000";

  constructor(customPath?: string) {
    this.logPath = customPath || path.resolve(process.cwd(), "audit.jsonl");
    this.initLastHash();
  }

  private initLastHash(): void {
    if (fs.existsSync(this.logPath)) {
      try {
        const content = fs.readFileSync(this.logPath, "utf-8").trim();
        const lines = content.split("\n").filter(Boolean);
        if (lines.length > 0) {
          const lastRecord = JSON.parse(lines[lines.length - 1]);
          if (lastRecord.hash) {
            this.lastHash = lastRecord.hash;
          }
        }
      } catch {
        // Fallback to genesis hash if unreadable
      }
    }
  }

  public logAction(ctx: AgentActionContext, result: SecurityEvaluationResult): AuditRecord {
    const recordId = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    const rawData = `${recordId}|${timestamp}|${ctx.actor}|${ctx.actionType}|${ctx.target}|${result.allowed}|${this.lastHash}`;
    const hash = crypto.createHash("sha256").update(rawData).digest("hex");

    const record: AuditRecord = {
      id: recordId,
      timestamp,
      actor: ctx.actor,
      actionType: ctx.actionType,
      target: ctx.target,
      allowed: result.allowed,
      blockedReason: result.blockedReason,
      findingsCount: result.findings.length,
      prevHash: this.lastHash,
      hash
    };

    this.lastHash = hash;
    fs.appendFileSync(this.logPath, JSON.stringify(record) + "\n", { encoding: "utf-8" });
    return record;
  }

  public getRecords(): AuditRecord[] {
    if (!fs.existsSync(this.logPath)) return [];
    const content = fs.readFileSync(this.logPath, "utf-8").trim();
    if (!content) return [];
    return content.split("\n").filter(Boolean).map(line => JSON.parse(line));
  }
}
