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

export interface HashChainVerificationResult {
  isValid: boolean;
  totalRecords: number;
  corruptRecordIndex?: number;
  corruptRecordId?: string;
  reason?: string;
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

  // Cryptographic Record Hashing binding ALL security-relevant fields (AS-15)
  public computeRecordHash(
    id: string,
    timestamp: string,
    actor: string,
    actionType: string,
    target: string,
    allowed: boolean,
    blockedReason: string | undefined,
    findingsCount: number,
    prevHash: string
  ): string {
    const rawData = `${id}|${timestamp}|${actor}|${actionType}|${target}|${allowed}|${blockedReason || ""}|${findingsCount}|${prevHash}`;
    return crypto.createHash("sha256").update(rawData).digest("hex");
  }

  public logAction(ctx: AgentActionContext, result: SecurityEvaluationResult): AuditRecord {
    const recordId = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const findingsCount = result.findings ? result.findings.length : 0;
    const blockedReason = result.blockedReason;

    const hash = this.computeRecordHash(
      recordId,
      timestamp,
      ctx.actor,
      ctx.actionType,
      ctx.target,
      result.allowed,
      blockedReason,
      findingsCount,
      this.lastHash
    );

    const record: AuditRecord = {
      id: recordId,
      timestamp,
      actor: ctx.actor,
      actionType: ctx.actionType,
      target: ctx.target,
      allowed: result.allowed,
      blockedReason,
      findingsCount,
      prevHash: this.lastHash,
      hash
    };

    this.lastHash = hash;

    // Log rotation check: rotate if > 10MB (AS-22)
    try {
      if (fs.existsSync(this.logPath)) {
        const stat = fs.statSync(this.logPath);
        if (stat.size > 10 * 1024 * 1024) {
          const rotated = `${this.logPath}.${Date.now()}.bak`;
          fs.renameSync(this.logPath, rotated);
          this.lastHash = "0000000000000000000000000000000000000000000000000000000000000000";
          record.prevHash = this.lastHash;
          record.hash = this.computeRecordHash(
            recordId, timestamp, ctx.actor, ctx.actionType, ctx.target, result.allowed, blockedReason, findingsCount, this.lastHash
          );
          this.lastHash = record.hash;
        }
      }
    } catch {
      // Rotation best-effort
    }

    fs.appendFileSync(this.logPath, JSON.stringify(record) + "\n", { encoding: "utf-8" });
    return record;
  }

  public getRecords(): AuditRecord[] {
    if (!fs.existsSync(this.logPath)) return [];
    const content = fs.readFileSync(this.logPath, "utf-8").trim();
    if (!content) return [];
    return content.split("\n").filter(Boolean).map(line => JSON.parse(line));
  }

  // Full cryptographic hash-chain tamper detection (AS-15)
  public verifyLogIntegrity(): HashChainVerificationResult {
    const records = this.getRecords();
    if (records.length === 0) {
      return { isValid: true, totalRecords: 0 };
    }

    let expectedPrevHash = "0000000000000000000000000000000000000000000000000000000000000000";

    for (let i = 0; i < records.length; i++) {
      const rec = records[i];

      // 1. Verify prevHash link
      if (rec.prevHash !== expectedPrevHash) {
        return {
          isValid: false,
          totalRecords: records.length,
          corruptRecordIndex: i,
          corruptRecordId: rec.id,
          reason: `Broken hash chain at index ${i}: prevHash mismatch. Expected ${expectedPrevHash}, found ${rec.prevHash}`
        };
      }

      // 2. Recompute and verify record SHA-256 hash
      const recomputed = this.computeRecordHash(
        rec.id,
        rec.timestamp,
        rec.actor,
        rec.actionType,
        rec.target,
        rec.allowed,
        rec.blockedReason,
        rec.findingsCount,
        rec.prevHash
      );

      if (recomputed !== rec.hash) {
        return {
          isValid: false,
          totalRecords: records.length,
          corruptRecordIndex: i,
          corruptRecordId: rec.id,
          reason: `Cryptographic digest mismatch at index ${i}. Record content was tampered with.`
        };
      }

      expectedPrevHash = rec.hash;
    }

    return { isValid: true, totalRecords: records.length };
  }
}
