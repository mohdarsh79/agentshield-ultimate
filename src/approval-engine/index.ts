import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { AgentActionContext } from "../types";

export interface ApprovalRequest {
  id: string;
  token: string;
  actor: string;
  actionType: string;
  target: string;
  parametersHash: string;
  createdAt: number;
  expiresAt: number;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CONSUMED";
  reason: string;
  resolvedBy?: string;
  resolvedAt?: number;
}

export class ApprovalEngine {
  private requests: Map<string, ApprovalRequest> = new Map();
  private defaultTtlMs: number;
  private maxRequests: number;
  private persistenceFilePath?: string;

  constructor(defaultTtlSeconds: number = 300, maxRequests: number = 1000, storageDir?: string) {
    this.defaultTtlMs = defaultTtlSeconds * 1000;
    this.maxRequests = maxRequests;
    if (storageDir) {
      this.persistenceFilePath = path.join(storageDir, "approvals.json");
      this.loadFromDisk();
    }
  }

  public createRequest(ctx: AgentActionContext, reason: string): ApprovalRequest {
    this.cleanupExpired();

    // Bounded storage protection: evict oldest if at capacity
    if (this.requests.size >= this.maxRequests) {
      const oldestKey = this.requests.keys().next().value;
      if (oldestKey) this.requests.delete(oldestKey);
    }

    const id = crypto.randomUUID();
    const token = crypto.randomBytes(32).toString("hex");
    const parametersHash = this.computeParamsHash(ctx);
    const now = Date.now();

    const request: ApprovalRequest = {
      id,
      token,
      actor: ctx.actor,
      actionType: ctx.actionType,
      target: ctx.target,
      parametersHash,
      createdAt: now,
      expiresAt: now + this.defaultTtlMs,
      status: "PENDING",
      reason
    };

    this.requests.set(token, request);
    this.saveToDisk();
    return request;
  }

  public resolveRequest(token: string, approved: boolean, approver: string = "human-operator"): boolean {
    const req = this.requests.get(token);
    if (!req) return false;

    if (Date.now() > req.expiresAt) {
      req.status = "EXPIRED";
      this.saveToDisk();
      return false;
    }

    req.status = approved ? "APPROVED" : "REJECTED";
    req.resolvedBy = approver;
    req.resolvedAt = Date.now();
    this.saveToDisk();
    return true;
  }

  // One-time verification and atomic consumption (prevents replay attacks)
  public verifyApproval(token: string, ctx: AgentActionContext): { valid: boolean; reason?: string } {
    const req = this.requests.get(token);
    if (!req) {
      return { valid: false, reason: "Approval token not found or invalid" };
    }

    if (req.status === "CONSUMED") {
      return { valid: false, reason: "Approval token has already been consumed (replay attempt blocked)" };
    }

    if (Date.now() > req.expiresAt) {
      req.status = "EXPIRED";
      this.saveToDisk();
      return { valid: false, reason: "Approval token has expired (TTL exceeded)" };
    }

    if (req.status !== "APPROVED") {
      return { valid: false, reason: `Approval status is ${req.status}` };
    }

    // Cryptographic Parameter Binding Check with Canonical Sorting
    const currentHash = this.computeParamsHash(ctx);
    if (currentHash !== req.parametersHash) {
      return { 
        valid: false, 
        reason: "Cryptographic parameter mismatch: Action parameters modified after approval" 
      };
    }

    // Mark as CONSUMED atomically to enforce single-use execution
    req.status = "CONSUMED";
    this.saveToDisk();

    return { valid: true };
  }

  public getPendingRequests(): ApprovalRequest[] {
    this.cleanupExpired();
    return Array.from(this.requests.values()).filter(r => r.status === "PENDING");
  }

  public getRequest(tokenOrId: string): ApprovalRequest | undefined {
    for (const req of this.requests.values()) {
      if (req.token === tokenOrId || req.id === tokenOrId) {
        return req;
      }
    }
    return undefined;
  }

  public cleanupExpired(): number {
    const now = Date.now();
    let expiredCount = 0;
    for (const [token, req] of this.requests.entries()) {
      if (now > req.expiresAt && req.status === "PENDING") {
        req.status = "EXPIRED";
        expiredCount++;
      }
    }
    if (expiredCount > 0) this.saveToDisk();
    return expiredCount;
  }

  private computeParamsHash(ctx: AgentActionContext): string {
    const canonicalParams = JSON.stringify(ctx.parameters || {}, Object.keys(ctx.parameters || {}).sort());
    return crypto.createHash("sha256").update(`${ctx.actionType}|${ctx.target}|${canonicalParams}`).digest("hex");
  }

  private saveToDisk(): void {
    if (!this.persistenceFilePath) return;
    try {
      const dir = path.dirname(this.persistenceFilePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const obj = Array.from(this.requests.values());
      fs.writeFileSync(this.persistenceFilePath, JSON.stringify(obj, null, 2), "utf-8");
    } catch {
      // Best-effort persistence
    }
  }

  private loadFromDisk(): void {
    if (!this.persistenceFilePath || !fs.existsSync(this.persistenceFilePath)) return;
    try {
      const content = fs.readFileSync(this.persistenceFilePath, "utf-8");
      const list: ApprovalRequest[] = JSON.parse(content);
      for (const item of list) {
        this.requests.set(item.token, item);
      }
    } catch {
      // Ignore load errors on corrupted files
    }
  }
}
