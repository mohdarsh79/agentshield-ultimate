import * as crypto from "crypto";
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
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
  reason: string;
  resolvedBy?: string;
  resolvedAt?: number;
}

export class ApprovalEngine {
  private requests: Map<string, ApprovalRequest> = new Map();
  private defaultTtlMs: number;
  private maxRequests: number;

  constructor(defaultTtlSeconds: number = 300, maxRequests: number = 1000) {
    this.defaultTtlMs = defaultTtlSeconds * 1000;
    this.maxRequests = maxRequests;
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
    return request;
  }

  public resolveRequest(token: string, approved: boolean, approver: string = "human-operator"): boolean {
    const req = this.requests.get(token);
    if (!req) return false;

    if (Date.now() > req.expiresAt) {
      req.status = "EXPIRED";
      return false;
    }

    req.status = approved ? "APPROVED" : "REJECTED";
    req.resolvedBy = approver;
    req.resolvedAt = Date.now();
    return true;
  }

  public verifyApproval(token: string, ctx: AgentActionContext): { valid: boolean; reason?: string } {
    const req = this.requests.get(token);
    if (!req) {
      return { valid: false, reason: "Approval token not found or invalid" };
    }

    if (Date.now() > req.expiresAt) {
      req.status = "EXPIRED";
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

    // Single-use token invalidation to prevent replay attacks
    this.requests.delete(token);

    return { valid: true };
  }

  public getPendingRequests(): ApprovalRequest[] {
    this.cleanupExpired();
    return Array.from(this.requests.values()).filter(r => r.status === "PENDING");
  }

  public getRequest(tokenOrId: string): ApprovalRequest | undefined {
    const req = this.requests.get(tokenOrId);
    if (req) return req;
    for (const r of this.requests.values()) {
      if (r.id === tokenOrId) return r;
    }
    return undefined;
  }

  public cleanupExpired(): number {
    const now = Date.now();
    let cleaned = 0;
    for (const [token, req] of this.requests.entries()) {
      if (now > req.expiresAt) {
        this.requests.delete(token);
        cleaned++;
      }
    }
    return cleaned;
  }

  public exportState(): ApprovalRequest[] {
    this.cleanupExpired();
    return Array.from(this.requests.values());
  }

  public importState(requests: ApprovalRequest[]): void {
    const now = Date.now();
    for (const req of requests) {
      if (req.expiresAt > now) {
        this.requests.set(req.token, req);
      }
    }
  }

  // Recursive Canonical Object Normalizer for deterministic JSON hashing
  private canonicalize(obj: unknown): unknown {
    if (obj === null || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(item => this.canonicalize(item));
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
      sorted[key] = this.canonicalize((obj as Record<string, unknown>)[key]);
    }
    return sorted;
  }

  private computeParamsHash(ctx: AgentActionContext): string {
    const canonicalParams = this.canonicalize(ctx.parameters || {});
    const payload = `${ctx.actor}|${ctx.actionType}|${ctx.target}|${JSON.stringify(canonicalParams)}`;
    return crypto.createHash("sha256").update(payload).digest("hex");
  }
}
