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
}

export class ApprovalEngine {
  private requests: Map<string, ApprovalRequest> = new Map();
  private defaultTtlMs: number;

  constructor(defaultTtlSeconds: number = 300) {
    this.defaultTtlMs = defaultTtlSeconds * 1000;
  }

  public createRequest(ctx: AgentActionContext, reason: string): ApprovalRequest {
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

  public resolveRequest(token: string, approved: boolean): boolean {
    const req = this.requests.get(token);
    if (!req) return false;

    if (Date.now() > req.expiresAt) {
      req.status = "EXPIRED";
      return false;
    }

    req.status = approved ? "APPROVED" : "REJECTED";
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
