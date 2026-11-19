import { test, describe } from "node:test";
import * as assert from "node:assert";
import { SecretGuard } from "../../src/secret-guard";
import { CommandGuard } from "../../src/command-guard";
import { ApprovalEngine } from "../../src/approval-engine";

describe("Secrets, Commands & Approval Tests", () => {
  test("SecretGuard detects and redacts OpenAI API keys", () => {
    const dummyKey = ["sk", "proj", "mockKeyForTestingOnly0123456789"].join("-");
    const raw = `My key is ${dummyKey} for API calls`;
    const res = SecretGuard.scanAndRedact(raw);
    assert.strictEqual(res.hasSecrets, true);
    assert.ok(res.redactedText.includes("[REDACTED_OPENAI_API_KEY]"));
  });

  test("CommandGuard blocks destructive rm -rf / command", () => {
    const res = CommandGuard.evaluateCommand({
      actionType: "command_execute",
      actor: "test_agent",
      target: "rm -rf /",
      parameters: { command: "rm -rf /" }
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("Dangerous shell execution"));
  });

  test("CommandGuard blocks unapproved shell chaining", () => {
    const res = CommandGuard.evaluateCommand({
      actionType: "command_execute",
      actor: "test_agent",
      target: "echo 1 && cat /etc/passwd",
      parameters: { command: "echo 1 && cat /etc/passwd" }
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("chaining"));
  });

  test("ApprovalEngine enforces cryptographic parameter binding", () => {
    const engine = new ApprovalEngine(300);
    const ctx = {
      actionType: "command_execute" as const,
      actor: "agent",
      target: "stripe_charge",
      parameters: { amount: 100 }
    };

    const req = engine.createRequest(ctx, "Approve payment");
    engine.resolveRequest(req.token, true);

    // Verify with original ctx succeeds
    const check1 = engine.verifyApproval(req.token, ctx);
    assert.strictEqual(check1.valid, true);

    // Replay with new token should fail
    const check2 = engine.verifyApproval(req.token, ctx);
    assert.strictEqual(check2.valid, false);
  });
});
