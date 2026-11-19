import { test, describe } from "node:test";
import * as assert from "node:assert";
import * as http from "http";
import { NetworkGuard } from "../../src/network-guard";
import { CommandGuard } from "../../src/command-guard";
import { ApprovalEngine } from "../../src/approval-engine";
import { BrowserGuard } from "../../src/browser-guard";
import { FilesystemGuard } from "../../src/filesystem-guard";
import { DashboardServer } from "../../src/dashboard";
import { SecurityScoreReport } from "../../src/types";

describe("Security Audit Regression Verification Suite", () => {
  test("REG-01: NetworkGuard blocks IPv6-mapped metadata IP ([::ffff:a9fe:a9fe])", () => {
    const res = NetworkGuard.evaluateRequest({
      actionType: "network_request",
      actor: "adversary",
      target: "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("metadata"));
  });

  test("REG-02: NetworkGuard blocks wildcard DNS pointing to metadata (169.254.169.254.nip.io)", () => {
    const res = NetworkGuard.evaluateRequest({
      actionType: "network_request",
      actor: "adversary",
      target: "http://169.254.169.254.nip.io/secret",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("metadata"));
  });

  test("REG-03: CommandGuard blocks single ampersand backgrounding operator", () => {
    const res = CommandGuard.evaluateCommand({
      actionType: "command_execute",
      actor: "adversary",
      target: "echo legitimate & evil_payload",
      parameters: { command: "echo legitimate & evil_payload" }
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("chaining"));
  });

  test("REG-04: CommandGuard blocks newline injection in command line", () => {
    const res = CommandGuard.evaluateCommand({
      actionType: "command_execute",
      actor: "adversary",
      target: "echo 1\nwhoami",
      parameters: { command: "echo 1\nwhoami" }
    });
    assert.strictEqual(res.allowed, false);
  });

  test("REG-05: BrowserGuard intercepts malicious open redirect destination", () => {
    const check = BrowserGuard.validateUrl("https://example.com/redirect?dest=https://xn--appl-45d.com/login");
    assert.strictEqual(check.allowed, false);
    assert.ok(check.reason?.includes("Open redirect target violates security policy"));
  });

  test("REG-06: ApprovalEngine handles key reordering with canonical JSON digest", () => {
    const engine = new ApprovalEngine(300);
    const ctx1 = {
      actionType: "command_execute" as const,
      actor: "agent",
      target: "transfer",
      parameters: { amount: 100, recipient: "alice" }
    };
    const req = engine.createRequest(ctx1, "Approval test");
    engine.resolveRequest(req.token, true);

    // Context with reordered keys
    const ctx2 = {
      actionType: "command_execute" as const,
      actor: "agent",
      target: "transfer",
      parameters: { recipient: "alice", amount: 100 }
    };

    const verify = engine.verifyApproval(req.token, ctx2);
    assert.strictEqual(verify.valid, true, "Canonical sorting should accept identical parameters regardless of key order");
  });

  test("REG-07: FilesystemGuard blocks double-encoded path traversal (%252e%252e)", () => {
    const res = FilesystemGuard.evaluateFileAccess({
      actionType: "file_read",
      actor: "adversary",
      target: "%252e%252e/%252e%252e/etc/passwd",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("Path traversal"));
  });

  test("REG-08: FilesystemGuard blocks Windows reserved device names (NUL, CON)", () => {
    const res = FilesystemGuard.evaluateFileAccess({
      actionType: "file_write",
      actor: "adversary",
      target: "CON.txt",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("reserved device name"));
  });

  test("REG-09: DashboardServer HTML escapes finding titles, evidence, and resources", async () => {
    const mockReport: SecurityScoreReport = {
      score: 50,
      grade: "F",
      totalFindings: 1,
      bySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 },
      byCategory: { CREDENTIAL: 1, PROMPT_INJECTION: 0, BROWSER: 0, FILESYSTEM: 0, NETWORK: 0, COMMAND: 0, MCP: 0, SKILL: 0, DOWNLOAD: 0, SUPPLY_CHAIN: 0, CONFIGURATION: 0 },
      findings: [{
        id: "XSS-TEST",
        severity: "CRITICAL",
        confidence: "CERTAIN",
        category: "CREDENTIAL",
        title: "Test <script>",
        evidence: "<script>alert(1)</script>",
        affectedResource: "<img src=x onerror=alert(1)>",
        impact: "Test",
        mitigation: "Test",
        standardReference: "Test",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      }],
      timestamp: new Date().toISOString()
    };

    const inst = await DashboardServer.start(mockReport, undefined, 4188);

    await new Promise<void>((resolve, reject) => {
      http.get(inst.url, (res) => {
        let body = "";
        res.on("data", chunk => body += chunk);
        res.on("end", async () => {
          assert.strictEqual(res.headers["content-security-policy"]?.includes("default-src 'self'"), true);
          assert.strictEqual(body.includes("<script>alert(1)</script>"), false, "Script tags must be escaped");
          assert.strictEqual(body.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), true, "Must contain HTML entities");
          await inst.stop();
          resolve();
        });
      }).on("error", reject);
    });
  });
});
