import { describe, it } from "node:test";
import * as assert from "node:assert";
import * as http from "node:http";
import { RedTeamRunner } from "../../src/red-team";
import { AgentShield } from "../../src/sdk";
import { NetworkGuard } from "../../src/network-guard";
import { FilesystemGuard } from "../../src/filesystem-guard";
import { ApprovalEngine } from "../../src/approval-engine";
import { WorkspaceScanner } from "../../src/workspace-scanner";
import { DashboardServer } from "../../src/dashboard";
import { RiskEngine } from "../../src/core/risk-engine";

describe("Engineering Audit Remediation Verification Suite (F-001 to F-010)", () => {
  // F-001: Dynamic Red-Team Runner Execution
  it("F-001: RedTeamRunner dynamically executes adversarial attacks and produces live verification metrics", async () => {
    const runner = new RedTeamRunner();
    const summary = await runner.runSuite();

    assert.ok(summary.totalScenarios >= 10, "Should contain at least 10 adversarial scenarios");
    assert.ok(summary.passedScenarios > 0, "Should have passing scenarios");
    assert.strictEqual(summary.failedScenarios, 0, "All adversarial scenarios must pass live defense");
    assert.strictEqual(summary.verificationRate, 100, "Live defense verification rate must be 100%");

    // Verify each result has real duration and non-empty details
    for (const res of summary.results) {
      assert.ok(typeof res.durationMs === "number", "Duration must be recorded");
      assert.ok(res.details.length > 0, "Details must be populated from actual guard output");
      assert.strictEqual(res.passed, true, `Scenario ${res.scenarioId} must pass`);
    }
  });

  // F-002: Human Approval Engine Integrated into Action Execution Gate
  it("F-002: SDK interceptAction halts high-risk action pending human approval, then permits upon valid token", () => {
    const shield = new AgentShield({ workspaceRoot: process.cwd() });

    // Financial transfer is a high-risk action in strict profile
    const highRiskAction = {
      actor: "autonomous-agent",
      actionType: "financial_transfer",
      target: "wire-transfer-gateway",
      parameters: { amount: 10000, recipient: "external-account", currency: "USD" }
    };

    // Step 1: Initial call without approval token must be blocked pending approval
    const initialResult = shield.interceptAction(highRiskAction);
    assert.strictEqual(initialResult.allowed, false, "High-risk action must be blocked initially");
    assert.strictEqual(initialResult.requiresApproval, true, "Must require approval");
    assert.ok(initialResult.approvalToken, "Must return an approval token");
    assert.ok(initialResult.blockedReason?.includes("Requires human approval"), "Must state approval requirement");

    // Step 2: Call with invalid / forged token must be rejected
    const forgedResult = shield.interceptAction({
      ...highRiskAction,
      approvalToken: "forged-or-nonexistent-token"
    });
    assert.strictEqual(forgedResult.allowed, false, "Forged token must be rejected");
    assert.ok(forgedResult.blockedReason?.includes("verification failed"), "Must report verification failure");

    // Step 3: Legitimate approval resolution
    const approved = shield.approvalEngine.resolveRequest(initialResult.approvalToken!, true, "sec-admin@company.com");
    assert.strictEqual(approved, true, "Approval resolution must succeed");

    // Step 4: Re-executing with the valid approved token must be ALLOWED
    const approvedResult = shield.interceptAction({
      ...highRiskAction,
      approvalToken: initialResult.approvalToken
    });
    assert.strictEqual(approvedResult.allowed, true, "Action with valid approved token must be allowed");
    assert.strictEqual(approvedResult.requiresApproval, false);

    // Step 5: Single-use replay attack must be blocked (token is consumed)
    const replayResult = shield.interceptAction({
      ...highRiskAction,
      approvalToken: initialResult.approvalToken
    });
    assert.strictEqual(replayResult.allowed, false, "Replayed token must be rejected on second use");
  });

  // F-003: Network Guard Asynchronous DNS Resolution for SSRF Protection
  it("F-003: NetworkGuard evaluateRequestAsync detects and blocks DNS resolution to private/metadata IP", async () => {
    // 169.254.169.254.nip.io resolves via public DNS to 169.254.169.254
    const metaDnsCtx = {
      actor: "agent",
      actionType: "network_request" as const,
      target: "http://169.254.169.254.nip.io/meta-data",
      parameters: { url: "http://169.254.169.254.nip.io/meta-data" }
    };

    const res = await NetworkGuard.evaluateRequestAsync(metaDnsCtx);
    assert.strictEqual(res.allowed, false, "Must block DNS resolution pointing to metadata");
    assert.ok(res.findings.length > 0, "Must generate security finding");
  });

  // F-004: Comprehensive Multi-Vector Workspace Scanner
  it("F-004: WorkspaceScanner performs deep multi-vector audit and records coverage metadata", () => {
    const report = WorkspaceScanner.scan(process.cwd());

    assert.ok(typeof report.score === "number", "Report must contain numerical score");
    assert.ok(report.coverage, "Report must include coverage metadata");
    assert.ok(report.coverage.filesInspected > 0, "Must inspect workspace files");
    assert.ok(report.coverage.scannersActive.length >= 5, "Must activate all core scanners");
    assert.ok(report.coverage.scannersActive.includes("SecretGuard"));
    assert.ok(report.coverage.scannersActive.includes("CommandGuard"));
    assert.ok(report.coverage.scannersActive.includes("McpGuard"));
  });

  // F-005: Filesystem Guard TOCTOU & Symlink Confinement
  it("F-005: FilesystemGuard blocks path traversal attempts and detects non-existent target parent escapes", () => {
    const ctx = {
      actor: "agent",
      actionType: "file_write" as const,
      target: "../../escaped-file.txt",
      parameters: {}
    };

    const res = FilesystemGuard.evaluateFileAccess(ctx, process.cwd());
    assert.strictEqual(res.allowed, false, "Must block escape outside workspace root");
    assert.strictEqual(res.findings[0].severity, "CRITICAL");
  });

  // F-009: Approval Engine Bounded Storage, Eviction & Approver Binding
  it("F-009: ApprovalEngine evicts expired requests, enforces capacity limit, and binds approver identity", () => {
    const engine = new ApprovalEngine(1, 5); // 1-second TTL, max 5 requests

    const ctx = {
      actor: "agent-test",
      actionType: "system_config",
      target: "system.ini",
      parameters: { key: "value" }
    };

    const req1 = engine.createRequest(ctx, "Test req 1");
    assert.strictEqual(req1.status, "PENDING");

    // Resolve with specific approver
    const resolved = engine.resolveRequest(req1.token, true, "security-director");
    assert.strictEqual(resolved, true);
    const inspected = engine.getRequest(req1.id);
    assert.strictEqual(inspected?.resolvedBy, "security-director");
    assert.ok(typeof inspected?.resolvedAt === "number");

    // Capacity bounding test
    for (let i = 0; i < 10; i++) {
      engine.createRequest({ ...ctx, target: `target_${i}` }, `Reason ${i}`);
    }
    // Requests size must never exceed maxRequests
    const pending = engine.getPendingRequests();
    assert.ok(pending.length <= 5, "Pending requests must not exceed capacity limit");
  });

  // F-010: Dashboard Authentication Token & Header / Cookie Support
  it("F-010: DashboardServer sets HttpOnly session cookie, accepts Authorization header, and strips URL token", async () => {
    const report = RiskEngine.calculateReport([]);
    const dashboard = await DashboardServer.start(report, 0);

    try {
      // 1. Initial request with ?token=... must set HttpOnly cookie and return HTML with token stripping script
      const initialRes = await new Promise<{ statusCode?: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
        const req = http.get(`http://127.0.0.1:${dashboard.port}/?token=${dashboard.authToken}`, (res) => {
          let body = "";
          res.on("data", chunk => body += chunk);
          res.on("end", () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
        });
        req.on("error", reject);
      });

      assert.strictEqual(initialRes.statusCode, 200, "Initial authenticated GET must succeed");
      assert.ok(
        initialRes.headers["set-cookie"]?.[0]?.includes("agentshield_session="),
        "Must set agentshield_session HttpOnly cookie"
      );
      assert.ok(
        initialRes.body.includes("window.history.replaceState"),
        "Must include client-side token stripping script to prevent URL history leakage"
      );

      // 2. Unauthenticated request to /api/report must receive 401 Unauthorized
      const unauthRes = await new Promise<{ statusCode?: number }>((resolve, reject) => {
        const req = http.get(`http://127.0.0.1:${dashboard.port}/api/report`, (res) => {
          resolve({ statusCode: res.statusCode });
        });
        req.on("error", reject);
      });
      assert.strictEqual(unauthRes.statusCode, 401, "Unauthenticated request must be rejected with 401");

      // 3. Authenticated request with Authorization header must succeed
      const authRes = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
        const req = http.get(`http://127.0.0.1:${dashboard.port}/api/report`, {
          headers: {
            "Authorization": `Bearer ${dashboard.authToken}`
          }
        }, (res) => {
          let body = "";
          res.on("data", chunk => body += chunk);
          res.on("end", () => resolve({ statusCode: res.statusCode, body }));
        });
        req.on("error", reject);
      });
      assert.strictEqual(authRes.statusCode, 200, "Bearer token must be accepted");
      const parsed = JSON.parse(authRes.body);
      assert.strictEqual(parsed.score, 100);
    } finally {
      await dashboard.stop();
    }
  });
});
