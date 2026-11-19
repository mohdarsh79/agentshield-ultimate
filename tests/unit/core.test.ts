import { test, describe } from "node:test";
import * as assert from "node:assert";
import { RiskEngine } from "../../src/core/risk-engine";
import { PolicyEngine } from "../../src/core/policy-engine";
import { SecurityFinding } from "../../src/types";

describe("Core Subsystem Tests", () => {
  test("RiskEngine should score 100 with A+ for zero findings", () => {
    const report = RiskEngine.calculateReport([]);
    assert.strictEqual(report.score, 100);
    assert.strictEqual(report.grade, "A+");
  });

  test("RiskEngine should penalize 25 points and assign F grade for CRITICAL finding", () => {
    const findings: SecurityFinding[] = [{
      id: "TEST-01",
      severity: "CRITICAL",
      confidence: "CERTAIN",
      category: "CREDENTIAL",
      title: "Test Critical Finding",
      evidence: "Test",
      affectedResource: "test.env",
      impact: "Test Impact",
      mitigation: "Test Mitigation",
      standardReference: "OWASP-LLM02",
      remediationStatus: "OPEN",
      timestamp: new Date().toISOString()
    }];

    const report = RiskEngine.calculateReport(findings);
    assert.strictEqual(report.score, 75);
    assert.strictEqual(report.grade, "F");
  });

  test("PolicyEngine should block sensitive credential file access", () => {
    const engine = new PolicyEngine("strict");
    const result = engine.evaluateAction({
      actionType: "file_read",
      actor: "test_agent",
      target: "/workspace/.ssh/id_rsa",
      parameters: {}
    });

    assert.strictEqual(result.allowed, false);
    assert.ok(result.blockedReason?.includes("sensitive filesystem target"));
  });

  test("PolicyEngine should block ad-click interactions in browser", () => {
    const engine = new PolicyEngine("strict");
    const result = engine.evaluateAction({
      actionType: "browser_click",
      actor: "browser_agent",
      target: "div.googleads-ad-container",
      parameters: {}
    });

    assert.strictEqual(result.allowed, false);
    assert.ok(result.blockedReason?.includes("advertising"));
  });
});
