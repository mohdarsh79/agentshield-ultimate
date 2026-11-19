import { test, describe } from "node:test";
import * as assert from "node:assert";
import { BrowserGuard } from "../../src/browser-guard";

describe("Browser Guard Tests", () => {
  test("Blocks clicking on sponsored search result element", () => {
    const res = BrowserGuard.evaluateBrowserAction({
      actionType: "browser_click",
      actor: "browser_agent",
      target: "a.sponsored-result",
      parameters: { selector: ".sponsored-result" }
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("advertising or sponsored content"));
  });

  test("Blocks clicking on ad-container class", () => {
    const res = BrowserGuard.evaluateBrowserAction({
      actionType: "browser_click",
      actor: "browser_agent",
      target: "div.ad-container",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
  });

  test("Detects punycode / homograph phishing domains", () => {
    const check = BrowserGuard.validateUrl("https://xn--appl-45d.com/login");
    assert.strictEqual(check.allowed, false);
    assert.strictEqual(check.isPhishing, true);
  });

  test("Allows navigating to safe standard domains", () => {
    const check = BrowserGuard.validateUrl("https://developer.mozilla.org/en-US/docs/Web/JavaScript");
    assert.strictEqual(check.allowed, true);
    assert.strictEqual(check.isAdOrSponsored, false);
  });
});
