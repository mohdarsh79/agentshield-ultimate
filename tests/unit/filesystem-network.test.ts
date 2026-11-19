import { test, describe } from "node:test";
import * as assert from "node:assert";
import { FilesystemGuard } from "../../src/filesystem-guard";
import { NetworkGuard } from "../../src/network-guard";

describe("Filesystem & Network Guard Tests", () => {
  test("FilesystemGuard blocks path traversal attempts", () => {
    const res = FilesystemGuard.evaluateFileAccess({
      actionType: "file_read",
      actor: "test_agent",
      target: "../../../etc/passwd",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("Path traversal"));
  });

  test("FilesystemGuard blocks access to .env files", () => {
    const res = FilesystemGuard.evaluateFileAccess({
      actionType: "file_read",
      actor: "test_agent",
      target: ".env",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("sensitive credential file"));
  });

  test("NetworkGuard blocks cloud instance metadata SSRF (169.254.169.254)", () => {
    const res = NetworkGuard.evaluateRequest({
      actionType: "network_request",
      actor: "test_agent",
      target: "http://169.254.169.254/latest/meta-data/",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("metadata"));
  });

  test("NetworkGuard blocks RFC-1918 private subnet egress", () => {
    const res = NetworkGuard.evaluateRequest({
      actionType: "network_request",
      actor: "test_agent",
      target: "http://192.168.1.100:8080/admin",
      parameters: {}
    });
    assert.strictEqual(res.allowed, false);
    assert.ok(res.blockedReason?.includes("private IP"));
  });
});
