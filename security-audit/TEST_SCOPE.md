# AgentShield Ultimate: Security Assessment Scope

**Target**: `AgentShield Ultimate` v1.0.0  
**Testing Methodology**: Grey-box source review, adversarial red-teaming, negative boundary testing, fuzzing, concurrency & race condition testing, supply-chain analysis.  

---

## 1. In-Scope Targets

1. **Perimeter Ingress Interfaces**:
   - `PromptGuard`: Direct/indirect prompt injection, document parsing, Unicode normalization, base64 payload decoding.
   - `BrowserGuard`: Click interception, DOM selector heuristics, URL parsing, Punycode/homograph classification.
   - `SkillScanner`: Static markdown, YAML frontmatter, script inspection, regex pattern matching.
   - `McpGuard`: MCP tool schema, tool descriptions, and environment variables.

2. **Runtime Policy & Enforcement Engines**:
   - `PolicyEngine`: Policy profile switching, fail-closed handling, execution gates.
   - `FilesystemGuard`: Path normalization, directory traversal, absolute path resolution, symlink checking.
   - `NetworkGuard`: SSRF filters, IPv4/IPv6 address parsing, DNS rebinding mitigations, cloud metadata protection.
   - `CommandGuard`: Shell injection parsing, metacharacter validation, process limits.
   - `SecretGuard`: High-entropy regex scanners, credential redaction.
   - `ApprovalEngine`: Cryptographic parameter binding, TTL expiration, race conditions, replay protection.

3. **External Services & Interfaces**:
   - `DashboardServer`: HTTP endpoint authorization, XSS in HTML template rendering, CSRF, Host header handling.
   - `RemediationEngine`: Snapshot backup creation, transactional rollback integrity.
   - CLI & SDK APIs: Input validation, type safety, error disclosure.
   - npm Package Distribution: Tarball integrity, export resolution, dependency provenance.

---

## 2. Out-of-Scope Constraints
- Production third-party infrastructure (no unauthorized outbound network scanning).
- Live cloud metadata queries against genuine external cloud providers (mock/synthetic queries only).
