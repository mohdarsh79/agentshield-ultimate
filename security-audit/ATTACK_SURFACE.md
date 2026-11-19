# AgentShield Ultimate: Attack Surface Inventory

## Comprehensive Attack Surface Mapping

### 1. Ingress Attack Surfaces
- **CLI Arguments**: `process.argv` inputs parsed in `src/cli/index.ts`. Potential for argument injection, unhandled exceptions, and invalid profile names.
- **SDK Action Context**: `AgentActionContext` objects supplied by calling harness or multi-agent adapter. Potential for malformed objects, non-string targets, prototype tampering.
- **Scraped Text Streams**: Passed into `PromptGuard.scan()`. Potential for regex catastrophic backtracking (ReDoS), unicode normalization confusion, payload evasion.
- **HTTP/Browser Navigation URLs**: Passed into `BrowserGuard.validateUrl()` and `NetworkGuard.evaluateRequest()`. Potential for URL parser discrepancies, IP format variations, DNS rebinding.
- **Local File System Paths**: Passed into `FilesystemGuard.evaluateFileAccess()`. Potential for UNC paths, Windows drive letter hops, symlink races, path encoding.

### 2. Runtime Processing Attack Surfaces
- **Policy Engine Rule Pipeline**: Evaluates synchronous rules. Risk of unhandled exception triggering fail-closed or inconsistent state.
- **Audit Logger Hash Chain**: Appends records to `audit.jsonl`. Risk of concurrent write race conditions leading to corrupted hash continuity.
- **Approval Engine Memory Map**: Stores approval tokens in memory. Risk of memory leak, TTL overflow, or parameter key reordering desynchronization.

### 3. Egress & UI Attack Surfaces
- **Local Dashboard Server**: Binds to `127.0.0.1:4173`. Risk of Cross-Site Request Forgery (CSRF) from browser tabs, Stored Cross-Site Scripting (XSS) via injected findings, Host header injection.
- **SARIF / JSON / Markdown Emitters**: Render scan reports. Risk of secret leakage in report strings if redaction is incomplete.
