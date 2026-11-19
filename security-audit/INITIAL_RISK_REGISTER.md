# AgentShield Ultimate: Initial Risk Register

| Risk ID | Title | Suspected Target | Initial Severity | Testing Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **RISK-01** | Stored XSS in Dashboard Server UI | `src/dashboard/index.ts` | **HIGH** | Inject malicious `<script>` tags in finding evidence and inspect rendered HTML response. |
| **RISK-02** | SSRF Bypass via Alternate IP Encodings (Decimal, Hex, Octal, IPv6) | `src/network-guard/index.ts` | **CRITICAL** | Probe NetworkGuard with decimal (e.g. `http://2852039166`), hex, octal, and IPv6 representations of 169.254.169.254 and 127.0.0.1. |
| **RISK-03** | Approval Parameter Mismatch on Object Key Reordering | `src/approval-engine/index.ts` | **MEDIUM** | Generate approval request with `{a: 1, b: 2}` and verify with `{b: 2, a: 1}`. |
| **RISK-04** | CommandGuard Bypasses via Multiline / Newline / Encoded Injections | `src/command-guard/index.ts` | **HIGH** | Test multiline strings (`rm -rf /\n`), base64 pipes, and variable substitution. |
| **RISK-05** | Filesystem Traversal via URL-encoded / Windows Specific Paths | `src/filesystem-guard/index.ts` | **HIGH** | Test double URL encoding `%252e%252e`, alternate data streams, UNC paths. |
| **RISK-06** | Catastrophic Regex Backtracking (ReDoS) in Parsers | `PromptGuard`, `SecretGuard` | **MEDIUM** | Fuzz regex patterns with crafted repetitive inputs to measure CPU execution time. |
