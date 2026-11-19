# AgentShield Ultimate: Architecture Specification

**Project**: AgentShield Ultimate (`agentshield-ultimate`)  
**Architecture Type**: Modular Zero-Trust Enforcement Engine & Universal Security Skill  
**Platform**: Node.js >= 18.0.0 / TypeScript (ESM & CommonJS)  

---

## 1. High-Level Modular Architecture

AgentShield Ultimate is designed around an decoupled, event-driven, zero-trust architecture. It contains 14 specialized security modules governed by a central Policy and Risk Engine.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             AGENTSHIELD CLI & SDK                           │
│     CLI (commander) │ TypeScript SDK │ REST/MCP Server │ Universal Skill    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                      CENTRAL POLICY & RISK ENGINE                           │
│  - Config & Rule Store (Strict / Balanced / Dev)                            │
│  - Event Bus & Telemetry Pipeline                                           │
│  - Audit Logger (JSONL with SHA-256 Hash Chaining)                          │
│  - Risk Scoring & Assessment Engine (0-100 Score, A-F Grade)                │
└──────┬───────────────────────────────┬───────────────────────────────┬──────┘
       │                               │                               │
┌──────▼──────────────────────┐ ┌──────▼──────────────────────┐ ┌──────▼──────┐
│      PERIMETER GUARDS       │ │      RUNTIME GUARDS         │ │ GOVERNANCE  │
├─────────────────────────────┤ ├─────────────────────────────┤ ├─────────────┤
│ 1. Prompt Guard             │ │ 5. Filesystem Guard         │ │ 11. Human   │
│    - Direct & Indirect PI   │ │    - Workspace Sandbox      │ │     Approval│
│    - Tool/Schema Poisoning  │ │    - Path Traversal Block   │ │     Engine  │
│    - Unicode & Homoglyphs   │ │    - Sensitive File Deny    │ │ 12. Security│
│                             │ │                             │ │     Dashboard│
│ 2. Browser Guard            │ │ 6. Network Guard            │ │ 13. Auto-   │
│    - Ad / Sponsored Blocker │ │    - SSRF & Cloud Metadata  │ │     Remedia-│
│    - Phishing & Homographs  │ │    - RFC 1918 Private Block │ │     tion    │
│    - Action Interceptor     │ │    - Egress Filtering       │ │ 14. Report- │
│                             │ │                             │ │     ing     │
│ 3. Skill Scanner            │ │ 7. Secret Guard             │ │     (SARIF, │
│    - SKILL.md AST Analysis  │ │    - 50+ Entropy Signatures │ │     Markdown,│
│    - Hidden Script Checks   │ │    - Redaction & Vault      │ │     JSON)   │
│                             │ │                             │ └─────────────┘
│ 4. MCP Guard                │ │ 8. Command Guard            │
│    - Tool Poisoning Audit   │ │    - Shell Injection Def.   │
│    - Permission Auditor     │ │    - Command Allowlisting   │
│                             │ │                             │
│                             │ │ 9. Download Guard           │
│                             │ │    - Magic Byte Sniffing    │
│                             │ │    - Archive Zip-Slip Def.  │
│                             │ │                             │
│                             │ │ 10. Supply Chain Guard      │
│                             │ │     - Lockfile Validator    │
│                             │ │     - Script Hook Auditor   │
└─────────────────────────────┘ └─────────────────────────────┘
```

---

## 2. Component Design & Responsibilities

### 2.1 Core Subsystem (`src/core/`)
- `PolicyEngine`: Loads and validates policy profiles (`strict`, `balanced`, `dev`). Evaluates proposed agent actions against rule sets in constant time.
- `RiskEngine`: Computes unified risk assessments based on severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL), category weights, and historical audit context. Computes 0–100 Security Score and letter grades.
- `AuditLogger`: Writes immutable, structured records to `audit.jsonl` with timestamps, action hashes, and caller metadata.
- `EventBus`: Decoupled publish/subscribe bus for real-time alerting, dashboard streaming, and metrics collection.

### 2.2 Perimeter Defense
- `PromptGuard`: Multi-layered classifier detecting prompt injection patterns, role-reversal attempts, hidden instructions, base64 payloads, and Unicode zero-width evasion.
- `BrowserGuard`: Intercepts headless/live browser automation events. Inspects DOM selector targets, text content, and URLs. Blocks interactions with sponsored ads, tracking nodes, and untrusted redirect loops.
- `SkillScanner`: Analyzes agent skills, markdown instructions, and plugin manifests for malicious shell commands, credential harvesting patterns, and stealth instructions.
- `McpGuard`: Audits Model Context Protocol server registrations and tool definitions to prevent schema injection and unauthorized tool escalation.

### 2.3 Runtime Protection
- `FilesystemGuard`: Validates file operations against authorized workspace roots, normalizes paths to prevent `../` traversal, and blocks access to sensitive system paths (`.ssh`, `.aws`, `.env`, `/etc/passwd`).
- `NetworkGuard`: Validates network endpoints prior to connection. Enforces domain allowlists and blocks loopback, private RFC-1918 subnets, and cloud instance metadata (AWS/GCP/Azure 169.254.169.254).
- `SecretGuard`: Identifies high-entropy API keys, JWTs, private keys, and passwords across input/output channels and automatically redacts them.
- `CommandGuard`: Parses shell commands before execution to detect command chaining (`&&`, `;`, `|`), reverse shells, dangerous flags, and unapproved binaries.
- `DownloadGuard`: Analyzes downloaded files via magic numbers (file signature headers) and guards against archive directory traversal (Zip Slip).

### 2.4 Governance & Remediation
- `ApprovalEngine`: Coordinates human-in-the-loop approvals for sensitive operations (financial, data deletion, credential changes). Uses cryptographic tokens with TTL expiration and fail-closed defaults.
- `RemediationEngine`: Validates detected misconfigurations and applies safe, transactional fixes with snapshot backups and automatic rollback on failure.
- `Dashboard`: Lightweight, local HTTP/WebSocket dashboard protected by cryptographic session tokens.
- `Reporting`: Formats findings into ANSI terminal tables, JSON, Markdown, HTML, and SARIF v2.1.0.

---

## 3. Data Flow for Tool Execution Interception

```
[Agent Action Request] 
      │ (e.g. read_file, execute_command, browser_click, mcp_invoke)
      ▼
┌──────────────────────────────────────────────┐
│  AgentShield Interceptor Gate                │
├──────────────────────────────────────────────┤
│ 1. Event emitted to EventBus                 │
│ 2. Parameter normalization & secret redacting│
│ 3. Target risk assessment                    │
└──────┬───────────────────────────────────────┘
       │
       ├───► [High-Risk Action? (Financial, Deletion, Privileged)]
       │         │
       │         ▼
       │     [Approval Engine] ──(Rejected/Timed Out)──► BLOCK & AUDIT
       │         │ (Approved)
       │         ▼
       ├───► [Guard Evaluation] (Filesystem, Network, Browser, Command)
       │         │
       │         ├───(Violation Detected)─────────────► BLOCK & AUDIT
       │         │
       │         └───(All Checks Passed)──────────────► EXECUTE SAFELY
       │                                                     │
       └─────────────────────────────────────────────────────┴──► Record in Audit Log
```

---

## 4. Performance & Reliability Guarantees
- **Zero-Dependency Runtime Core**: Fast startup (< 50ms) using native Node.js APIs without external binary dependencies.
- **Microsecond Policy Checks**: In-memory rule evaluation completes in < 5ms per event.
- **Fail-Closed Default**: In the event of an unhandled runtime error, the engine defaults to blocking the requested operation.
