# AgentShield Ultimate — Architecture Assessment

## System Topology & Security Boundary

`agentshield-ultimate` is designed as a TypeScript/Node.js zero-dependency security framework for AI agent systems, autonomous workflows, and tool execution pipelines.

```
                      +---------------------------------------+
                      |       Autonomous AI Agent Runtime     |
                      |  (LangChain, Claude, LlamaIndex, MCP) |
                      +-------------------+-------------------+
                                          |
                                          | interceptAction / interceptActionAsync
                                          v
+===================================================================================+
|                          AGENTSHIELD ULTIMATE CORE GATEWAY                         |
|                                                                                   |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  |    Prompt Guard    |  |     Command Guard    |  |     Filesystem Guard      |  |
|  | - Direct Injection |  | - Shell AST parser   |  | - Canonical realpathSync  |  |
|  | - Indirect Exfil   |  | - High-risk command  |  | - Traversal detection     |  |
|  | - Jailbreak rules  |  | - Pipe & subshell chk|  | - Sensitive file blocks   |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  |   Network Guard    |  |     Secret Guard     |  |       Browser Guard       |  |
|  | - Async DNS Lookup |  | - High-entropy shann.|  | - Target URL validation   |  |
|  | - Private IP block |  | - API key patterns   |  | - Data exfil mitigation   |  |
|  | - Cloud metadata   |  | - Automatic redact   |  | - Navigation restriction  |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                     Central Policy & Risk Assessment Engine                 |  |
|  | - Dynamic weighted risk aggregation (0 - 100)                               |  |
|  | - Fail-closed operational policy gating                                     |  |
|  | - Cryptographic Approval Engine challenge generator                         |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                     Cryptographic Approval Engine (F-002)                   |  |
|  | - HMAC-SHA256 parameter commitment tokens                                   |  |
|  | - Bounded TTL cache & auto-eviction (F-009)                                 |  |
|  | - Multi-party approver identity validation                                  |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                      Tamper-Evident Audit Logging Bus                       |  |
|  | - SHA-256 forward-linked cryptographic hash chain                           |  |
|  | - Structured JSON-lines audit trail                                         |  |
|  +-----------------------------------------------------------------------------+  |
+===================================================================================+
                                          |
                      +-------------------+-------------------+
                      |                                       |
                      v                                       v
          [ ALLOWED: Clean Execution ]           [ BLOCKED: Policy / Security ]
```

---

## Core Components & Remediated Architectures

### 1. SDK Interceptor (`src/sdk/index.ts`)
- **Synchronous & Asynchronous Interception**: Provides `interceptAction` and `interceptActionAsync`.
- **Fail-Closed Gatekeeper**: If any security guard flags high risk or requires human approval, execution is immediately halted with a structured `AgentShieldBlockedError`.
- **Approval Verification**: Automatically checks provided approval tokens against parameter cryptographic hashes before permitting high-risk operations.

### 2. Live Adversarial Red-Team Engine (`src/red-team/index.ts`)
- Replaces static reports with `RedTeamRunner`.
- Executes 13 live synthetic attack vectors targeting prompt injection, path traversal, command chaining, SSRF, secret leakage, and approval bypass.
- Produces verifiable execution telemetry with timestamps, duration, and pass/fail assertions.

### 3. Deep Multi-Vector Workspace Scanner (`src/workspace-scanner/index.ts`)
- Recursively audits directories for malicious skills, unsanitized MCP configs, dangerous `package.json` lifecycle scripts, hardcoded credentials, and symlink traps.
- Reports comprehensive metrics: total files inspected, skipped directories (`node_modules`, `.git`), issue severity breakdowns, and scan durations.

### 4. Asynchronous Network & SSRF Defense (`src/network-guard/index.ts`)
- Implements `evaluateRequestAsync(url)` utilizing Node's `dns.promises.lookup`.
- Detects DNS rebinding and internal IP resolutions for RFC-1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), AWS/GCP/Azure link-local metadata (169.254.169.254), Carrier-Grade NAT (100.64.0.0/10), and loopback addresses.

### 5. TOCTOU & Symlink Filesystem Guard (`src/filesystem-guard/index.ts`)
- Analyzes existing file paths and resolves target directories using `fs.realpathSync`.
- Traverses upwards to nearest existing parent directories for non-existent target files to prevent symlink race conditions and directory traversal breakouts.

### 6. Zero-Dependency AST/Static Analysis Linter (`scripts/lint.js`)
- Recursively scans TypeScript and JavaScript source files.
- Enforces strict hygiene: bans `eval()`, `new Function()`, `debugger;`, and silent empty catch blocks.

### 7. Secure Local Dashboard Server (`src/dashboard/index.ts`)
- Ephemeral port binding (`port: 0` support) preventing test collisions.
- Session authorization using `HttpOnly; SameSite=Strict` cookies.
- Authorization header support (`Bearer <token>`).
- Client-side URL credential stripping using `history.replaceState` to eliminate token leakage.
