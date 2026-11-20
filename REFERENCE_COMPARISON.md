# AgentShield Ultimate — Reference Comparison & Competitive Analysis

## Comparative Benchmark Analysis

`agentshield-ultimate` was evaluated against leading open-source and commercial agent security frameworks:
1. **`affaan-m/agentshield`**: The initial baseline predecessor framework.
2. **`NVIDIA/SkillSpector`**: Enterprise skill and agent capability inspection tool.
3. **`Nasiko` / Similar Agent Firewalls**: Proxy-based LLM application firewalls.

---

## Feature & Architecture Comparison Matrix

| Feature / Capability | `affaan-m/agentshield` | `NVIDIA/SkillSpector` | `Nasiko` / Proxy Firewalls | `agentshield-ultimate` (Remediated) |
| :--- | :---: | :---: | :---: | :---: |
| **Zero External Runtime Dependencies** | Yes | No (Python/Heavy ML) | No (External Gateway) | **Yes (Pure Node.js standard library)** |
| **TypeScript / Node.js Native SDK** | Partial | No | No (HTTP Proxy) | **Yes (Full TS 5.x typings)** |
| **Live Executable Red-Team Engine** | No (Mocked) | Yes (Static rule-based) | No | **Yes (13 live multi-vector tests)** |
| **Cryptographic Human Approval Gating** | No | No | Optional | **Yes (HMAC-SHA256 parameter bound)** |
| **Async DNS SSRF / Metadata Defense** | No (String match only) | N/A | Yes | **Yes (Live DNS resolution & validation)** |
| **Symlink TOCTOU Path Defense** | No | N/A | N/A | **Yes (Canonical realpathSync checking)** |
| **Recursive Workspace Scanning** | Basic | Advanced | N/A | **Yes (Skills, MCP configs, package scripts)** |
| **Audit Log Tamper-Evident Hashing** | Basic | No | Yes | **Yes (SHA-256 cryptographic chain)** |
| **Local Secure Dashboard** | Token in URL query | N/A | Cloud Hosted | **Yes (HttpOnly cookie + sanitization)** |
| **Static Code Quality / Linting** | Fake echo script | Flake8/Black | ESLint | **Yes (Dedicated AST static linter)** |

---

## Distinct Architectural Advantages

1. **Ultra-Lightweight Footprint**: Zero runtime `node_modules` dependencies ensures instant installation, zero supply-chain attack surface, and negligible memory overhead.
2. **Fail-Closed Execution**: Where typical prompt filters merely log warnings, `agentshield-ultimate` halts tool execution immediately unless explicitly cleared or cryptographically approved.
3. **Comprehensive In-Process Defense**: Covers prompt injection, filesystem access, command injection, network calls, browser navigation, secret leakage, and human approvals under a unified risk engine.
