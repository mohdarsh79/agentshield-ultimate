# AgentShield Ultimate: Comprehensive Audit Inventory

**Audit Date**: November 2026  
**Assessment Phase**: Initial Discovery & Component Mapping  
**Target Repository**: `Agentshield_ultimate`  
**Framework Package**: `agentshield-ultimate@1.0.0`  

---

## 1. Inventory of Modules & Source Code

| Module | Source Path | Main Export / Class | Primary Responsibility |
| :--- | :--- | :--- | :--- |
| **Types & Contracts** | `src/types/index.ts` | Interfaces, Types, Enums | Security schemas, finding formats, action contexts, severity levels |
| **Event Bus** | `src/core/event-bus.ts` | `SecurityEventBus` | Decoupled event pub/sub for real-time security telemetry |
| **Audit Logger** | `src/core/audit-logger.ts` | `AuditLogger` | Tamper-evident append-only JSONL with SHA-256 hash chaining |
| **Risk Engine** | `src/core/risk-engine.ts` | `RiskEngine` | 0–100 scoring algorithm, grade calculation, category weights |
| **Policy Engine** | `src/core/policy-engine.ts` | `PolicyEngine` | Central policy rules, profile switching, fail-closed gate |
| **Prompt Guard** | `src/prompt-guard/index.ts` | `PromptGuard` | Prompt injection, jailbreak heuristics, Unicode & Base64 scanner |
| **Browser Guard** | `src/browser-guard/index.ts` | `BrowserGuard` | Ad/sponsored result blocker, phishing & homograph detector |
| **Filesystem Guard** | `src/filesystem-guard/index.ts` | `FilesystemGuard` | Workspace confinement, path traversal, symlink escapes |
| **Network Guard** | `src/network-guard/index.ts` | `NetworkGuard` | Anti-SSRF, RFC-1918 private IP block, cloud metadata protection |
| **Secret Guard** | `src/secret-guard/index.ts` | `SecretGuard` | 50+ credential signatures, entropy scanning, masking |
| **Command Guard** | `src/command-guard/index.ts` | `CommandGuard` | Shell injection prevention, dangerous command blocker |
| **Download Guard** | `src/download-guard/index.ts` | `DownloadGuard` | Magic byte executable sniffing, lifecycle script auditing |
| **Approval Engine** | `src/approval-engine/index.ts` | `ApprovalEngine` | Cryptographically bound human-in-the-loop gate with TTL |
| **Reporting Engine** | `src/reporting/index.ts` | `SecurityReporter` | Formatted output (ANSI, JSON, Markdown, SARIF v2.1.0) |
| **Dashboard Server** | `src/dashboard/index.ts` | `DashboardServer` | Embedded authenticated local HTTP dashboard |
| **Remediation Engine**| `src/remediation/index.ts` | `RemediationEngine` | Safe automated fixes with snapshot backups & rollback |
| **Agent Adapters** | `src/adapters/index.ts` | `UniversalAgentAdapterRegistry` | Multi-agent support (Claude, Cursor, Codex, OpenClaw, etc.) |
| **Programmatic SDK** | `src/sdk/index.ts` | `AgentShield` | Unified client API for runtime action interception |
| **CLI Executable** | `src/cli/index.ts` | `runCli` | CLI tool supporting 11 subcommands |

---

## 2. Inventory of Test Suites

| Suite Name | Path | Coverage Scope |
| :--- | :--- | :--- |
| `core.test.ts` | `tests/unit/core.test.ts` | RiskEngine scoring, PolicyEngine rule matching |
| `prompt-guard.test.ts` | `tests/unit/prompt-guard.test.ts` | Direct/indirect injections, Unicode evasion, benign inputs |
| `browser-guard.test.ts` | `tests/unit/browser-guard.test.ts` | Ad clicks, sponsored links, homograph domains |
| `filesystem-network.test.ts` | `tests/unit/filesystem-network.test.ts` | Path traversal, .env denial, metadata SSRF, RFC-1918 |
| `secrets-commands-approval.test.ts` | `tests/unit/secrets-commands-approval.test.ts` | Token redaction, destructive commands, approval replay |
| `red-team.test.ts` | `tests/adversarial/red-team.test.ts` | End-to-end multi-turn adversarial red-team benchmarks |

---

## 3. Inventory of Skills and Integrations

- Universal Skill: `skills/agentshield-ultimate/SKILL.md`
- Modular References: 12 reference guides under `skills/agentshield-ultimate/references/`
- CI/CD Workflows: `.github/workflows/ci.yml`, `security-audit.yml`, `release.yml`
