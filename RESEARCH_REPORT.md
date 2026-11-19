# AgentShield Ultimate: Comprehensive Upstream & Standards Research Report

**Project**: AgentShield Ultimate (`agentshield-ultimate`)  
**Document**: Upstream Security Architecture & Standards Analysis  
**Classification**: Public Open-Source Research & Design Baseline  
**Date**: November 2026  
**Author**: Principal Security Architect & Engineering Team  

---

## 1. Executive Summary

As AI agents evolve from read-only LLM chat interfaces into autonomous systems executing shell commands, traversing file systems, interacting with external APIs, driving headless browsers, and invoking Model Context Protocol (MCP) toolkits, the attack surface expands exponentially. Traditional application security models assume static trust boundaries and deterministic execution flows. In contrast, autonomous agent workflows operate on non-deterministic model completions driven by untrusted external context (user queries, fetched web pages, ingested PDFs, MCP tool descriptions, repository files, third-party skills).

**AgentShield Ultimate** is conceived to solve this critical security vacuum by providing a dual-layer architecture:
1. **Universal AI Agent Security Skill** (`SKILL.md` + modular policies): High-leverage behavioral guidance, system prompt defensive framing, and cognitive safety constraints across leading agent harnesses (Claude Code, OpenAI Codex, Cursor, OpenClaw, GitHub Copilot, Gemini CLI, Windsurf, Cline, Continue).
2. **Deterministic, Independent Security Enforcement Engine**: An executable zero-trust runtime gate written in TypeScript that intercepts, audits, validates, risk-scores, and enforces guardrails at the OS, browser, filesystem, network, secret, and MCP interfaces **regardless of whether the LLM attempts to comply or is jailbroken**.

This research report analyzes four foundational upstream open-source projects, reviews international AI safety and cybersecurity standards, identifies core vulnerability classes, maps architectural overlaps and unique capabilities, and formulates the design blueprint for AgentShield Ultimate.

---

## 2. Upstream Repository Comparative Analysis

### 2.1 NVIDIA SkillSpector (`NVIDIA/SkillSpector`)
* **Repository**: `https://github.com/NVIDIA/SkillSpector`
* **License**: Apache 2.0
* **Core Focus**: Static analysis and LLM-assisted semantic evaluation of AI agent skills (`SKILL.md`) and MCP server implementations.
* **Architectural Mechanics**:
  - Two-tier scanning pipeline: Tier 1 executes fast static regex and Abstract Syntax Tree (AST) pattern matching (scanning for `eval()`, `child_process`, `os.system`, dangerous shell pipelines, obfuscated payloads, and known vulnerable dependencies via OSV.dev). Tier 2 deploys an optional LLM-as-a-judge semantic analysis to evaluate intent discrepancy between a skill's declared description and its actual execution code.
  - Granular vulnerability taxonomies: Excessive agency, prompt injection vectors, system prompt exfiltration, unauthorized tool misuse, MCP least-privilege violations, supply-chain contamination.
  - Multi-target ingress: Git repositories, local directories, tar/zip archives, single markdown files.
  - Formatted outputs: Terminal ANSI tables, JSON, Markdown, and SARIF for GitHub Code Scanning integration.
* **Key Lessons & Limitations for AgentShield Ultimate**:
  - *Strength*: Rigorous taxonomy of skill-specific attack vectors and standardized SARIF export.
  - *Limitation*: Python-centric runtime; primarily an offline/pre-commit scanner rather than an active inline runtime security enforcement proxy for agents.
  - *AgentShield Integration*: We independently implement a high-speed TypeScript AST/regex skill scanning engine with full support for YAML frontmatter parsing, shell command extraction, hidden prompt injection detection, and SARIF output without dragging Python runtime dependencies.

### 2.2 Nasiko (`Nasiko-Labs/nasiko`)
* **Repository**: `https://github.com/Nasiko-Labs/nasiko`
* **License**: Apache 2.0
* **Core Focus**: Enterprise agent control plane, runtime governance, MCP gateway, and cost/token observability.
* **Architectural Mechanics**:
  - MCP Gateway acting as a policy proxy between AI agents and external tools, enforcing per-tool stances (`allow`, `ask`, `block`).
  - Flow Guards mitigating runaway autonomous loops: hard execution depth thresholds, tool fan-out caps, token budgets, timeout enforcement, and anti-recursion cycle checks.
  - Ephemeral credential vault: Agents never receive long-lived API tokens or master credentials; the runtime mints short-lived (e.g. 60-second) scoped bearer tokens. Sensitive secrets are AES-256-GCM encrypted at rest.
  - Human-in-the-Loop (HITL) gate pausing execution when sensitive capabilities are invoked.
* **Key Lessons & Limitations for AgentShield Ultimate**:
  - *Strength*: Outstanding runtime containment concepts (ephemeral secrets, loop runaway protection, tool stance gating).
  - *Limitation*: Heavy distributed architecture (Rust daemon, PostgreSQL, Redis, OCI registry) designed for multi-tenant enterprise clusters rather than lightweight local developer workstations or embedded npm packages.
  - *AgentShield Integration*: We adapt Nasiko's core governance invariants—cryptographically bound human approval tokens, ephemeral secret redaction, and strict tool authorization policies—into an embedded, zero-dependency Node.js/TypeScript engine that runs instantly via `npx agentshield-ultimate` or as a background sidecar.

### 2.3 Tencent AI-Infra-Guard (`Tencent/AI-Infra-Guard`)
* **Repository**: `https://github.com/Tencent/AI-Infra-Guard` (Zhuque Lab)
* **License**: Apache 2.0
* **Core Focus**: Full-stack AI Red Teaming, MCP security, agent workflow scanning, and jailbreak evaluation.
* **Architectural Mechanics**:
  - Infrastructure vulnerability scanner targeting local LLM servers (Ollama, ComfyUI, vLLM, n8n, Triton).
  - MCP scanning engine targeting tool poisoning, schema poisoning, and backdoored parameters.
  - Multi-agent platform auditing (Dify, Coze) mapped against OWASP Top 10 for Agentic Applications.
  - Automated adversarial jailbreak evaluation suite benchmarking LLM robustness against deceptive, multi-turn, and jailbreak prompts.
* **Key Lessons & Limitations for AgentShield Ultimate**:
  - *Strength*: Comprehensive red-teaming perspective and tool poisoning taxonomy.
  - *Limitation*: Designed as an internal enterprise red-team server; explicit warning in upstream docs notes the lack of native authentication and advises against running on exposed interfaces.
  - *AgentShield Integration*: We incorporate AI-Infra-Guard's red-teaming attack vectors into our automated verification test suite (`tests/adversarial/` and `agentshield red-team`), and build an embedded, authenticated security dashboard with cryptographically generated session tokens.

### 2.4 Affaan Mustafa AgentShield (`affaan-m/agentshield`)
* **Repository**: `https://github.com/affaan-m/agentshield`
* **License**: MIT
* **Core Focus**: Configuration auditor, secret scanner, permission checker, and hook injector for Claude Code and Agent Harnesses.
* **Architectural Mechanics**:
  - Deep audit of `.claude/`, `.cursor/`, `.mcp.json`, and agent configuration states.
  - Transparent 0–100 Security Score with weighted category penalties (Secret Exposure, Unsafe Permissions, Hook Poisoning, Network Exposure).
  - Automated remediation engine with safe transactional backup and rollback capabilities.
  - Pre-commit and CI/CD GitHub Actions integration (`ecc-agentshield`).
* **Key Lessons & Limitations for AgentShield Ultimate**:
  - *Strength*: Exceptional developer ergonomics, native npm/TypeScript architecture, actionable 0–100 scoring, and transactional remediation.
  - *AgentShield Integration*: Serves as direct heritage for AgentShield Ultimate's risk scoring model, automated remediation engine, and configuration auditing, which we expand with universal multi-agent adapters, active browser security, SSRF defense, and zero-trust runtime policy engines.

---

## 3. Authoritative Cybersecurity & AI Standards Synthesis

AgentShield Ultimate aligns directly with recognized international standards:

| Standard / Framework | Relevant Domain | AgentShield Ultimate Implementation |
| :--- | :--- | :--- |
| **OWASP Top 10 for LLM Applications (2025/2026)** | Prompt Injection (LLM01), Sensitive Info Disclosure (LLM02), Supply Chain (LLM03), Data/Model Poisoning (LLM04), Improper Output Handling (LLM05), Excessive Agency (LLM06), System Prompt Leakage (LLM07), Vector/Embedding Weaknesses (LLM08), Misinformation (LLM09), Unbounded Consumption (LLM10) | Deterministic prompt injection filters, secret redaction, AST supply-chain scanner, human approval gates, execution timeouts. |
| **OWASP Top 10 for Agentic Applications** | Tool Poisoning, Memory Tampering, Cascading Goal Hijacking, Runaway Loop Exfiltration, Cross-Agent Impersonation | MCP Guard with strict schema validation, unified memory isolation, execution recursion limits, origin-pinned authorization. |
| **OWASP MCP Security Guidance** | MCP Server Transport, Tool Poisoning, Description Injection, SSRF via Tool Invocations | MCP Guard configuration auditor, regex-based description analyzer, SSRF filter on all tool network parameters. |
| **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)** | AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak), AML.T0043 (Exfiltration via Agent), AML.T0040 (ML Supply Chain Compromise) | Continuous adversarial red-team test suite, prompt boundary tokens, AST integrity checks, outbound network egress filtering. |
| **NIST AI Risk Management Framework (AI RMF 1.0)** | Govern (1.0), Map (2.0), Measure (3.0), Manage (4.0) | Continuous risk telemetry, structured audit event log (`audit.jsonl`), transparent scoring formula, automated rollback remediation. |
| **OpenSSF & SLSA (Supply-chain Levels for Software Artifacts)** | Build Integrity, Hermetic Dependencies, Provenance | Pinned dependency locks, GitHub Actions build provenance with OIDC, zero-dependency runtime core, SBOM generation (SPDX/CycloneDX). |
| **CWE / CVE Mappings** | CWE-79 (XSS/Ad Injections), CWE-200 (Info Exposure), CWE-22 (Path Traversal), CWE-78 (OS Command Injection), CWE-918 (SSRF) | Filesystem Guard (path traversal/symlink escape blocking), Network Guard (private IP/cloud metadata block), Secret Guard (redaction). |

---

## 4. Threat Matrix & Unique Capabilities Matrix

```
+----------------------------------------------------------------------------------------------------+
|                                    AGENTSHIELD ULTIMATE CAPABILITY MATRIX                          |
+------------------------------+------------------+---------+--------------------+-------------------+
| Security Capability          | NVIDIA           | Nasiko  | Tencent            | AGENTSHIELD       |
|                              | SkillSpector     | Labs    | AI-Infra-Guard     | ULTIMATE          |
+------------------------------+------------------+---------+--------------------+-------------------+
| SKILL.md Static Scanner      | Yes (Python/AST) | No      | Yes (Partial)      | Yes (TypeScript)  |
| MCP Tool Poisoning Scanner   | Yes              | Partial | Yes                | Yes (Deep Schema) |
| Runtime Tool Gateway & HITL  | No (Offline)     | Yes     | No (Offline/Audit) | Yes (Zero-Trust)  |
| Ephemeral Secret Redaction   | No               | Yes     | No                 | Yes (50+ Patterns)|
| Browser Ad/Sponsored Blocker | No               | No      | No                 | YES (Deterministic|
| Phishing & Homograph Guard   | No               | No      | No                 | YES (IDN/Entropy) |
| Local Filesystem Sandbox     | No               | No      | No                 | YES (Path Traver.)|
| Anti-SSRF & Cloud Metadata   | No               | Partial | Partial            | YES (Full RFC1918)|
| Multi-Agent Adapters (9+)    | No               | Partial | No                 | YES (Universal)   |
| Embedded Authenticated Dash  | No               | Web UI  | Unauthenticated UI | YES (Auth Token)  |
| Auto-Remediation & Rollback  | No               | No      | No                 | YES (Transactional|
| Zero-Dependency Runtime Core | No (Python deps) | Rust/DB | Python/Flask       | YES (Node/TS Core)|
+------------------------------+------------------+---------+--------------------+-------------------+
```

---

## 5. Architectural Recommendations for AgentShield Ultimate

1. **Pure TypeScript/Node.js Architecture**: Build the core framework without heavy external system dependencies (Postgres/Redis/Python). Everything required to secure an agent session must run directly inside the developer's Node.js runtime or CLI environment.
2. **Deterministic Pre-Execution Gates**: Never permit an agent action (shell command, HTTP request, file read/write, browser click) to execute without synchronous interception and validation by the AgentShield Policy Engine.
3. **Browser Action Enforcement**: Browser automation (Puppeteer, Playwright, Chrome DevTools MCP) must validate target DOM nodes, rejecting elements bearing advertisement IDs, sponsored CSS classes, tracking domains, or off-scope origins.
4. **Transparent Risk Engine**: Findings must map to transparent severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL) with exact CWE/OWASP anchors and remediation steps.
5. **Fail-Closed by Design**: If an inspection fails, an approval token expires, or a target classification is ambiguous, the engine must default to blocking the action.
