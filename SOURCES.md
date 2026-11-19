# AgentShield Ultimate: Sources & Research Bibliography

This document inventories all upstream repositories, authoritative security standards, academic research, and technical specifications studied and referenced in the creation of **AgentShield Ultimate**.

---

## 1. Primary Upstream Repositories

### 1.1 NVIDIA SkillSpector
* **Repository**: `https://github.com/NVIDIA/SkillSpector`
* **Maintainer**: NVIDIA Corporation
* **License**: Apache License 2.0
* **Commit Baseline**: Main branch (November 2026)
* **Analyzed Components**:
  - `skillspector/scanner/`: Static AST pattern scanner for Python/Bash/YAML.
  - `skillspector/rules/`: YARA and regex heuristics for tool misuse, prompt injection, and excessive privilege.
  - `skillspector/eval/`: Semantic LLM evaluation guidelines and prompt templates.
  - `skillspector/reporters/`: SARIF format emitter and JSON schema.

### 1.2 Nasiko (Nasiko Labs)
* **Repository**: `https://github.com/Nasiko-Labs/nasiko`
* **Maintainer**: Nasiko Labs
* **License**: Apache License 2.0
* **Commit Baseline**: Main branch (November 2026)
* **Analyzed Components**:
  - `gateway/mcp/`: MCP runtime proxy architecture, tool catalog filtering (`allow`, `ask`, `block`).
  - `governance/flow_guards/`: Loop limiters, fan-out limits, recursion cycle detection.
  - `secrets/vault/`: Ephemeral token issuance, AES-256-GCM encryption at rest, secret substitution.
  - `harness/discovery/`: Passive agent discovery across Claude Code, Cursor, Codex.

### 1.3 Tencent AI-Infra-Guard (A.I.G)
* **Repository**: `https://github.com/Tencent/AI-Infra-Guard`
* **Maintainer**: Tencent Zhuque Lab
* **License**: MIT License (or Apache 2.0 dual reference in tooling)
* **Commit Baseline**: Main branch (November 2026)
* **Analyzed Components**:
  - `modules/agent_scan/`: OWASP Agentic Top 10 automated test harness.
  - `modules/mcp_scan/`: Model Context Protocol tool description poisoning detection.
  - `modules/jailbreak/`: Multi-turn jailbreak and deceptive prompt benchmarks.
  - `modules/skill_scan/`: Intent mismatch detection between skill declarations and executable code.

### 1.4 Affaan Mustafa AgentShield
* **Repository**: `https://github.com/affaan-m/agentshield`
* **Maintainer**: Affaan Mustafa (`affaan-m`)
* **License**: MIT License
* **Analyzed Components**:
  - Configuration audit routines for `.claude/`, `.cursor/`, and `.mcp.json`.
  - Transparent 0–100 security scoring algorithm and letter grading.
  - Transactional automated remediation engine with rollback state management.
  - CLI commands and GitHub Actions CI/CD workflows.

---

## 2. Standards & Frameworks

### 2.1 OWASP Foundation
* **OWASP Top 10 for Large Language Model Applications (2025/2026)**
  - URL: `https://owasp.org/www-project-top-10-for-large-language-model-applications/`
  - References: LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM03 (Supply Chain Risks), LLM06 (Excessive Agency), LLM07 (System Prompt Leakage), LLM10 (Unbounded Consumption).
* **OWASP Agentic Security Initiatives & Guidance (2026)**
  - Focus: Tool authorization boundaries, memory poisoning, agent-to-agent delegation attacks, autonomous feedback loop hijacking.
* **OWASP Model Context Protocol (MCP) Security Guidelines**
  - Focus: Tool definition poisoning, dynamic schema injection, SSRF via tool parameters, unauthorized filesystem mounting.

### 2.2 MITRE Corporation
* **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)**
  - URL: `https://atlas.mitre.org/`
  - Techniques: AML.T0051 (Prompt Injection), AML.T0054 (LLM Jailbreaking), AML.T0043 (Exfiltration via Agent Tool Calls), AML.T0040 (Supply Chain Contamination), AML.T0048 (Insecure Output Handling).

### 2.3 NIST (National Institute of Standards and Technology)
* **NIST AI Risk Management Framework (AI RMF 1.0 / SP 1270)**
  - Core functions: Govern, Map, Measure, Manage.
  - Guidelines for agentic autonomy, trustworthy telemetry, and verifiable guardrails.

### 2.4 OpenSSF & SLSA
* **OpenSSF (Open Source Security Foundation)**
  - Best Practices Badge Criteria and Dependency Integrity.
* **SLSA (Supply-chain Levels for Software Artifacts) v1.0**
  - Requirements for hermetic builds, tamper-evident provenance, and lockfile validation.

### 2.5 IETF RFCs
* **RFC 1918**: Address Allocation for Private Internets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
* **RFC 3986**: Uniform Resource Identifier (URI) Generic Syntax.
* **RFC 5890**: Internationalized Domain Names for Applications (IDNA) and homograph attack vectors.
* **RFC 6749**: The OAuth 2.0 Authorization Framework (ephemeral tokens and scoped delegations).
