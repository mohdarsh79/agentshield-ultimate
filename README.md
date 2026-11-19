# AgentShield Ultimate

<p align="left">
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/Security-Policy%20Active-brightgreen?style=flat-square" alt="Security Policy" /></a>
  <a href="ARCHITECTURE.md"><img src="https://img.shields.io/badge/Security%20Architecture-Zero--Trust-blue?style=flat-square" alt="Zero Trust" /></a>
  <a href="SECURITY_TESTING.md"><img src="https://img.shields.io/badge/Automated%20Tests-35%20Passing-success?style=flat-square" alt="Tests" /></a>
  <a href="package.json"><img src="https://img.shields.io/badge/Release-v1.0.0-blueviolet?style=flat-square" alt="Version" /></a>
</p>

> **Universal Zero-Trust Security Framework for Autonomous AI Agents**

AgentShield Ultimate provides dual-layer security for AI coding assistants, autonomous agents, and browser automation systems:
1. **Universal AI Agent Security Skill** (`SKILL.md`): Cognitive guidance and behavioral constraints.
2. **Deterministic Security Enforcement Engine**: Independent, zero-trust TypeScript runtime that intercepts, audits, and enforces boundaries regardless of whether the model obeys instructions.

---

## Key Capabilities

- **Browser Security & Ad-Click Prevention**: Blocks clicks on advertising nodes (`sponsored`, `ad-container`, `commercial_unit`) and detects punycode homograph phishing domains.
- **Prompt Injection Defense**: Intercepts direct prompt overrides, indirect webpage/document injections, hidden comments, and unicode evasion characters.
- **Filesystem Sandbox**: Strictly confines operations to workspace boundaries, blocking directory traversal (`../`) and sensitive file targets (`.ssh`, `.env`, `.aws`).
- **Network & Anti-SSRF Guard**: Prohibits private RFC-1918 egress and cloud instance metadata access (`169.254.169.254`).
- **Credential & Secret Protection**: Scans and redacts 50+ high-entropy credential patterns (AWS, OpenAI, GitHub tokens, JWTs, private keys).
- **Command Guard**: Intercepts dangerous system operations (`rm -rf /`, fork bombs) and unapproved shell chaining metacharacters.
- **MCP Security**: Audits Model Context Protocol server configurations and detects poisoned tool descriptions.
- **Human Approval Gate**: Enforces cryptographically bound, fail-closed human approval for financial, file deletion, and software installation actions.
- **Transparent Risk Scoring**: Calculates an objective 0–100 security score and A+ to F grade.

---

## Quick Start

### Installation

```bash
# Run instantly via npx
npx agentshield-ultimate scan

# Or install globally
npm install -g agentshield-ultimate
```

### CLI Commands

```bash
# Initialize configuration in current project
agentshield init

# Scan workspace skills, MCP configs, package scripts, and secrets
agentshield scan

# Output scan as SARIF for GitHub Code Scanning
agentshield scan --sarif

# Run adversarial red-team simulation suite
agentshield red-team

# Safely apply automated remediations with rollback backup
agentshield fix

# Launch local authenticated security dashboard
agentshield dashboard
```

### Programmatic SDK Usage

```typescript
import { AgentShield } from "agentshield-ultimate";

const shield = new AgentShield({ profile: "strict" });

// Intercept an agent action before execution
const result = shield.interceptAction({
  actionType: "browser_click",
  actor: "agent-01",
  target: "a.sponsored-result",
  parameters: { selector: ".sponsored-result" }
});

if (!result.allowed) {
  console.error("Action blocked by AgentShield:", result.blockedReason);
}
```

---

## Supported Agents

- **Claude Code**: Full support (Hooks, Skill, Runtime Engine)
- **Cursor**: Full support (Rules, MCP Guard, Runtime Engine)
- **OpenAI Codex**: Full support (SDK Proxy, Policy Engine)
- **OpenClaw**: Full support (Hook Interceptors, Skill)
- **GitHub Copilot**: Workspace Rules & Static Analysis
- **Gemini CLI**: Full support (Sidecar, Skill, Engine)
- **Windsurf**: Cascade Rules & MCP Guard
- **Cline**: Protocol Integration & Policy Rules
- **Continue**: Config Filter & Policy Engine

---

## Documentation

- [Installation Guide](INSTALLATION.md)
- [Architecture Specification](ARCHITECTURE.md)
- [Threat Model (STRIDE)](THREAT_MODEL.md)
- [API Reference](API.md)
- [CLI Reference](CLI.md)
- [Configuration Guide](CONFIGURATION.md)
- [Security Testing & Benchmarks](SECURITY_TESTING.md)
- [Incident Response](INCIDENT_RESPONSE.md)

---

## License

Original code licensed under the MIT License. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [ATTRIBUTION.md](ATTRIBUTION.md) for research citations.
