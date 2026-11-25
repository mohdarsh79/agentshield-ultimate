# AgentShield Ultimate — Incident Response Procedure

## Overview
This document specifies the incident response procedure for autonomous AI agent security events detected by `agentshield-ultimate`.

## Incident Severity Tiers
1. **P0 (Critical Severity)**
   - Arbitrary shell command injection (`rm -rf`, reverse shells, fork bombs).
   - Direct prompt injection and uncontained jailbreaks attempting exfiltration.
   - Cloud metadata SSRF attempts (`169.254.169.254`).
   - Hardcoded master API credential disclosure.
   - Action: Halt agent process immediately, revoke exposed credentials, quarantine affected skill.

2. **P1 (High Severity)**
   - Workspace boundary path traversal attempts or symlink breakouts.
   - Unauthorized browser credential autofill.
   - Network egress attempts to private RFC-1918 subnets.
   - Action: Fail closed, record audit event, generate cryptographic approval challenge.

3. **P2 (Medium Severity)**
   - Suspicious package lifecycle scripts or unpinned dependencies.
   - Missing `.env` exclusion in `.gitignore`.
   - Action: Apply automated transactional remediation via `agentshield fix`.

## Incident Containment & Recovery Workflow
1. **Identification**: Review tamper-evident audit records using `audit.verifyLogIntegrity()`.
2. **Containment**: Switch agent policy profile to `strict` mode via `agentshield policy strict`.
3. **Eradication**: Remove malicious MCP configurations, corrupted skill files, or hostile prompts.
4. **Recovery**: Verify workspace integrity via `agentshield scan` and run adversarial test suite via `agentshield red-team`.
