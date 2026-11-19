# AgentShield Ultimate: Security Design Specification

**Classification**: Core Security Specification  
**Version**: 1.0.0  

---

## 1. Zero-Trust Enforcement Principles

1. **Explicit Identity & Authorization**: Every action attempted by an AI agent carries an explicit request context (actor, requested resource, operation type, arguments, timestamp).
2. **Deterministic Pre-Execution Gates**: Security policies are evaluated prior to side-effect execution. Post-execution checks are insufficient to prevent irreversible actions.
3. **Fail-Closed Architecture**: Any uncertainty in policy matching, parameter parsing, or human approval verification results in an immediate denial.
4. **Least Privilege by Default**: File access is restricted strictly to designated workspace directories; network egress is blocked by default unless explicitly allowed; destructive shell commands require approval.

---

## 2. Risk Classification Model

Every security finding in AgentShield Ultimate is structured with standardized metadata:

```typescript
export interface SecurityFinding {
  id: string;               // e.g. "SEC-FS-001"
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  confidence: "CERTAIN" | "HIGH" | "MEDIUM" | "LOW";
  category: "CREDENTIAL" | "PROMPT_INJECTION" | "BROWSER" | "FILESYSTEM" | 
            "NETWORK" | "COMMAND" | "MCP" | "SKILL" | "SUPPLY_CHAIN";
  title: string;
  evidence: string;
  affectedResource: string;
  impact: string;
  mitigation: string;
  standardReference: string; // e.g. "OWASP-LLM01 / CWE-78"
  remediationStatus: "OPEN" | "REMEDIATED" | "IGNORED";
}
```

### Risk Scoring Formula (0–100 Scale)

AgentShield Ultimate implements an objective, transparent scoring formula:

$$\text{Base Score} = 100$$
$$\text{Penalty} = \sum (\text{Count}_{\text{CRITICAL}} \times 25) + \sum (\text{Count}_{\text{HIGH}} \times 15) + \sum (\text{Count}_{\text{MEDIUM}} \times 5) + \sum (\text{Count}_{\text{LOW}} \times 1)$$
$$\text{Security Score} = \max(0, \text{Base Score} - \text{Penalty})$$

### Letter Grade Mapping
- **A+ (97–100)**: Pristine configuration; zero findings; strict sandboxing active.
- **A (90–96)**: Strong security posture; zero Critical/High findings.
- **B (80–89)**: Acceptable posture; low/medium findings only.
- **C (70–79)**: Warning level; unmitigated medium/high findings present.
- **D (60–69)**: Dangerous state; high-severity exposure or unverified tools.
- **F (< 60)**: Critical vulnerability; active secret exposure or unauthorized shell execution permitted.

---

## 3. Human-in-the-Loop Approval Protocol

High-risk operations require cryptographic authorization:
1. **Challenge Generation**: The engine produces an approval request containing a SHA-256 digest of the exact action parameters (e.g., target file, destination amount, shell command string).
2. **Time-to-Live (TTL)**: Approvals expire automatically after a configurable window (default: 300 seconds).
3. **Parameter Binding**: The approval token is strictly bound to the action digest. If the agent alters any parameter before execution, the token is invalidated.
4. **Offline / Unattended Fallback**: If no human response is received, the action is aborted without side effects.
