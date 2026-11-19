import { SecurityFinding, AgentActionContext, SecurityEvaluationResult, Severity } from "../types";

export class CommandGuard {
  private static readonly CRITICAL_COMMANDS: Array<{ regex: RegExp; name: string; severity: Severity; impact: string }> = [
    { regex: /\brm\s+(-rf|-fr)\s+(\/|~|\$HOME|\*)/i, name: "Root/Home Recursive Deletion", severity: "CRITICAL", impact: "Total filesystem destruction." },
    { regex: /:(){ :\|:& };:/, name: "Bash Fork Bomb", severity: "CRITICAL", impact: "Denial of service via resource exhaustion." },
    { regex: /\bmkfs(\.[a-z0-9]+)?\s+/i, name: "Filesystem Formatting Command", severity: "CRITICAL", impact: "Destroys drive partition contents." },
    { regex: /\bdd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\//i, name: "Raw Disk Overwrite Command", severity: "CRITICAL", impact: "Destructive disk destruction." },
    { regex: /\b(nc|netcat)\s+.*-e\s+\/bin\/(ba)?sh/i, name: "Netcat Reverse Shell", severity: "CRITICAL", impact: "Exposes interactive host shell to remote attacker." },
    { regex: /\bcurl\s+[^|\n]+\|\s*(ba|z)?sh/i, name: "Uninspected Remote Script Pipeline", severity: "CRITICAL", impact: "Executes unverified remote script with local permissions." }
  ];

  // Metacharacters used for command injection and command chaining
  private static readonly FORBIDDEN_CHAINING_PATTERNS = [
    /;/g,
    /&&/g,
    /\|\|/g,
    /\|/g,
    /`/g,
    /\$\(/g,
    /\r/g,
    /\n/g,
    // Single & when not preceded or followed by & or >
    /(?<![&>])&(?!&)/g
  ];

  public static evaluateCommand(ctx: AgentActionContext, allowShellChaining: boolean = false): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    const command = String(ctx.parameters?.command || ctx.target);

    // 1. Critical Destructive Command Check
    for (const pat of this.CRITICAL_COMMANDS) {
      const match = command.match(pat.regex);
      if (match) {
        const finding: SecurityFinding = {
          id: `FIND-CMD-CRIT-${Date.now().toString(36)}`,
          severity: pat.severity,
          confidence: "CERTAIN",
          category: "COMMAND",
          title: `Dangerous System Command Blocked: ${pat.name}`,
          evidence: `Command line contains signature: "${match[0]}"`,
          affectedResource: "os:command_line",
          impact: pat.impact,
          mitigation: "Remove destructive system operations from agent capabilities.",
          standardReference: "CWE-78 / OWASP-LLM06",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Dangerous shell execution blocked: ${pat.name}`,
          findings,
          scorePenalty: 25
        };
      }
    }

    // 2. Uncontrolled Shell Injection Chaining Check (including single &, ;, |, newlines)
    if (!allowShellChaining) {
      const matchedPattern = this.FORBIDDEN_CHAINING_PATTERNS.find(pat => pat.test(command));
      if (matchedPattern) {
        const finding: SecurityFinding = {
          id: `FIND-CMD-CHAIN-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "MEDIUM",
          category: "COMMAND",
          title: "Shell Command Chaining Metacharacters Detected",
          evidence: `Command string contains forbidden shell chaining or backgrounding operators: "${command}"`,
          affectedResource: "os:command_line",
          impact: "Potential shell injection or hidden secondary command execution.",
          mitigation: "Execute singular atomic commands with structured argument arrays.",
          standardReference: "CWE-78 / Shell Injection",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: "Command chaining, subshells, newlines, and backgrounding operators are prohibited by default",
          findings,
          scorePenalty: 15
        };
      }
    }

    return { allowed: true, findings, scorePenalty: 0 };
  }
}
