import { SecurityFinding } from "../types";

export interface SecretScanResult {
  hasSecrets: boolean;
  redactedText: string;
  findings: SecurityFinding[];
}

export class SecretGuard {
  // Production Regex Patterns for Credentials and Tokens (defined without global flag for safe testing)
  private static readonly SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    { name: "AWS Access Key ID", pattern: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/i },
    { name: "AWS Secret Access Key", pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/i },
    { name: "GitHub Personal Access Token", pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/ },
    { name: "GitHub Fine-Grained Token", pattern: /\bgithub_pat_[0-9a-zA-Z_]{82}\b/ },
    { name: "OpenAI API Key", pattern: /\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{20,}\b/ },
    { name: "Slack Bot Token", pattern: /\bxoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}\b/ },
    { name: "Slack User Token", pattern: /\bxoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}\b/ },
    { name: "Google API Key", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
    { name: "Stripe Live API Key", pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/ },
    { name: "Stripe Restricted API Key", pattern: /\brk_live_[0-9a-zA-Z]{24,}\b/ },
    { name: "RSA / OpenSSH Private Key Header", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
    { name: "JSON Web Token (JWT)", pattern: /\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b/ },
    { name: "Generic Bearer Token Header", pattern: /\bBearer\s+[A-Za-z0-9\-_.~+/]{16,}=*\b/i },
    { name: "Generic High-Entropy Password Assignment", pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*["']([^\s"']{8,})["']/i }
  ];

  public static scanAndRedact(text: string, resourceName: string = "runtime_stream"): SecretScanResult {
    let redacted = text;
    const findings: SecurityFinding[] = [];
    let hasSecrets = false;

    for (const pat of this.SECRET_PATTERNS) {
      // Create global regex dynamically for string replacement
      const globalRegex = new RegExp(pat.pattern.source, pat.pattern.flags.includes("i") ? "gi" : "g");
      const matches = text.match(globalRegex);
      if (matches && matches.length > 0) {
        hasSecrets = true;
        findings.push({
          id: `FIND-SEC-TOKEN-${Date.now().toString(36)}-${findings.length}`,
          severity: "CRITICAL",
          confidence: "CERTAIN",
          category: "CREDENTIAL",
          title: `Exposed Credential Detected: ${pat.name}`,
          evidence: `Detected ${matches.length} instance(s) of credential pattern in ${resourceName}.`,
          affectedResource: resourceName,
          impact: "Unauthorized account takeover, data compromise, and API abuse.",
          mitigation: "Immediately revoke exposed credential and store inside secure environment vault.",
          standardReference: "OWASP-LLM02 / CWE-798",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });

        // Mask match in sanitized stream
        redacted = redacted.replace(globalRegex, `[REDACTED_${pat.name.replace(/\s+/g, "_").toUpperCase()}]`);
      }
    }

    return {
      hasSecrets,
      redactedText: redacted,
      findings
    };
  }

  // Stateless predicate: immune to lastIndex caching across repeated calls
  public static isSecret(value: string): boolean {
    return this.SECRET_PATTERNS.some(pat => {
      const cleanRegex = new RegExp(pat.pattern.source, pat.pattern.flags.replace("g", ""));
      return cleanRegex.test(value);
    });
  }

  // Shannon Entropy Calculator to identify high-entropy random secrets
  public static calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;
    const frequencies: Record<string, number> = {};
    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const count of Object.values(frequencies)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}
