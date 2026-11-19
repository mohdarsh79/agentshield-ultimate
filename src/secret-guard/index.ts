import { SecurityFinding } from "../types";

export interface SecretScanResult {
  hasSecrets: boolean;
  redactedText: string;
  findings: SecurityFinding[];
}

export class SecretGuard {
  // Production Regex Patterns for Credentials and Tokens
  private static readonly SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
    { name: "AWS Access Key ID", regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g },
    { name: "AWS Secret Access Key", regex: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi },
    { name: "GitHub Personal Access Token", regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g },
    { name: "GitHub Fine-Grained Token", regex: /\bgithub_pat_[0-9a-zA-Z_]{82}\b/g },
    { name: "OpenAI API Key", regex: /\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{20,}\b/g },
    { name: "Slack Bot Token", regex: /\bxoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}\b/g },
    { name: "Slack User Token", regex: /\bxoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}\b/g },
    { name: "Google API Key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
    { name: "Stripe Live API Key", regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
    { name: "Stripe Restricted API Key", regex: /\brk_live_[0-9a-zA-Z]{24,}\b/g },
    { name: "RSA / OpenSSH Private Key Header", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
    { name: "JSON Web Token (JWT)", regex: /\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b/g },
    { name: "Generic Bearer Token Header", regex: /Bearer\s+[A-Za-z0-9\-_.~+/]+=*/gi },
    { name: "Generic High-Entropy Password Assignment", regex: /(?:password|passwd|pwd|secret)\s*[:=]\s*["']([^\s"']{8,})["']/gi }
  ];

  public static scanAndRedact(text: string, resourceName: string = "runtime_stream"): SecretScanResult {
    let redacted = text;
    const findings: SecurityFinding[] = [];
    let hasSecrets = false;

    for (const pat of this.SECRET_PATTERNS) {
      const matches = text.match(pat.regex);
      if (matches && matches.length > 0) {
        hasSecrets = true;
        findings.push({
          id: `FIND-SEC-TOKEN-${Date.now().toString(36)}`,
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
        redacted = redacted.replace(pat.regex, `[REDACTED_${pat.name.replace(/\s+/g, "_").toUpperCase()}]`);
      }
    }

    return {
      hasSecrets,
      redactedText: redacted,
      findings
    };
  }

  public static isSecret(value: string): boolean {
    return this.SECRET_PATTERNS.some(pat => pat.regex.test(value));
  }
}
