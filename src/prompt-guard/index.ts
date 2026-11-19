import { SecurityFinding, Confidence, Severity } from "../types";

export interface PromptScanResult {
  isSafe: boolean;
  threatType?: string;
  confidence: Confidence;
  findings: SecurityFinding[];
  sanitizedText: string;
}

export class PromptGuard {
  // Direct Injection & Jailbreak Heuristics
  private static readonly DIRECT_INJECTION_PATTERNS: Array<{ regex: RegExp; name: string; severity: Severity }> = [
    { regex: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)/i, name: "System Instruction Override", severity: "CRITICAL" },
    { regex: /system\s+override\b/i, name: "System Override Directive", severity: "CRITICAL" },
    { regex: /disregard\s+(all\s+|any\s+|prior\s+|previous\s+)*(safety|system|operational)\s+(guidelines|filters|boundaries)/i, name: "Safety Bypass Attempt", severity: "CRITICAL" },
    { regex: /you\s+are\s+now\s+(DAN|unconstrained|jailbroken|freed|an\s+unrestricted\s+AI)/i, name: "Jailbreak Persona Switch", severity: "CRITICAL" },
    { regex: /(reveal|print|output|leak|show|dump)\s+(your\s+)?(system\s+prompt|initial\s+instructions|developer\s+mode|internal\s+credentials)/i, name: "System Prompt Extraction", severity: "HIGH" },
    { regex: /assume\s+the\s+role\s+of\s+an\s+evil|unfiltered|malicious\s+assistant/i, name: "Adversarial Role Assumption", severity: "HIGH" },
    { regex: /developer\s+mode\s+(enabled|activated|override)/i, name: "Developer Mode Exploitation", severity: "HIGH" }
  ];

  // Hidden Instruction / Indirect Injection Heuristics
  private static readonly HIDDEN_INSTRUCTION_PATTERNS: Array<{ regex: RegExp; name: string; severity: Severity }> = [
    { regex: /<!--[\s\S]*?(system|instructions|ignore|curl|bash|powershell)[\s\S]*?-->/i, name: "HTML Comment Hidden Instruction", severity: "HIGH" },
    { regex: /\[\/\/\]:\s*#(.*?)(ignore|override|system|secret)/i, name: "Markdown Invisible Comment Injection", severity: "HIGH" },
    { regex: /<script[\s\S]*?>[\s\S]*?<\/script>/i, name: "Embedded Executable Script Tag", severity: "HIGH" },
    { regex: /data:text\/html;base64,[A-Za-z0-9+/=]+/i, name: "Data URI Base64 HTML Injection", severity: "HIGH" }
  ];

  // Zero-width Unicode & Bidirectional Overrides
  private static readonly UNICODE_EVASION_REGEX = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g;

  // Base64-encoded shell command detector
  private static readonly SUSPICIOUS_BASE64_REGEX = /(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

  public static scan(input: string, contextSource: string = "untrusted_input"): PromptScanResult {
    const findings: SecurityFinding[] = [];
    let isSafe = true;
    let threatType: string | undefined;

    // 1. Detect and strip Unicode Evasion (Zero-width characters & Bidi overrides)
    const unicodeMatches = input.match(this.UNICODE_EVASION_REGEX);
    if (unicodeMatches && unicodeMatches.length > 0) {
      findings.push({
        id: `FIND-PROMPT-UNI-${Date.now().toString(36)}`,
        severity: "MEDIUM",
        confidence: "CERTAIN",
        category: "PROMPT_INJECTION",
        title: "Invisible Unicode / Bidi Override Detected",
        evidence: `Found ${unicodeMatches.length} zero-width or bidirectional control characters used for filter evasion.`,
        affectedResource: contextSource,
        impact: "Obfuscates malicious commands from lexical inspection filters.",
        mitigation: "Normalize Unicode representation and strip non-printable directional glyphs.",
        standardReference: "OWASP-LLM01 / CWE-172",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      });
      isSafe = false;
      threatType = "Unicode Evasion";
    }

    // Normalized text representation
    const normalized = input.replace(this.UNICODE_EVASION_REGEX, "");

    // 2. Direct Prompt Injections
    for (const pat of this.DIRECT_INJECTION_PATTERNS) {
      const match = normalized.match(pat.regex);
      if (match) {
        findings.push({
          id: `FIND-PROMPT-DIR-${Date.now().toString(36)}`,
          severity: pat.severity,
          confidence: "HIGH",
          category: "PROMPT_INJECTION",
          title: pat.name,
          evidence: `Matched injection pattern: "${match[0]}"`,
          affectedResource: contextSource,
          impact: "Adversarial prompt attempts to usurp model instructions and override constraints.",
          mitigation: "Drop untrusted input or encapsulate inside strict data delimiters.",
          standardReference: "OWASP-LLM01 / MITRE-AML.T0051",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
        isSafe = false;
        threatType = pat.name;
      }
    }

    // 3. Hidden Instructions & Document Injections
    for (const pat of this.HIDDEN_INSTRUCTION_PATTERNS) {
      const match = normalized.match(pat.regex);
      if (match) {
        findings.push({
          id: `FIND-PROMPT-HID-${Date.now().toString(36)}`,
          severity: pat.severity,
          confidence: "HIGH",
          category: "PROMPT_INJECTION",
          title: pat.name,
          evidence: `Matched hidden payload: "${match[0].substring(0, 100)}"`,
          affectedResource: contextSource,
          impact: "Indirect injection payload embedded in documentation, markdown, or webpage.",
          mitigation: "Sanitize external HTML/Markdown before passing into LLM context.",
          standardReference: "OWASP-LLM01 / MITRE-AML.T0051",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
        isSafe = false;
        threatType = pat.name;
      }
    }

    // 4. Inspect Potential Base64 Encoded Payloads
    const base64Matches = normalized.match(this.SUSPICIOUS_BASE64_REGEX) || [];
    for (const b64 of base64Matches) {
      if (b64.length >= 32) {
        try {
          const decoded = Buffer.from(b64, "base64").toString("utf-8");
          if (/curl|bash|wget|eval|rm\s+-rf|powershell|id_rsa/i.test(decoded)) {
            findings.push({
              id: `FIND-PROMPT-B64-${Date.now().toString(36)}`,
              severity: "CRITICAL",
              confidence: "CERTAIN",
              category: "PROMPT_INJECTION",
              title: "Obfuscated Base64 Shell Payload Detected",
              evidence: `Decoded payload contains dangerous command: ${decoded.substring(0, 80)}`,
              affectedResource: contextSource,
              impact: "Attacker attempting to evade lexical filters using base64 encoding.",
              mitigation: "Quarantine input and forbid execution of dynamic base64 decoders.",
              standardReference: "OWASP-LLM01 / CWE-116",
              remediationStatus: "OPEN",
              timestamp: new Date().toISOString()
            });
            isSafe = false;
            threatType = "Base64 Obfuscated Payload";
          }
        } catch {
          // Ignore invalid base64
        }
      }
    }

    return {
      isSafe,
      threatType,
      confidence: findings.some(f => f.confidence === "CERTAIN") ? "CERTAIN" : "HIGH",
      findings,
      sanitizedText: normalized
    };
  }
}
