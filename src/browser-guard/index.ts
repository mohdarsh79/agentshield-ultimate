import { SecurityFinding, AgentActionContext, SecurityEvaluationResult } from "../types";

export interface BrowserValidationResult {
  allowed: boolean;
  isAdOrSponsored: boolean;
  isPhishing: boolean;
  reason?: string;
  finding?: SecurityFinding;
}

export class BrowserGuard {
  // Disallowed URL schemes that bypass HTTP controls or trigger script execution
  private static readonly DISALLOWED_SCHEMES = new Set([
    "javascript:",
    "data:",
    "file:",
    "blob:",
    "about:",
    "vbscript:",
    "ftp:"
  ]);

  private static readonly AD_TRACKING_DOMAINS = [
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "adnxs.com",
    "advertising.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "scorecardresearch.com"
  ];

  private static readonly SUSPICIOUS_TLDS = [
    ".zip",
    ".mov",
    ".top",
    ".xyz",
    ".work",
    ".click",
    ".loan"
  ];

  private static readonly REDIRECT_PARAM_KEYS = [
    "url",
    "redirect",
    "target",
    "dest",
    "destination",
    "next",
    "forward"
  ];

  public static evaluateBrowserAction(ctx: AgentActionContext): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    const targetUrl = String(ctx.parameters?.url || ctx.target);

    // 1. URL Protocol & Navigation Security
    if (ctx.actionType === "browser_navigate" || targetUrl.startsWith("http") || targetUrl.includes("://") || targetUrl.startsWith("javascript:")) {
      const valRes = this.validateUrl(targetUrl);
      if (!valRes.allowed) {
        if (valRes.finding) findings.push(valRes.finding);
        return {
          allowed: false,
          blockedReason: valRes.reason || "Browser navigation blocked by security policy",
          findings,
          scorePenalty: valRes.isPhishing ? 25 : 15
        };
      }
    }

    // 2. Element Selector & Form Phishing Defense
    if (ctx.actionType === "browser_click") {
      const clickTarget = (String(ctx.target || "") + " " + JSON.stringify(ctx.parameters || {})).toLowerCase();
      const adMarkers = ["ad-container", "sponsored", "commercial_unit", "googleads", "doubleclick", "promo-card", "ads-ad"];
      const matched = adMarkers.some(m => clickTarget.includes(m));
      if (matched) {
        const finding: SecurityFinding = {
          id: `FIND-BRW-AD-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "HIGH",
          category: "BROWSER",
          title: "Ad/Sponsored Element Click Blocked",
          evidence: `Attempted browser click on advertising or sponsored element: "${ctx.target}"`,
          affectedResource: String(ctx.target),
          impact: "Autonomous navigation to third-party ad networks or click hijacking.",
          mitigation: "Prohibit autonomous agent interaction with advertising nodes.",
          standardReference: "OWASP-LLM02 / Browser Security",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: "Autonomous interaction with advertising or sponsored content is prohibited",
          findings,
          scorePenalty: 15
        };
      }
    }

    if (ctx.actionType === "browser_fill_form") {
      const fieldName = String(ctx.parameters?.field || "").toLowerCase();
      const fieldValue = String(ctx.parameters?.value || "");

      if (fieldName.includes("password") || fieldName.includes("cvv") || fieldName.includes("ssn")) {
        const finding: SecurityFinding = {
          id: `FIND-BRW-CRED-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "HIGH",
          category: "BROWSER",
          title: "Sensitive Credential Autofill Blocked",
          evidence: `Agent attempted to autonomously populate sensitive field '${fieldName}'.`,
          affectedResource: targetUrl,
          impact: "Autonomous submission of user secrets or credentials to unverified web forms.",
          mitigation: "Require explicit human authorization before filling credentials.",
          standardReference: "OWASP-LLM02 / Credential Protection",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Autonomous entry into sensitive field '${fieldName}' requires human approval`,
          findings,
          scorePenalty: 20
        };
      }
    }

    return { allowed: true, findings, scorePenalty: 0 };
  }

  public static validateUrl(urlStr: string): BrowserValidationResult {
    try {
      const trimmed = urlStr.trim();
      const lower = trimmed.toLowerCase();

      // 1. Protocol / Scheme Allowlist Check (Reject javascript:, data:, file:, etc.)
      for (const scheme of this.DISALLOWED_SCHEMES) {
        if (lower.startsWith(scheme)) {
          return {
            allowed: false,
            isAdOrSponsored: false,
            isPhishing: true,
            reason: `Disallowed browser URL scheme '${scheme}' blocked (only http/https permitted)`,
            finding: {
              id: `FIND-BRW-SCHEME-${Date.now().toString(36)}`,
              severity: "CRITICAL",
              confidence: "CERTAIN",
              category: "BROWSER",
              title: "Dangerous Browser URL Scheme Blocked",
              evidence: `Attempted browser navigation to script or local resource: "${urlStr}"`,
              affectedResource: urlStr,
              impact: "Cross-site scripting (XSS), script execution, or arbitrary local file disclosure.",
              mitigation: "Strictly restrict browser navigation to http: and https: protocols.",
              standardReference: "CWE-79 / XSS & Script Execution",
              remediationStatus: "OPEN",
              timestamp: new Date().toISOString()
            }
          };
        }
      }

      const parsed = new URL(trimmed);

      // Verify protocol is strictly http or https
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return {
          allowed: false,
          isAdOrSponsored: false,
          isPhishing: true,
          reason: `Unsupported URL protocol '${parsed.protocol}' (only http: and https: permitted)`
        };
      }

      const hostname = parsed.hostname.toLowerCase();

      // 2. Multi-label Punycode & Homograph Detection (checks all hostname labels)
      const labels = hostname.split(".");
      const hasPunycodeLabel = labels.some(lbl => lbl.startsWith("xn--"));
      const hasNonAscii = /[^\u0000-\u007F]/.test(hostname);

      if (hasPunycodeLabel || hasNonAscii) {
        return {
          allowed: false,
          isAdOrSponsored: false,
          isPhishing: true,
          reason: `Potential IDN Homograph / Punycode phishing detected in domain label: ${hostname}`,
          finding: {
            id: `FIND-BRW-HOMO-${Date.now().toString(36)}`,
            severity: "CRITICAL",
            confidence: "HIGH",
            category: "BROWSER",
            title: "Punycode / Homograph Domain Detected",
            evidence: `Domain '${hostname}' utilizes internationalized punycode label(s) resembling legitimate brand origins.`,
            affectedResource: urlStr,
            impact: "High probability of credential harvesting or brand spoofing.",
            mitigation: "Block connection and require human verification of genuine domain.",
            standardReference: "CWE-451 / RFC-5890",
            remediationStatus: "OPEN",
            timestamp: new Date().toISOString()
          }
        };
      }

      // 3. Ad Tracking Networks Defense
      const isAdDomain = this.AD_TRACKING_DOMAINS.some(ad => hostname.endsWith(ad));
      if (isAdDomain) {
        return {
          allowed: false,
          isAdOrSponsored: true,
          isPhishing: false,
          reason: `Navigation to known ad/tracking network blocked: ${hostname}`
        };
      }

      // 4. Inspect Embedded Open-Redirect Parameters
      for (const paramKey of this.REDIRECT_PARAM_KEYS) {
        const destParam = parsed.searchParams.get(paramKey);
        if (destParam && (destParam.startsWith("http://") || destParam.startsWith("https://") || destParam.startsWith("javascript:"))) {
          const nestedCheck = this.validateUrl(destParam);
          if (!nestedCheck.allowed) {
            return {
              allowed: false,
              isAdOrSponsored: nestedCheck.isAdOrSponsored,
              isPhishing: nestedCheck.isPhishing,
              reason: `Open redirect target violates security policy: ${nestedCheck.reason}`,
              finding: nestedCheck.finding
            };
          }
        }
      }

      // 5. Fake Login URL / Phishing heuristic
      if (parsed.pathname.includes("login") || parsed.pathname.includes("signin")) {
        const isSuspiciousTLD = this.SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
        if (isSuspiciousTLD) {
          return {
            allowed: false,
            isAdOrSponsored: false,
            isPhishing: true,
            reason: `Suspicious login target on high-risk TLD (${hostname})`,
            finding: {
              id: `FIND-BRW-PHISH-${Date.now().toString(36)}`,
              severity: "CRITICAL",
              confidence: "HIGH",
              category: "BROWSER",
              title: "Suspicious Authentication Endpoint",
              evidence: `Target '${urlStr}' attempts to host an authentication flow on a high-risk TLD.`,
              affectedResource: urlStr,
              impact: "Severe risk of agent credential leakage or session hijacking.",
              mitigation: "Enforce domain allowlisting for any agent authentication actions.",
              standardReference: "OWASP-LLM02 / CWE-200",
              remediationStatus: "OPEN",
              timestamp: new Date().toISOString()
            }
          };
        }
      }

      return { allowed: true, isAdOrSponsored: false, isPhishing: false };
    } catch {
      return {
        allowed: false,
        isAdOrSponsored: false,
        isPhishing: false,
        reason: `Malformed or unparseable target URL: ${urlStr}`
      };
    }
  }
}
