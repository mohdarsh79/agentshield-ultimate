import { SecurityFinding, AgentActionContext, SecurityEvaluationResult } from "../types";

export interface BrowserValidationResult {
  allowed: boolean;
  reason?: string;
  isAdOrSponsored: boolean;
  isPhishing: boolean;
  finding?: SecurityFinding;
}

export class BrowserGuard {
  // Known advertising and sponsored class names / IDs / attributes in modern search engines & websites
  private static readonly AD_INDICATORS = [
    "ad-container", "sponsored", "commercial_unit", "googleads", "doubleclick",
    "ad-slot", "ad-banner", "ad-wrapper", "ad_unit", "promo-box", "sponsored-result",
    "pla-unit", "ads-ad", "ad-badge", "ad_badge", "ad-feedback", "carbon-ads"
  ];

  // Malicious / Phishing TLDs and known malicious domains
  private static readonly SUSPICIOUS_TLDS = [
    ".zip", ".mov", ".top", ".xyz", ".country", ".kim", ".work", ".gdn", ".click"
  ];

  // Tracking and Ad Network Domains
  private static readonly AD_TRACKING_DOMAINS = [
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "adnxs.com", "criteo.com", "outbrain.com", "taboola.com", "scorecardresearch.com"
  ];

  // Common Open-Redirect parameter names
  private static readonly REDIRECT_PARAM_KEYS = [
    "url", "redirect", "dest", "destination", "target", "next", "u", "r"
  ];

  public static evaluateBrowserAction(ctx: AgentActionContext): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];

    if (ctx.actionType === "browser_click") {
      const clickTarget = (ctx.target + " " + JSON.stringify(ctx.parameters)).toLowerCase();
      
      // 1. Strict Ad & Sponsored Element Check
      const matchedAdIndicator = this.AD_INDICATORS.find(ind => clickTarget.includes(ind));
      if (matchedAdIndicator) {
        const finding: SecurityFinding = {
          id: `FIND-BRW-AD-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "CERTAIN",
          category: "BROWSER",
          title: "Advertisement / Sponsored Link Click Blocked",
          evidence: `Element matches ad/sponsored selector indicator: '${matchedAdIndicator}'`,
          affectedResource: ctx.target,
          impact: "Prevents autonomous agent from clicking malicious or commercial sponsored links.",
          mitigation: "Instruct agent to focus strictly on organic, non-advertising web elements.",
          standardReference: "OWASP-Agentic / Zero-Trust Ad Policy",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Autonomous click blocked: Target element is identified as advertising or sponsored content (${matchedAdIndicator})`,
          findings,
          scorePenalty: 15
        };
      }
    }

    if (ctx.actionType === "browser_navigate" || ctx.parameters?.url) {
      const urlStr = String(ctx.parameters?.url || ctx.target);
      const urlCheck = this.validateUrl(urlStr);
      if (!urlCheck.allowed) {
        if (urlCheck.finding) findings.push(urlCheck.finding);
        return {
          allowed: false,
          blockedReason: urlCheck.reason,
          findings,
          scorePenalty: 25
        };
      }
    }

    return { allowed: true, findings, scorePenalty: 0 };
  }

  public static validateUrl(urlStr: string): BrowserValidationResult {
    try {
      const parsed = new URL(urlStr);
      const hostname = parsed.hostname.toLowerCase();

      // 1. Check for Homograph / Punycode Attacks
      if (hostname.startsWith("xn--") || /[^\u0000-\u007F]/.test(hostname)) {
        return {
          allowed: false,
          isAdOrSponsored: false,
          isPhishing: true,
          reason: `Potential IDN Homograph / Phishing spoofing detected: ${hostname}`,
          finding: {
            id: `FIND-BRW-HOMO-${Date.now().toString(36)}`,
            severity: "CRITICAL",
            confidence: "HIGH",
            category: "BROWSER",
            title: "Punycode / Homograph Domain Detected",
            evidence: `Domain '${hostname}' utilizes internationalized characters resembling trusted origins.`,
            affectedResource: urlStr,
            impact: "High probability of credential harvesting or malware staging.",
            mitigation: "Block connection and require human verification of genuine domain.",
            standardReference: "CWE-451 / RFC-5890",
            remediationStatus: "OPEN",
            timestamp: new Date().toISOString()
          }
        };
      }

      // 2. Check for Ad Tracking Networks
      const isAdDomain = this.AD_TRACKING_DOMAINS.some(ad => hostname.endsWith(ad));
      if (isAdDomain) {
        return {
          allowed: false,
          isAdOrSponsored: true,
          isPhishing: false,
          reason: `Navigation to known ad/tracking network blocked: ${hostname}`
        };
      }

      // 3. Inspect Embedded Open-Redirect Parameters
      for (const paramKey of this.REDIRECT_PARAM_KEYS) {
        const destParam = parsed.searchParams.get(paramKey);
        if (destParam && (destParam.startsWith("http://") || destParam.startsWith("https://"))) {
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

      // 4. Fake Login URL / Password Phishing heuristic
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
        reason: `Malformed URL string: ${urlStr}`
      };
    }
  }
}
