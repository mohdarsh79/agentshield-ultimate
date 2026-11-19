import { SecurityFinding, AgentActionContext, SecurityEvaluationResult } from "../types";

export interface NetworkPolicyOptions {
  allowLocalhost?: boolean;
  allowedDomains?: string[];
  blockedDomains?: string[];
}

export class NetworkGuard {
  // Cloud Metadata IPs & Hostnames
  private static readonly METADATA_HOSTNAMES = [
    "metadata.google.internal",
    "metadata.internal"
  ];

  public static evaluateRequest(
    ctx: AgentActionContext, 
    options: NetworkPolicyOptions = { allowLocalhost: false }
  ): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    const targetUrl = String(ctx.parameters?.url || ctx.target);

    try {
      const parsed = new URL(targetUrl);
      const rawHostname = parsed.hostname.toLowerCase();
      const normalizedIp = this.normalizeIpAddress(rawHostname);

      // 1. Cloud Instance Metadata Endpoint Defense (Critical SSRF)
      // Catches 169.254.169.254, 169.254.0.0/16 link-local, fd00:ec2::254, 100.100.100.200, or wildcard domains
      const isCloudMetadata = 
        this.METADATA_HOSTNAMES.includes(rawHostname) ||
        rawHostname.includes("169.254.169.254") ||
        rawHostname.includes("metadata.google.internal") ||
        (normalizedIp && this.isLinkLocal(normalizedIp)) ||
        normalizedIp === "169.254.169.254" ||
        normalizedIp === "100.100.100.200" ||
        normalizedIp === "fd00:ec2::254";

      if (isCloudMetadata) {
        const finding: SecurityFinding = {
          id: `FIND-NET-META-${Date.now().toString(36)}`,
          severity: "CRITICAL",
          confidence: "CERTAIN",
          category: "NETWORK",
          title: "Cloud Metadata SSRF Target Blocked",
          evidence: `Connection target '${targetUrl}' attempts to query cloud metadata service.`,
          affectedResource: targetUrl,
          impact: "Exfiltration of instance IAM credentials, service account tokens, and cloud environment secrets.",
          mitigation: "Strictly block agent access to link-local metadata address 169.254.169.254 and metadata domains.",
          standardReference: "CWE-918 / OWASP-LLM06 / MITRE-AML.T0043",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Blocked cloud instance metadata access: ${rawHostname}`,
          findings,
          scorePenalty: 25
        };
      }

      // 2. Loopback Address Protection (unless specifically permitted in local dev)
      const isLoopback = 
        rawHostname === "localhost" || 
        rawHostname.includes("127.0.0.1") ||
        rawHostname === "0.0.0.0" || 
        normalizedIp === "::1" || 
        normalizedIp === "127.0.0.1" || 
        (normalizedIp && normalizedIp.startsWith("127."));

      if (isLoopback && !options.allowLocalhost) {
        const finding: SecurityFinding = {
          id: `FIND-NET-LOOP-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "CERTAIN",
          category: "NETWORK",
          title: "Loopback Network Access Blocked",
          evidence: `Agent attempted network access to local loopback interface: ${rawHostname}`,
          affectedResource: targetUrl,
          impact: "Unintended access to local internal developer daemons or unauthenticated services.",
          mitigation: "Prohibit loopback egress unless explicitly configured in dev profile.",
          standardReference: "CWE-918 / SSRF Defense",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Local loopback egress blocked by zero-trust network policy: ${rawHostname}`,
          findings,
          scorePenalty: 15
        };
      }

      // 3. RFC-1918 Private Subnet Detection
      if (normalizedIp && this.isPrivateIp(normalizedIp)) {
        const finding: SecurityFinding = {
          id: `FIND-NET-RFC1918-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "HIGH",
          category: "NETWORK",
          title: "Private Subnet Egress Blocked (RFC 1918)",
          evidence: `IP '${normalizedIp}' belongs to private internal corporate subnet range.`,
          affectedResource: targetUrl,
          impact: "Internal network port scanning and pivot through corporate infrastructure.",
          mitigation: "Enforce perimeter gateway filtering for autonomous agents.",
          standardReference: "CWE-918 / RFC-1918",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Egress to internal private IP subnet blocked: ${normalizedIp}`,
          findings,
          scorePenalty: 15
        };
      }

      // 4. Blocklist Validation
      if (options.blockedDomains && options.blockedDomains.some(d => rawHostname.endsWith(d))) {
        return {
          allowed: false,
          blockedReason: `Domain is explicitly blacklisted: ${rawHostname}`,
          findings,
          scorePenalty: 10
        };
      }

      // 5. Allowlist Validation (if configured)
      if (options.allowedDomains && options.allowedDomains.length > 0) {
        const isAllowed = options.allowedDomains.some(d => rawHostname === d || rawHostname.endsWith("." + d));
        if (!isAllowed) {
          return {
            allowed: false,
            blockedReason: `Domain is not present in designated allowlist: ${rawHostname}`,
            findings,
            scorePenalty: 10
          };
        }
      }

      return { allowed: true, findings, scorePenalty: 0 };
    } catch {
      return {
        allowed: false,
        blockedReason: `Malformed or unparseable target URL: ${targetUrl}`,
        findings,
        scorePenalty: 5
      };
    }
  }

  // Normalizes IPv6-mapped IPv4, brackets, hex/octal representations
  private static normalizeIpAddress(hostname: string): string | null {
    let clean = hostname.replace(/[\[\]]/g, "").trim().toLowerCase();

    // Check for IPv6-mapped IPv4 (::ffff:169.254.169.254 or ::ffff:a9fe:a9fe)
    if (clean.startsWith("::ffff:")) {
      const rest = clean.substring(7);
      if (rest.includes(".")) {
        return rest;
      }
      // Hex representation e.g. a9fe:a9fe
      const hexParts = rest.split(":");
      if (hexParts.length === 2 && hexParts[0].length === 4 && hexParts[1].length === 4) {
        const p1 = parseInt(hexParts[0].substring(0, 2), 16);
        const p2 = parseInt(hexParts[0].substring(2, 4), 16);
        const p3 = parseInt(hexParts[1].substring(0, 2), 16);
        const p4 = parseInt(hexParts[1].substring(2, 4), 16);
        return `${p1}.${p2}.${p3}.${p4}`;
      }
    }

    return clean;
  }

  private static isLinkLocal(ip: string): boolean {
    const parts = ip.split(".").map(Number);
    if (parts.length === 4 && parts[0] === 169 && parts[1] === 254) {
      return true;
    }
    return false;
  }

  private static isPrivateIp(ip: string): boolean {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return false;

    // 10.0.0.0 - 10.255.255.255
    if (parts[0] === 10) return true;
    // 172.16.0.0 - 172.31.255.255
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0 - 192.168.255.255
    if (parts[0] === 192 && parts[1] === 168) return true;

    return false;
  }
}
