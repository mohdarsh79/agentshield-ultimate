import * as dns from "dns";
import { SecurityFinding, AgentActionContext, SecurityEvaluationResult } from "../types";

export interface NetworkPolicyOptions {
  allowLocalhost?: boolean;
  allowedPorts?: number[];
  disallowedIps?: string[];
}

export class NetworkGuard {
  private static readonly METADATA_HOSTNAMES = [
    "instance-data",
    "metadata.google.internal",
    "metadata.azure.internal",
    "169.254.169.254",
    "100.100.100.200", // Alibaba Cloud metadata
    "fd00:ec2::254"     // AWS IPv6 metadata
  ];

  private static readonly ALLOWED_SCHEMES = new Set(["http:", "https:"]);

  public static evaluateRequest(
    ctx: AgentActionContext, 
    options: NetworkPolicyOptions = { allowLocalhost: false }
  ): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    const targetUrl = String(ctx.parameters?.url || ctx.target).trim();

    try {
      const parsed = new URL(targetUrl);

      // 0. Enforce HTTP/HTTPS Protocol Allowlist (Reject file:, ftp:, gopher:, etc.)
      if (!this.ALLOWED_SCHEMES.has(parsed.protocol)) {
        const finding: SecurityFinding = {
          id: `FIND-NET-SCHEME-${Date.now().toString(36)}`,
          severity: "CRITICAL",
          confidence: "CERTAIN",
          category: "NETWORK",
          title: "Non-HTTP Protocol Egress Blocked",
          evidence: `Agent attempted network request with disallowed protocol '${parsed.protocol}' in URL: ${targetUrl}`,
          affectedResource: targetUrl,
          impact: "Arbitrary local file disclosure (file://) or protocol-level SSRF pivoting.",
          mitigation: "Strictly restrict autonomous network egress to http: and https: protocols.",
          standardReference: "CWE-918 / Protocol Smuggling",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Unsupported or dangerous URL protocol '${parsed.protocol}' (only http: and https: permitted)`,
          findings,
          scorePenalty: 25
        };
      }

      const rawHostname = parsed.hostname.toLowerCase();
      const normalizedIp = this.normalizeIpAddress(rawHostname);

      // 1. Cloud Instance Metadata Endpoint Defense (Critical SSRF)
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

      // 2. Loopback Address Protection
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

      // 4. Port Restrictions
      const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === "https:" ? 443 : 80);
      const allowedPorts = options.allowedPorts || [80, 443, 8080, 8443];
      if (!allowedPorts.includes(port)) {
        const finding: SecurityFinding = {
          id: `FIND-NET-PORT-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "CERTAIN",
          category: "NETWORK",
          title: "Non-Standard Network Port Blocked",
          evidence: `Target URL specifies port ${port}, which is outside permitted egress ports.`,
          affectedResource: targetUrl,
          impact: "Outbound communication on unexpected ports may indicate C2 beaconing or internal exploitation.",
          mitigation: "Restrict agent network outbound traffic strictly to standard web ports (80, 443).",
          standardReference: "Perimeter Security / Port Restrictions",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        };
        findings.push(finding);
        return {
          allowed: false,
          blockedReason: `Access to port ${port} is prohibited by network security policy`,
          findings,
          scorePenalty: 15
        };
      }

      return { allowed: true, findings, scorePenalty: 0 };
    } catch {
      return {
        allowed: false,
        blockedReason: `Malformed or unparseable target URL: ${targetUrl}`,
        findings,
        scorePenalty: 10
      };
    }
  }

  // Asynchronous Network Evaluation with Live DNS Resolution & Pinning
  public static async evaluateRequestAsync(
    ctx: AgentActionContext,
    options: NetworkPolicyOptions = { allowLocalhost: false }
  ): Promise<SecurityEvaluationResult> {
    const syncResult = this.evaluateRequest(ctx, options);
    if (!syncResult.allowed) return syncResult;

    const targetUrl = String(ctx.parameters?.url || ctx.target).trim();
    try {
      const parsed = new URL(targetUrl);
      const hostname = parsed.hostname.toLowerCase();

      // If already IP literal, synchronous evaluateRequest covers it
      if (this.isIpLiteral(hostname)) {
        return syncResult;
      }

      // Perform live DNS lookup across A and AAAA records to eliminate DNS rebinding attacks
      const addresses = await dns.promises.lookup(hostname, { all: true });

      for (const record of addresses) {
        const ip = record.address;
        const normalizedIp = this.normalizeIpAddress(ip) || ip;

        // Check if DNS resolved to private IP (RFC-1918)
        if (this.isPrivateIp(normalizedIp)) {
          return {
            allowed: false,
            blockedReason: `DNS resolution for ${hostname} resolved to forbidden private IP: ${ip}`,
            findings: [{
              id: `FIND-NET-DNS-SSRF-${Date.now().toString(36)}`,
              severity: "CRITICAL",
              confidence: "CERTAIN",
              category: "NETWORK",
              title: "DNS Rebinding / SSRF to Private IP Blocked",
              evidence: `Domain '${hostname}' resolved via DNS to private network address '${ip}'.`,
              affectedResource: targetUrl,
              impact: "Bypasses hostname-based SSRF filters via attacker-controlled DNS rebinding.",
              mitigation: "Pin resolved IP and enforce perimeter policy on actual socket destination.",
              standardReference: "CWE-918 / SSRF via DNS Rebinding",
              remediationStatus: "OPEN",
              timestamp: new Date().toISOString()
            }],
            scorePenalty: 25
          };
        }

        // Check if DNS resolved to cloud metadata or link-local address
        if (this.isLinkLocal(normalizedIp) || normalizedIp === "169.254.169.254") {
          return {
            allowed: false,
            blockedReason: `DNS resolution for ${hostname} resolved to cloud instance metadata: ${ip}`,
            findings: [{
              id: `FIND-NET-DNS-META-${Date.now().toString(36)}`,
              severity: "CRITICAL",
              confidence: "CERTAIN",
              category: "NETWORK",
              title: "DNS Resolution to Cloud Metadata Blocked",
              evidence: `Domain '${hostname}' resolved to link-local metadata address '${ip}'.`,
              affectedResource: targetUrl,
              impact: "Instance credential theft via deceptive DNS record resolution.",
              mitigation: "Drop DNS answers resolving to 169.254.0.0/16.",
              standardReference: "CWE-918 / Cloud Metadata SSRF",
              remediationStatus: "OPEN",
              timestamp: new Date().toISOString()
            }],
            scorePenalty: 25
          };
        }

        // Check if DNS resolved to loopback
        if ((normalizedIp === "127.0.0.1" || normalizedIp.startsWith("127.") || normalizedIp === "::1") && !options.allowLocalhost) {
          return {
            allowed: false,
            blockedReason: `DNS resolution for ${hostname} resolved to local loopback interface: ${ip}`,
            findings: [{
              id: `FIND-NET-DNS-LOOP-${Date.now().toString(36)}`,
              severity: "HIGH",
              confidence: "CERTAIN",
              category: "NETWORK",
              title: "DNS Resolution to Loopback Blocked",
              evidence: `Domain '${hostname}' resolved to 127.0.0.1 loopback address.`,
              affectedResource: targetUrl,
              impact: "Access to internal host services via public domain DNS pointing to localhost.",
              mitigation: "Disallow loopback addresses in public DNS resolutions.",
              standardReference: "CWE-918",
              remediationStatus: "OPEN",
              timestamp: new Date().toISOString()
            }],
            scorePenalty: 20
          };
        }
      }

      return syncResult;
    } catch {
      return syncResult;
    }
  }

  private static isIpLiteral(str: string): boolean {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(str) || str.includes(":");
  }

  private static isPrivateIp(ip: string): boolean {
    // IPv4 RFC 1918 & Carrier-grade NAT
    const parts = ip.split(".").map(Number);
    if (parts.length === 4 && parts.every(n => !isNaN(n))) {
      if (parts[0] === 10) return true;
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
      if (parts[0] === 192 && parts[1] === 168) return true;
      if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true; // CGNAT
    }

    // IPv6 Unique Local Address (fc00::/7) and Link-Local (fe80::/10)
    if (ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80")) return true;
    return false;
  }

  private static isLinkLocal(ip: string): boolean {
    return ip.startsWith("169.254.") || ip.startsWith("fe80:");
  }

  private static normalizeIpAddress(hostname: string): string | null {
    let clean = hostname.replace(/^\[|\]$/g, "");
    if (clean.startsWith("::ffff:")) {
      clean = clean.substring(7);
      if (/^[0-9a-f]{1,4}:[0-9a-f]{1,4}$/i.test(clean)) {
        const sub = clean.split(":");
        const p1 = parseInt(sub[0], 16);
        const p2 = parseInt(sub[1], 16);
        return `${(p1 >> 8) & 0xff}.${p1 & 0xff}.${(p2 >> 8) & 0xff}.${p2 & 0xff}`;
      }
    }
    return clean;
  }
}
