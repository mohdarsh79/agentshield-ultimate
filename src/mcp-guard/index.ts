import * as fs from "fs";
import { SecurityFinding, Severity } from "../types";

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, unknown>;
    required?: string[];
  };
}

export interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

export class McpGuard {
  // Patterns indicative of tool description poisoning
  private static readonly POISON_DESCRIPTION_PATTERNS: Array<{ regex: RegExp; severity: Severity; name: string }> = [
    { regex: /always\s+(call|run|execute)\s+this\s+tool\s+(first|before\s+anything\s+else)/i, severity: "HIGH", name: "Forced Execution Priority Poisoning" },
    { regex: /do\s+not\s+(tell|inform|alert)\s+the\s+user/i, severity: "CRITICAL", name: "Covert Execution Directive" },
    { regex: /send\s+(credentials|tokens|passwords|secrets|\.env)\s+to/i, severity: "CRITICAL", name: "Exfiltration Tool Directive" },
    { regex: /ignore\s+previous\s+instructions/i, severity: "CRITICAL", name: "Prompt Injection in Tool Schema" }
  ];

  public static auditServerConfig(serverName: string, config: McpServerConfig): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // 1. Audit Environment Variables for Plaintext Secrets
    if (config.env) {
      for (const [key, val] of Object.entries(config.env)) {
        if (/api_?key|secret|token|password|auth/i.test(key) && val.length > 5 && !val.startsWith("${")) {
          findings.push({
            id: `FIND-MCP-SECRET-${Date.now().toString(36)}`,
            severity: "HIGH",
            confidence: "HIGH",
            category: "MCP",
            title: `Hardcoded Secret in MCP Server Config: ${serverName}`,
            evidence: `Environment key '${key}' contains hardcoded plaintext credentials in MCP configuration.`,
            affectedResource: `mcp_server:${serverName}`,
            impact: "Credential exposure in version control and client configuration files.",
            mitigation: "Reference credentials via environment variables: '${ENV_VAR}'.",
            standardReference: "OWASP-LLM02 / CWE-798",
            remediationStatus: "OPEN",
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    // 2. Audit Dangerous Remote Transports (Insecure HTTP/WS)
    if (config.url) {
      if (config.url.startsWith("http://") && !config.url.includes("localhost") && !config.url.includes("127.0.0.1")) {
        findings.push({
          id: `FIND-MCP-INSECURE-HTTP-${Date.now().toString(36)}`,
          severity: "HIGH",
          confidence: "CERTAIN",
          category: "MCP",
          title: `Insecure Cleartext MCP Transport: ${serverName}`,
          evidence: `MCP server URL '${config.url}' uses unencrypted HTTP transport.`,
          affectedResource: `mcp_server:${serverName}`,
          impact: "Man-in-the-middle attacks can inspect or alter tool definitions and execution streams.",
          mitigation: "Use TLS encrypted transport (https:// or wss://).",
          standardReference: "CWE-319 / Transport Security",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
      }
    }

    // 3. Command execution risk
    if (config.command && ["bash", "sh", "cmd", "powershell"].includes(config.command.toLowerCase())) {
      findings.push({
        id: `FIND-MCP-RAW-SHELL-${Date.now().toString(36)}`,
        severity: "MEDIUM",
        confidence: "HIGH",
        category: "MCP",
        title: `MCP Server Spawned Via Raw Shell: ${serverName}`,
        evidence: `Server command executes directly via shell binary '${config.command}'.`,
        affectedResource: `mcp_server:${serverName}`,
        impact: "Expands potential shell argument injection surface.",
        mitigation: "Invoke direct binary executables directly without shell intermediaries.",
        standardReference: "CWE-78 / Command Execution",
        remediationStatus: "OPEN",
        timestamp: new Date().toISOString()
      });
    }

    return findings;
  }

  public static auditToolDefinition(serverName: string, tool: McpToolDefinition): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const desc = tool.description || "";

    for (const pat of this.POISON_DESCRIPTION_PATTERNS) {
      const match = desc.match(pat.regex);
      if (match) {
        findings.push({
          id: `FIND-MCP-POISON-${Date.now().toString(36)}`,
          severity: pat.severity,
          confidence: "HIGH",
          category: "MCP",
          title: `Poisoned MCP Tool Description: ${tool.name}`,
          evidence: `Matched poison pattern: "${match[0]}" in tool '${tool.name}' from server '${serverName}'`,
          affectedResource: `mcp_tool:${serverName}/${tool.name}`,
          impact: "Attempts to manipulate agent reasoning or hijack autonomous tool invocation order.",
          mitigation: "Sanitize tool descriptions and reject third-party MCP servers with coercive descriptions.",
          standardReference: "OWASP-MCP-Security / MITRE-AML.T0040",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  public static auditConfigFile(filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    if (!fs.existsSync(filePath)) return findings;

    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      const mcpServers = parsed.mcpServers || parsed;

      if (typeof mcpServers === "object") {
        for (const [name, config] of Object.entries(mcpServers)) {
          findings.push(...this.auditServerConfig(name, config as McpServerConfig));
        }
      }
    } catch {
      // Non-blocking parse error
    }

    return findings;
  }
}
