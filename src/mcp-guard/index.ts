import * as fs from "fs";
import { SecurityFinding, Severity, AgentActionContext, SecurityEvaluationResult } from "../types";

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

  // Runtime Tool Call Interception (AS-06 / AS-18)
  public static evaluateToolCall(ctx: AgentActionContext): SecurityEvaluationResult {
    const findings: SecurityFinding[] = [];
    const toolName = String(ctx.target || ctx.parameters?.toolName || "");
    const paramsStr = JSON.stringify(ctx.parameters || {});

    // Check for prompt injection or covert directives embedded in tool call parameters
    for (const pat of this.POISON_DESCRIPTION_PATTERNS) {
      if (pat.regex.test(toolName) || pat.regex.test(paramsStr)) {
        findings.push({
          id: `FIND-MCP-POISON-${Date.now().toString(36)}`,
          severity: pat.severity,
          confidence: "CERTAIN",
          category: "MCP",
          title: `Malicious MCP Tool Invocation Blocked: ${pat.name}`,
          evidence: `MCP tool execution context matches poisoning pattern '${pat.name}'`,
          affectedResource: `mcp_tool:${toolName}`,
          impact: "Adversarial tool hijacking, prompt injection, or unauthorized covert data exfiltration.",
          mitigation: "Reject tool execution and quarantine compromised MCP server definition.",
          standardReference: "OWASP-LLM07 / Tool Poisoning",
          remediationStatus: "OPEN",
          timestamp: new Date().toISOString()
        });
        return {
          allowed: false,
          blockedReason: `MCP tool call blocked due to detected adversarial signature: ${pat.name}`,
          findings,
          scorePenalty: 25
        };
      }
    }

    return { allowed: true, findings, scorePenalty: 0 };
  }

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
        title: `Raw Shell Used as MCP Command: ${serverName}`,
        evidence: `Server command is configured to invoke raw shell '${config.command}'.`,
        affectedResource: `mcp_server:${serverName}`,
        impact: "Increases risk of shell injection if arguments are dynamically formulated.",
        mitigation: "Invoke standalone compiled binary executables with direct arguments rather than raw shells.",
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
      if (pat.regex.test(desc)) {
        findings.push({
          id: `FIND-MCP-POISON-${Date.now().toString(36)}`,
          severity: pat.severity,
          confidence: "HIGH",
          category: "MCP",
          title: `MCP Tool Description Poisoning Detected: ${tool.name}`,
          evidence: `Tool description matches suspicious pattern '${pat.name}': "${desc.substring(0, 80)}..."`,
          affectedResource: `mcp_tool:${serverName}/${tool.name}`,
          impact: "Adversarial instructions in tool description hijack LLM reasoning during tool selection.",
          mitigation: "Sanitize tool descriptions and disallow imperative prompt injection directives.",
          standardReference: "OWASP-LLM07 / Insecure Plugin Design",
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
      const content = fs.readFileSync(filePath, "utf-8");
      const config = JSON.parse(content);
      const servers = config.mcpServers || config.servers || {};

      for (const [name, serverConf] of Object.entries(servers)) {
        findings.push(...this.auditServerConfig(name, serverConf as McpServerConfig));
      }
    } catch {
      // Return empty if unparseable
    }

    return findings;
  }
}
