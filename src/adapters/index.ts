import { PolicyProfile, AgentActionContext, SecurityEvaluationResult } from "../types";
import { PolicyEngine } from "../core/policy-engine";

export interface AgentAdapter {
  agentName: string;
  supportLevel: "FULL" | "PARTIAL" | "INSTRUCTIONS_ONLY";
  initialize: (workspaceRoot: string, profile: PolicyProfile) => Promise<boolean>;
  interceptAction: (ctx: AgentActionContext) => SecurityEvaluationResult;
}

export class ClaudeCodeAdapter implements AgentAdapter {
  public agentName = "Claude Code";
  public supportLevel = "FULL" as const;
  private engine: PolicyEngine;

  constructor(profile: PolicyProfile = "strict") {
    this.engine = new PolicyEngine(profile);
  }

  public async initialize(): Promise<boolean> {
    return true;
  }

  public interceptAction(ctx: AgentActionContext): SecurityEvaluationResult {
    return this.engine.evaluateAction(ctx);
  }
}

export class CursorAdapter implements AgentAdapter {
  public agentName = "Cursor";
  public supportLevel = "FULL" as const;
  private engine: PolicyEngine;

  constructor(profile: PolicyProfile = "strict") {
    this.engine = new PolicyEngine(profile);
  }

  public async initialize(): Promise<boolean> {
    return true;
  }

  public interceptAction(ctx: AgentActionContext): SecurityEvaluationResult {
    return this.engine.evaluateAction(ctx);
  }
}

export class CodexAdapter implements AgentAdapter {
  public agentName = "OpenAI Codex";
  public supportLevel = "FULL" as const;
  private engine: PolicyEngine;

  constructor(profile: PolicyProfile = "strict") {
    this.engine = new PolicyEngine(profile);
  }

  public async initialize(): Promise<boolean> {
    return true;
  }

  public interceptAction(ctx: AgentActionContext): SecurityEvaluationResult {
    return this.engine.evaluateAction(ctx);
  }
}

export class UniversalAgentAdapterRegistry {
  private static adapters: Map<string, AgentAdapter> = new Map();

  public static register(adapter: AgentAdapter): void {
    this.adapters.set(adapter.agentName.toLowerCase(), adapter);
  }

  public static get(name: string): AgentAdapter | undefined {
    return this.adapters.get(name.toLowerCase());
  }

  public static listAll(): Array<{ name: string; support: string }> {
    return [
      { name: "Claude Code", support: "FULL (Hooks, Skill, Runtime Engine)" },
      { name: "Cursor", support: "FULL (MCP Guard, Rule Files, Runtime Engine)" },
      { name: "OpenAI Codex", support: "FULL (SDK Proxy, Policy Engine)" },
      { name: "OpenClaw", support: "FULL (Hook Interceptors, Skill)" },
      { name: "GitHub Copilot", support: "PARTIAL (Workspace Rules, Static Scan)" },
      { name: "Gemini CLI", support: "FULL (Sidecar, Skill, Engine)" },
      { name: "Windsurf", support: "FULL (MCP Guard, Cascade Rules)" },
      { name: "Cline", support: "FULL (MCP Protocol, Rule Engine)" },
      { name: "Continue", support: "FULL (Config Filter, Policy Engine)" }
    ];
  }
}

// Pre-register standard adapters
UniversalAgentAdapterRegistry.register(new ClaudeCodeAdapter());
UniversalAgentAdapterRegistry.register(new CursorAdapter());
UniversalAgentAdapterRegistry.register(new CodexAdapter());
