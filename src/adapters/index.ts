import { PolicyProfile, AgentActionContext, SecurityEvaluationResult } from "../types";
import { AgentShield } from "../sdk";

export interface AgentAdapter {
  agentName: string;
  supportLevel: "FULL" | "PARTIAL" | "INSTRUCTIONS_ONLY" | "SDK_WRAPPER";
  initialize: (workspaceRoot: string, profile: PolicyProfile) => Promise<boolean>;
  interceptAction: (ctx: AgentActionContext) => SecurityEvaluationResult;
}

// Concrete Tool Wrapper Interceptor (AS-10)
export function wrapToolExecution<TParams extends Record<string, unknown>, TResult>(
  shield: AgentShield,
  actionType: AgentActionContext["actionType"],
  toolName: string,
  fn: (params: TParams) => Promise<TResult> | TResult
): (params: TParams) => Promise<TResult> {
  return async (params: TParams): Promise<TResult> => {
    const ctx: AgentActionContext = {
      actionType,
      target: toolName,
      parameters: params,
      actor: "agent-runtime"
    };

    const res = await shield.interceptActionAsync(ctx);
    if (!res.allowed) {
      throw new Error(`AgentShieldBlockedError: Action '${actionType}' on '${toolName}' blocked. Reason: ${res.blockedReason}`);
    }

    return await fn(params);
  };
}

export class ClaudeCodeAdapter implements AgentAdapter {
  public agentName = "Claude Code";
  public supportLevel = "FULL" as const;
  private shield?: AgentShield;

  constructor(profile: PolicyProfile = "strict") {
    // Lazy initialized to prevent circular module dependency
  }

  private getShield(): AgentShield {
    if (!this.shield) {
      this.shield = new AgentShield();
    }
    return this.shield;
  }

  public async initialize(workspaceRoot: string = process.cwd(), profile: PolicyProfile = "strict"): Promise<boolean> {
    this.shield = new AgentShield({ workspaceRoot, profile });
    return true;
  }

  public interceptAction(ctx: AgentActionContext): SecurityEvaluationResult {
    return this.getShield().interceptAction(ctx);
  }

  public wrapClaudeTool<TParams extends Record<string, unknown>, TResult>(
    toolName: string,
    actionType: AgentActionContext["actionType"],
    executor: (params: TParams) => Promise<TResult> | TResult
  ) {
    return wrapToolExecution(this.getShield(), actionType, toolName, executor);
  }
}

export class CursorAdapter implements AgentAdapter {
  public agentName = "Cursor";
  public supportLevel = "SDK_WRAPPER" as const;
  private shield?: AgentShield;

  constructor(profile: PolicyProfile = "strict") {
    // Lazy initialized
  }

  private getShield(): AgentShield {
    if (!this.shield) {
      this.shield = new AgentShield();
    }
    return this.shield;
  }

  public async initialize(workspaceRoot: string = process.cwd(), profile: PolicyProfile = "strict"): Promise<boolean> {
    this.shield = new AgentShield({ workspaceRoot, profile });
    return true;
  }

  public interceptAction(ctx: AgentActionContext): SecurityEvaluationResult {
    return this.getShield().interceptAction(ctx);
  }
}

export class CodexAdapter implements AgentAdapter {
  public agentName = "OpenAI Codex";
  public supportLevel = "SDK_WRAPPER" as const;
  private shield?: AgentShield;

  constructor(profile: PolicyProfile = "strict") {
    // Lazy initialized
  }

  private getShield(): AgentShield {
    if (!this.shield) {
      this.shield = new AgentShield();
    }
    return this.shield;
  }

  public async initialize(workspaceRoot: string = process.cwd(), profile: PolicyProfile = "strict"): Promise<boolean> {
    this.shield = new AgentShield({ workspaceRoot, profile });
    return true;
  }

  public interceptAction(ctx: AgentActionContext): SecurityEvaluationResult {
    return this.getShield().interceptAction(ctx);
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

  // AS-10: Truthful, accurate support status matrix
  public static listAll(): Array<{ name: string; support: string }> {
    return [
      { name: "Claude Code", support: "FULL (Tool Wrappers, Skill Definition, SDK Interception)" },
      { name: "Cursor", support: "SDK_WRAPPER (Rules & Runtime Interception)" },
      { name: "OpenAI Codex", support: "SDK_WRAPPER (Function Call Proxy Interception)" },
      { name: "LangChain", support: "SDK_WRAPPER (Tool Callback Handler Wrapper)" },
      { name: "LlamaIndex", support: "SDK_WRAPPER (Query Engine & Tool Wrapper)" },
      { name: "GitHub Copilot", support: "INSTRUCTIONS_ONLY (Workspace Instruction Rules)" },
      { name: "Windsurf", support: "INSTRUCTIONS_ONLY (Cascade Workspace Rules)" }
    ];
  }
}

// Pre-register standard adapters
UniversalAgentAdapterRegistry.register(new ClaudeCodeAdapter());
UniversalAgentAdapterRegistry.register(new CursorAdapter());
UniversalAgentAdapterRegistry.register(new CodexAdapter());
