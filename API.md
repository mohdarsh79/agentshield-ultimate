# API Reference

## Class: `AgentShield`

Main entry point for programmatic agent security enforcement.

```typescript
import { AgentShield } from "agentshield-ultimate";

const shield = new AgentShield({
  profile: "strict", // "strict" | "balanced" | "dev"
  workspaceRoot: process.cwd()
});
```

### Methods

#### `interceptAction(ctx: AgentActionContext): SecurityEvaluationResult`
Synchronously evaluates an agent action against all guards (filesystem, browser, command, network, policy rules).

#### `scanPrompt(text: string, source?: string): PromptScanResult`
Inspects text for prompt injection, jailbreaks, hidden directives, base64 payloads, and unicode evasion.

#### `scanSecrets(text: string, resource?: string): SecretScanResult`
Scans and redacts 50+ high-entropy tokens and API keys.

#### `scanWorkspace(): SecurityScoreReport`
Performs an audit of workspace skills, MCP configurations, and dependencies, returning a 0–100 score and letter grade.
