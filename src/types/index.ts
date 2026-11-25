export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type Confidence = "CERTAIN" | "HIGH" | "MEDIUM" | "LOW";

export type SecurityCategory = 
  | "CREDENTIAL"
  | "PROMPT_INJECTION"
  | "BROWSER"
  | "FILESYSTEM"
  | "NETWORK"
  | "COMMAND"
  | "MCP"
  | "SKILL"
  | "DOWNLOAD"
  | "SUPPLY_CHAIN"
  | "CONFIGURATION"
  | "APPROVAL";

export type PolicyProfile = "strict" | "balanced" | "dev";

export interface SecurityFinding {
  id: string;
  severity: Severity;
  confidence: Confidence;
  category: SecurityCategory;
  title: string;
  evidence: string;
  affectedResource: string;
  impact: string;
  mitigation: string;
  standardReference: string;
  remediationStatus: "OPEN" | "REMEDIATED" | "IGNORED" | "ACTION_REQUIRED";
  timestamp: string;
}

export interface SecurityEvaluationResult {
  allowed: boolean;
  blockedReason?: string;
  requiresApproval?: boolean;
  approvalToken?: string;
  approvalRequest?: unknown;
  findings: SecurityFinding[];
  scorePenalty: number;
}

export interface AgentActionContext {
  actionType: "file_read" | "file_write" | "file_delete" | "command_execute" | "browser_click" | "browser_navigate" | "network_request" | "mcp_tool_call" | "download" | "financial_transfer" | string;
  actor: string;
  target: string;
  parameters?: Record<string, unknown>;
  approvalToken?: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  category: SecurityCategory;
  severity: Severity;
  description: string;
  enforceAction: "block" | "require_approval" | "warn";
  evaluate: (ctx: AgentActionContext) => { matched: boolean; details?: string };
}

export interface SecurityScoreReport {
  timestamp: string;
  score: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F" | string;
  totalFindings: number;
  findings: SecurityFinding[];
  bySeverity: Record<Severity, number>;
  byCategory: Record<SecurityCategory, number>;
  categoryScores?: Record<SecurityCategory, number>;
  coverage?: {
    filesInspected: number;
    filesSkipped: number;
    durationMs: number;
    scannersActive: string[];
  };
}

export interface AgentShieldConfig {
  workspaceRoot?: string;
  auditLogPath?: string;
  profile?: PolicyProfile;
  defaultApprovalTtlSeconds?: number;
}

export type CategoryScores = Record<SecurityCategory, number>;
