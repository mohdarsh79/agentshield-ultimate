import * as fs from "fs";
import * as path from "path";
import { SecurityFinding } from "../types";

export interface RemediationResult {
  remediatedCount: number;
  backupDir: string;
  actionsTaken: string[];
  remediatedFindings: SecurityFinding[];
}

export class RemediationEngine {
  private backupDir: string;
  private workspaceRoot: string;
  private trackedCreations: Set<string> = new Set();

  constructor(workspaceRoot: string = process.cwd()) {
    this.workspaceRoot = path.resolve(workspaceRoot);
    this.backupDir = path.join(this.workspaceRoot, ".agentshield_backup", Date.now().toString());
  }

  public remediate(findings: SecurityFinding[], workspaceRoot: string = this.workspaceRoot): RemediationResult {
    const ws = path.resolve(workspaceRoot);
    const actionsTaken: string[] = [];
    const remediatedFindings: SecurityFinding[] = [];
    let remediatedCount = 0;

    // Ensure backup directory exists
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }

    for (const finding of findings) {
      if (finding.category === "FILESYSTEM" && finding.affectedResource.includes(".env")) {
        // Safe Remediation: Add .env to .gitignore if missing
        const gitignorePath = path.join(ws, ".gitignore");
        const existedBefore = fs.existsSync(gitignorePath);
        if (this.backupFile(gitignorePath, existedBefore)) {
          let gitignore = existedBefore ? fs.readFileSync(gitignorePath, "utf-8") : "";
          if (!gitignore.includes(".env")) {
            gitignore += "\n# Added by AgentShield Ultimate remediation\n.env\n.env.*\n";
            fs.writeFileSync(gitignorePath, gitignore, "utf-8");
            actionsTaken.push(`Appended .env protection entries to ${gitignorePath}`);
            finding.remediationStatus = "REMEDIATED";
            remediatedFindings.push(finding);
            remediatedCount++;
          }
        }
      }

      // AS-09: Do NOT mark MCP secret as REMEDIATED unless configuration was actually modified
      if (finding.category === "MCP" && finding.title.includes("Hardcoded Secret")) {
        // Mark as ACTION_REQUIRED since automated secret extraction requires manual secret manager integration
        finding.remediationStatus = "ACTION_REQUIRED";
        actionsTaken.push(`Marked ${finding.affectedResource} for operator action: externalize secret into environment variables.`);
      }
    }

    return {
      remediatedCount,
      backupDir: this.backupDir,
      actionsTaken,
      remediatedFindings
    };
  }

  // AS-16: Rollback restores strictly into configured workspaceRoot, NOT process.cwd()
  public rollback(): boolean {
    if (!fs.existsSync(this.backupDir)) return false;

    // 1. Remove files that were newly created during remediation
    for (const createdRel of this.trackedCreations) {
      const createdPath = path.join(this.workspaceRoot, createdRel);
      if (fs.existsSync(createdPath)) {
        try {
          fs.unlinkSync(createdPath);
        } catch {
          // Ignore delete errors
        }
      }
    }

    // 2. Restore backed-up files into workspaceRoot
    const files = fs.readdirSync(this.backupDir);
    for (const f of files) {
      const src = path.join(this.backupDir, f);
      const dest = path.join(this.workspaceRoot, f);
      fs.copyFileSync(src, dest);
    }
    return true;
  }

  private backupFile(targetPath: string, existed: boolean): boolean {
    try {
      if (existed && fs.existsSync(targetPath)) {
        const dest = path.join(this.backupDir, path.basename(targetPath));
        fs.copyFileSync(targetPath, dest);
      } else {
        // Track that file was created by remediation so rollback can delete it
        this.trackedCreations.add(path.relative(this.workspaceRoot, targetPath));
      }
      return true;
    } catch {
      return false;
    }
  }
}
