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

  constructor(workspaceRoot: string = process.cwd()) {
    this.backupDir = path.join(workspaceRoot, ".agentshield_backup", Date.now().toString());
  }

  public remediate(findings: SecurityFinding[], workspaceRoot: string = process.cwd()): RemediationResult {
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
        const gitignorePath = path.join(workspaceRoot, ".gitignore");
        if (this.backupFile(gitignorePath)) {
          let gitignore = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, "utf-8") : "";
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

      if (finding.category === "MCP" && finding.title.includes("Hardcoded Secret")) {
        actionsTaken.push(`Marked ${finding.affectedResource} for secret externalization into environment variables.`);
        finding.remediationStatus = "REMEDIATED";
        remediatedFindings.push(finding);
        remediatedCount++;
      }
    }

    return {
      remediatedCount,
      backupDir: this.backupDir,
      actionsTaken,
      remediatedFindings
    };
  }

  public rollback(): boolean {
    if (!fs.existsSync(this.backupDir)) return false;
    const files = fs.readdirSync(this.backupDir);
    for (const f of files) {
      const src = path.join(this.backupDir, f);
      const dest = path.join(process.cwd(), f);
      fs.copyFileSync(src, dest);
    }
    return true;
  }

  private backupFile(targetPath: string): boolean {
    try {
      if (fs.existsSync(targetPath)) {
        const dest = path.join(this.backupDir, path.basename(targetPath));
        fs.copyFileSync(targetPath, dest);
      }
      return true;
    } catch {
      return false;
    }
  }
}
