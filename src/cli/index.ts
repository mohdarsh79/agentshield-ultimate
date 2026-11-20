#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import { AgentShield } from "../sdk";
import { SecurityReporter } from "../reporting";
import { DashboardServer } from "../dashboard";
import { UniversalAgentAdapterRegistry } from "../adapters";
import { RedTeamRunner } from "../red-team";

const args = process.argv.slice(2);
const command = args[0] || "help";

async function runCli(): Promise<void> {
  const shield = new AgentShield({ workspaceRoot: process.cwd() });

  switch (command) {
    case "version":
    case "-v":
    case "--version": {
      console.log("AgentShield Ultimate v1.0.0 (Production Release)");
      break;
    }

    case "init": {
      console.log("\n[+] Initializing AgentShield Ultimate in current workspace...");
      const configDir = path.join(process.cwd(), ".agentshield");
      if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });

      const configTemplate = {
        version: "1.0.0",
        profile: "strict",
        enforceBrowserAdBlock: true,
        enforceFilesystemSandbox: true,
        enforceAntiSsrf: true,
        enforceHumanApprovalForFinancial: true
      };
      fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify(configTemplate, null, 2), "utf-8");
      console.log("[✓] Created .agentshield/config.json with strict zero-trust profile.");
      console.log("[✓] AgentShield Ultimate initialized successfully.\n");
      break;
    }

    case "scan": {
      console.log("\n[*] Running comprehensive AgentShield multi-vector workspace scan...");
      const report = shield.scanWorkspace();
      const format = args.includes("--json") ? "json" : args.includes("--sarif") ? "sarif" : args.includes("--md") ? "md" : "ansi";

      if (format === "json") {
        console.log(SecurityReporter.toJson(report));
      } else if (format === "sarif") {
        console.log(SecurityReporter.toSarif(report));
      } else if (format === "md") {
        console.log(SecurityReporter.toMarkdown(report));
      } else {
        console.log(SecurityReporter.toAnsi(report));
      }
      break;
    }

    case "audit":
    case "checkup": {
      console.log("\n[*] Auditing runtime configuration & action history...");
      const report = shield.scanWorkspace();
      console.log(SecurityReporter.toAnsi(report));
      break;
    }

    case "threat-model": {
      const profile = shield.policyEngine.getProfile();
      console.log("\n=======================================================");
      console.log(" AGENTSHIELD ULTIMATE THREAT MODEL & TRUST BOUNDARIES");
      console.log("=======================================================");
      console.log(` Active Policy Profile : ${profile.toUpperCase()}`);
      console.log(" Standard Taxonomies   : STRIDE, MITRE ATLAS, OWASP LLM Top 10");
      console.log("-------------------------------------------------------");
      console.log(" Trust Boundary 1: LLM Non-Deterministic Cognition -> UNTRUSTED");
      console.log("   - Enforced by: PromptGuard (injection, jailbreaks, hidden comments, unicode evasion)");
      console.log(" Trust Boundary 2: Host Operating System & Shell -> SANDBOXED");
      console.log("   - Enforced by: FilesystemGuard (path traversal, symlink escapes, reserved devices)");
      console.log("   - Enforced by: CommandGuard (destructive commands, chaining, reverse shells)");
      console.log(" Trust Boundary 3: Network & External Egress -> ISOLATED");
      console.log("   - Enforced by: NetworkGuard (cloud metadata SSRF, RFC-1918 subnets, DNS rebinding)");
      console.log("   - Enforced by: BrowserGuard (ad click hijacking, homograph phishing, open redirects)");
      console.log(" Trust Boundary 4: High-Risk & Financial Operations -> APPROVAL-GATED");
      console.log("   - Enforced by: ApprovalEngine (cryptographic SHA-256 parameter binding, single-use)");
      console.log("=======================================================\n");
      break;
    }

    case "red-team": {
      console.log("\n[*] Executing live adversarial red-team test suite against active guards...");
      const runner = new RedTeamRunner();
      const summary = await runner.runSuite();

      for (const res of summary.results) {
        const tag = res.passed ? "[PASS]" : "[FAIL]";
        console.log(` ${tag} (${res.category.padEnd(16)}) ${res.name} [${res.durationMs}ms]`);
        if (!res.passed) {
          console.log(`        Details: ${res.details}`);
        }
      }
      console.log(`-------------------------------------------------------`);
      console.log(` Total Scenarios: ${summary.totalScenarios} | Passed: ${summary.passedScenarios} | Failed: ${summary.failedScenarios}`);
      console.log(` Live Defense Verification Rate: ${summary.verificationRate}%\n`);
      if (summary.failedScenarios > 0) {
        process.exitCode = 1;
      }
      break;
    }

    case "fix": {
      console.log("\n[*] Running automated transactional remediation...");
      const report = shield.scanWorkspace();
      const res = shield.remediationEngine.remediate(report.findings, process.cwd());
      console.log(`[✓] Remediated ${res.remediatedCount} findings.`);
      for (const act of res.actionsTaken) {
        console.log(`    - ${act}`);
      }
      console.log(`[✓] Backup snapshot preserved in: ${res.backupDir}\n`);
      break;
    }

    case "policy": {
      const newProfile = args[1] as "strict" | "balanced" | "dev";
      if (newProfile && ["strict", "balanced", "dev"].includes(newProfile)) {
        shield.policyEngine.setProfile(newProfile);
        console.log(`\n[✓] Switched active policy profile to: ${newProfile}\n`);
      } else {
        console.log(`\nCurrent Policy Profile: ${shield.policyEngine.getProfile()}`);
        console.log("Available profiles: strict | balanced | dev\n");
      }
      break;
    }

    case "integrations": {
      console.log("\n=======================================================");
      console.log(" AGENTSHIELD ULTIMATE SUPPORTED AGENT INTEGRATIONS");
      console.log("=======================================================");
      const list = UniversalAgentAdapterRegistry.listAll();
      for (const item of list) {
        console.log(` - ${item.name.padEnd(16)} : ${item.support}`);
      }
      console.log("=======================================================\n");
      break;
    }

    case "report": {
      const report = shield.scanWorkspace();
      const outputPath = args[1] || "agentshield-report.md";
      fs.writeFileSync(outputPath, SecurityReporter.toMarkdown(report), "utf-8");
      console.log(`\n[✓] Exported security report to: ${outputPath}\n`);
      break;
    }

    case "dashboard": {
      console.log("\n[*] Launching embedded authenticated Security Dashboard...");
      const report = shield.scanWorkspace();
      const inst = await DashboardServer.start(report, 4173, shield.auditLogger);
      console.log(`[✓] Dashboard live at: ${inst.url}`);
      console.log("    Press Ctrl+C to terminate server.\n");
      break;
    }

    case "help":
    default: {
      console.log(`
AgentShield Ultimate CLI - Universal AI Agent Security Framework

Usage: agentshield <command> [options]

Commands:
  init            Initialize AgentShield configuration in current workspace
  scan            Scan workspace skills, MCP configs, package scripts, and credentials
  audit           Audit runtime configuration and tamper-evident event log
  checkup         Quick security posture assessment
  threat-model    Display STRIDE threat model and trust boundaries
  red-team        Execute adversarial attack simulation suite
  fix             Safely apply automated remediations with rollback backup
  policy <name>   View or switch policy profile (strict | balanced | dev)
  integrations    List supported agent integrations and support tiers
  report [path]   Export security report to Markdown file
  dashboard       Start local authenticated web dashboard
  version         Display package version
`);
      break;
    }
  }
}

runCli().catch((err) => {
  console.error("AgentShield Fatal Error:", err);
  process.exit(1);
});
