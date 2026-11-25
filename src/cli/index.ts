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
      const isMachineOutput = args.includes("--json") || args.includes("--sarif");
      if (isMachineOutput) {
        // AS-13: Send status log to stderr so stdout is 100% valid standalone JSON/SARIF
        process.stderr.write("[*] Running comprehensive AgentShield multi-vector workspace scan...\n");
      } else {
        console.log("\n[*] Running comprehensive AgentShield multi-vector workspace scan...");
      }

      const report = shield.scanWorkspace();
      const format = args.includes("--json") ? "json" : args.includes("--sarif") ? "sarif" : args.includes("--md") ? "md" : "ansi";

      if (format === "json") {
        process.stdout.write(SecurityReporter.toJson(report) + "\n");
      } else if (format === "sarif") {
        process.stdout.write(SecurityReporter.toSarif(report) + "\n");
      } else if (format === "md") {
        process.stdout.write(SecurityReporter.toMarkdown(report) + "\n");
      } else {
        process.stdout.write(SecurityReporter.toAnsi(report) + "\n");
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
        
        // AS-14: Persist policy profile changes to .agentshield/config.json
        const configDir = path.join(process.cwd(), ".agentshield");
        if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });
        const configPath = path.join(configDir, "config.json");
        let currentConfig: Record<string, unknown> = {};
        if (fs.existsSync(configPath)) {
          try {
            currentConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
          } catch {
            currentConfig = {};
          }
        }
        currentConfig.profile = newProfile;
        fs.writeFileSync(configPath, JSON.stringify(currentConfig, null, 2), "utf-8");

        console.log(`\n[✓] Switched and persisted active policy profile to: ${newProfile}\n`);
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
        console.log(` • ${item.name.padEnd(20)}: ${item.support}`);
      }
      console.log("=======================================================\n");
      break;
    }

    case "dashboard": {
      const preferredPort = args[1] ? parseInt(args[1], 10) : 3840;
      console.log("\n[*] Initiating AgentShield Local Security Dashboard...");
      const report = shield.scanWorkspace();
      const inst = await DashboardServer.start(report, preferredPort, shield.auditLogger);
      console.log(`\n=======================================================`);
      console.log(` AGENTSHIELD ULTIMATE SECURE DASHBOARD ONLINE`);
      console.log(`=======================================================`);
      console.log(` Access URL   : ${inst.url}`);
      console.log(` Bound Port   : ${inst.port}`);
      console.log(` Session Token: ${inst.authToken}`);
      console.log(` Security     : HttpOnly cookie session auth & local-only host binding`);
      console.log(` Press Ctrl+C to terminate dashboard server.`);
      console.log(`=======================================================\n`);
      break;
    }

    default: {
      console.log(`
AgentShield Ultimate — Autonomous AI Agent Security Framework (CLI)
Usage: agentshield <command> [options]

Commands:
  scan [--json|--sarif|--md]  Run comprehensive multi-vector workspace security scan
  audit                       Audit runtime security configuration and action logs
  red-team                    Execute live adversarial red-team simulation suite
  threat-model                Display active trust boundaries and mitigation matrix
  fix                         Automatically remediate discovered configuration flaws
  policy <strict|balanced|dev> Persist and configure active runtime policy profile
  integrations                List supported autonomous agent integrations
  dashboard [port]            Launch local zero-trust security monitoring web UI
  version                     Display installed AgentShield framework version
`);
    }
  }
}

runCli().catch((err) => {
  process.stderr.write(`[!] Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
