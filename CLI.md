# CLI Reference

The `agentshield` command-line utility provides scanning, auditing, and remediation capabilities.

## Commands

- `agentshield init`: Initialize configuration in the current workspace.
- `agentshield scan [options]`:
  - `--json`: Output report as JSON.
  - `--sarif`: Output report in SARIF v2.1.0 format.
  - `--md`: Output report in GitHub-flavored Markdown.
- `agentshield audit`: Audit configuration posture and tamper-evident event log.
- `agentshield threat-model`: Display STRIDE threat model summary.
- `agentshield red-team`: Run adversarial attack simulation suite.
- `agentshield fix`: Safely apply automated remediations with snapshot backups.
- `agentshield policy [strict|balanced|dev]`: View or switch policy profile.
- `agentshield integrations`: Display supported AI agent integrations.
- `agentshield dashboard`: Launch local authenticated security dashboard.
- `agentshield version`: Display version information.
