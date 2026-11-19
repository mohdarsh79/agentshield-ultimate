# Incident Response and Reporting

## Incident Handling Workflow
1. **Detection**: The policy engine flags an unauthorized action or prompt injection.
2. **Containment**: Execution is immediately halted (fail-closed).
3. **Evidence Capture**: Full contextual details are committed to the tamper-evident `audit.jsonl`.
4. **Remediation**: The remediation engine creates a transactional backup and executes safe mitigation.
5. **Reporting**: Findings are exported via SARIF, Markdown, or JSON for security visibility.
