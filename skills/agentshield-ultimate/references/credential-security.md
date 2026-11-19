# Credential, Command and Supply-Chain Security

## Credential Protection
- Secrets and tokens must never appear in raw text output or unencrypted logs.
- Automatic redaction masks detected API tokens (`[REDACTED_SECRET]`).

## Command Execution
- Prohibit destructive system operations (recursive root or home directory deletion, fork bombs, disk formatting).
- Prohibit piping remote uninspected scripts to shell (`curl | bash`).
- Enforce command argument array separation to avoid shell metacharacter injection.

## Download & Supply Chain
- Verify file headers via magic bytes; prohibit arbitrary execution of downloaded binary files.
- Inspect package lifecycle scripts (`preinstall`, `postinstall`) before running package managers.
