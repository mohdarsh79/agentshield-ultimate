# Filesystem and Network Security

## Filesystem Invariants
- Restrict all file operations to the designated project workspace root.
- Block access to `.ssh`, `.env`, `.aws`, `/etc/passwd`, and private identity tokens.
- Resolve symlinks and reject targets pointing outside the repository boundaries.

## Network Invariants
- Block egress to private IPv4 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
- Block link-local cloud instance metadata addresses (`169.254.169.254`, `metadata.google.internal`).
- Enforce strict domain allowlisting in production environments.
