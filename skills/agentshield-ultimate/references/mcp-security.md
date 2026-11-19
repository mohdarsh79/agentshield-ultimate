# Model Context Protocol (MCP) Security

## Rules
- Audit `.mcp.json` and client configs for hardcoded plaintext secrets.
- Inspect tool descriptions for coercive instructions or forced priority directives.
- Validate tool parameters to prevent path traversal or SSRF injection.
- Enforce TLS encryption for remote MCP transports.
