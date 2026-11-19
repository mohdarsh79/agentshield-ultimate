# Configuration Guide

AgentShield Ultimate can be configured via `.agentshield/config.json` or programmatically in the SDK.

## Configuration Schema

```json
{
  "version": "1.0.0",
  "profile": "strict",
  "enforceBrowserAdBlock": true,
  "enforceFilesystemSandbox": true,
  "enforceAntiSsrf": true,
  "enforceHumanApprovalForFinancial": true,
  "workspaceRoot": "./",
  "allowedDomains": [
    "github.com",
    "npmjs.com",
    "developer.mozilla.org"
  ]
}
```

### Policy Profiles
- `strict`: Enforces all sandboxing rules, blocks all ad-clicks, rejects private IP egress, requires approval for any high-risk action.
- `balanced`: Enforces security boundaries while allowing loopback testing for local developer daemons.
- `dev`: Permissive auditing mode for initial local environment testing.
