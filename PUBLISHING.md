# Publishing & Release Guide

## npm Package: `agentshield-ultimate`

### Verification Pipeline
Before publishing, the release pipeline executes:
1. `npm run typecheck`
2. `npm run build`
3. `npm test`
4. `npm pack --dry-run`

### Security Checks
Verify that the published tarball excludes:
- Development files (`tests/`, `dist/tests/`)
- Environment files (`.env`, `.env.*`)
- Local audit logs (`audit.jsonl`)

### Publishing Command
```bash
npm publish --access public --provenance
```
