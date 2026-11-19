# ADR-002: Deterministic Browser Action Guard and Ad-Click Prevention

## Status
Accepted

## Context
Autonomous browser automation agents (operating via Puppeteer, Playwright, or Chrome DevTools MCP) frequently search the web to retrieve documentation or complete tasks. Attackers exploit this via sponsored search results, phishing redirects, and malicious ad networks targeting automated scraping workflows.

## Decision
We enforce browser action interception at the automation API layer:
1. Every DOM click target is evaluated against ad selectors, sponsored badges, and tracking elements.
2. Target URLs are analyzed against phishing patterns, punycode/homoglyph spoofing, and redirect chains.
3. Clicks on advertising or sponsored links are strictly blocked with an actionable audit event.

## Consequences
- **Positive**: Eliminates malware delivery and credential theft vectors caused by automated ad interaction.
- **Negative**: Requires maintaining and updating ad selector heuristics and tracking domain lists.
