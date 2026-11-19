# Threat Model Review & Attack Surface Analysis

## 1. Threat Model Validation & Assumptions Challenge

The threat model assumes:
1. **Model Non-Determinism**: AI models cannot be relied upon to obey security instructions; all actions must be intercepted by a deterministic engine outside the cognitive loop. (Confirmed valid assumption).
2. **Untrusted External Data**: All web pages, documents, PDFs, and tool outputs contain potential indirect prompt injection vectors. (Confirmed valid assumption).
3. **Workspace Boundary Confinement**: AI operations are restricted to designated project directories. (Needs empirical verification across path variants).

## 2. Identified Attack Surfaces

```
[Attacker Vector]                  [Entry Point]             [Target Boundary]
-------------------------------------------------------------------------------------
Indirect Prompt Injection     ---> Scraped Webpage / Docs ---> PromptGuard Lexical Filter
Homograph Phishing            ---> Browser Navigation URL ---> BrowserGuard URL Validator
Ad-Click Hijacking            ---> Browser Click Selector ---> BrowserGuard DOM Matcher
SSRF / Metadata Exfiltration  ---> HTTP Request URL       ---> NetworkGuard IP Parser
Path Traversal Escape         ---> File Read/Write Target ---> FilesystemGuard Path Resolver
Shell Injection               ---> Command Execution      ---> CommandGuard Shell Parser
Stored XSS / Dashboard Attack ---> Malicious Finding Log  ---> DashboardServer HTML Render
Approval Parameter Mismatch   ---> Unordered JSON Payload ---> ApprovalEngine Hash Digest
```

## 3. High-Priority Vulnerability Hypotheses

1. **Dashboard Stored XSS**: Does the dashboard server sanitize untrusted findings before embedding them into the raw HTML string?
2. **SSRF Filter Bypass via Alternative IP Encodings**: Does NetworkGuard handle decimal (`http://2852039166`), hexadecimal, octal, or IPv6-mapped IPv4 representations of `169.254.169.254` and `127.0.0.1`?
3. **Approval Engine Hash Invalidation / Replay**: Does `JSON.stringify` parameter hashing fail when object keys are reordered (e.g. `{a: 1, b: 2}` vs `{b: 2, a: 1}`)?
4. **Command Injection via Newlines or Base64**: Can shell metacharacters like newlines (`\n`) or base64 decoding pipelines bypass CommandGuard?
5. **Path Traversal via Encoded / Windows Drive Escapes**: Can UNC paths (`\\?\C:\`) or alternate data streams bypass path checks?
