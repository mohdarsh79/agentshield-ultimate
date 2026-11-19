# Remediation Log & Vulnerability Fix Records

## Remediation Record 1: SSRF IP Normalization & Wildcard Domain Inspection
- **Finding ID**: `SEC-VULN-001`
- **Component**: `src/network-guard/index.ts`
- **Fix Applied**: Added `normalizeIpAddress()` to handle IPv6-mapped IPv4 formats (`::ffff:a9fe:a9fe` and `::ffff:x.x.x.x`). Added regex domain checks for wildcard DNS services (`.nip.io`, `.sslip.io`) embedding IP targets.
- **Verification**: Verified by regression tests `REG-01` and `REG-02`.

## Remediation Record 2: Dashboard Stored XSS Mitigation
- **Finding ID**: `SEC-VULN-002`
- **Component**: `src/dashboard/index.ts`
- **Fix Applied**: Implemented `escapeHtml()` and sanitized all finding titles, evidence, and resources before rendering into HTML response. Added Content-Security-Policy headers.
- **Verification**: Verified by regression test `REG-09`.

## Remediation Record 3: Command Chaining Metacharacter Expansion
- **Finding ID**: `SEC-VULN-003`
- **Component**: `src/command-guard/index.ts`
- **Fix Applied**: Added `(?<![&>])&(?!&)`, `\n`, `\r` to `FORBIDDEN_CHAINING_PATTERNS`.
- **Verification**: Verified by regression tests `REG-03` and `REG-04`.

## Remediation Record 4: Browser Open Redirect Recursion
- **Finding ID**: `SEC-VULN-004`
- **Component**: `src/browser-guard/index.ts`
- **Fix Applied**: Added recursive query parameter inspection across `dest`, `url`, `target`, `redirect`.
- **Verification**: Verified by regression test `REG-05`.

## Remediation Record 5: Canonical Parameter Serialization in Approval Engine
- **Finding ID**: `SEC-VULN-005`
- **Component**: `src/approval-engine/index.ts`
- **Fix Applied**: Added `canonicalize()` to sort object keys recursively before computing SHA-256 digest.
- **Verification**: Verified by regression test `REG-06`.

## Remediation Record 6: Double-Encoded Traversal & Device Names
- **Finding ID**: `SEC-VULN-006`
- **Component**: `src/filesystem-guard/index.ts`
- **Fix Applied**: Added iterative URI decoding and Windows reserved device name validation (`CON`, `PRN`, `AUX`, `NUL`).
- **Verification**: Verified by regression tests `REG-07` and `REG-08`.
