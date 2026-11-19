# AgentShield Ultimate: High Severity Findings

## FINDING: SEC-VULN-002
- **Title**: Stored Cross-Site Scripting (XSS) in Dashboard UI
- **Severity**: **HIGH** (CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N - Base Score: 8.2)
- **Confidence**: **CERTAIN** (Empirically Reproduced and Verified)
- **Affected File**: `src/dashboard/index.ts`
- **Impact**: When an agent scans malicious files, prompts, or websites containing HTML markup (`<script>`, `<img src=x onerror=...>`, SVG payloads), the findings evidence and resource paths are embedded unescaped into the dashboard template. A developer opening `http://127.0.0.1:4173/?token=...` executes the injected JavaScript in their browser context, enabling local session token theft or arbitrary authenticated dashboard API invocation.
- **Root Cause**: `DashboardServer` interpolated raw strings directly into the HTML response:
  ```typescript
  <td><strong>${f.title}</strong><br><small>${f.evidence}</small></td>
  <td><code>${f.affectedResource}</code></td>
  ```
- **Remediation**:
  1. Implement strict HTML entity encoding function `escapeHtml()` for all interpolated fields (`&`, `<`, `>`, `"`, `'`).
  2. Implement strict Content-Security-Policy (CSP) header: `default-src 'self'; style-src 'unsafe-inline'; script-src 'self'`.
- **Regression Test**: Added to `tests/security-audit/regression-audit.test.ts`.
- **Verification Status**: Remediated.

---

## FINDING: SEC-VULN-003
- **Title**: Command Chaining Bypass via Single Ampersand Backgrounding (`&`)
- **Severity**: **HIGH** (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - Base Score: 8.4)
- **Confidence**: **CERTAIN** (Empirically Reproduced and Verified)
- **Affected File**: `src/command-guard/index.ts`
- **Impact**: `INJECTION_OPERATORS` contained `";", "&&", "||", "|", "\`", "$("`, but omitted the single ampersand (`&`). An attacker can inject secondary commands via `cmd1 & cmd2`, causing `cmd2` to execute asynchronously without tripping the chaining prevention rule.
- **Remediation**:
  1. Add single `&` (when not preceded or followed by `&` or `>`) and newlines (`\n`, `\r`) to forbidden metacharacters.
- **Regression Test**: Added to `tests/security-audit/regression-audit.test.ts`.
- **Verification Status**: Remediated.

---

## FINDING: SEC-VULN-004
- **Title**: Open Redirect Destination Extraction Failure in BrowserGuard
- **Severity**: **HIGH** (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N - Base Score: 7.5)
- **Confidence**: **HIGH**
- **Affected File**: `src/browser-guard/index.ts`
- **Impact**: An attacker navigates the agent to `https://legitimate.org/redirect?url=http://169.254.169.254`. BrowserGuard only inspected the immediate URL string without checking embedded redirect destination parameters (`url`, `redirect`, `dest`, `target`).
- **Remediation**: Recursively extract and validate embedded redirect query parameters against all browser and network policies.
- **Regression Test**: Added to `tests/security-audit/regression-audit.test.ts`.
- **Verification Status**: Remediated.
