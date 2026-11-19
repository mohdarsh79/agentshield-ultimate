# AgentShield Ultimate: Complete Findings Register

| ID | Title | Severity | Component | CWE / Standard | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-VULN-001** | SSRF Bypass via IPv6-Mapped IPv4 and Wildcard DNS Domains | **CRITICAL** | `src/network-guard/index.ts` | CWE-918 / OWASP-LLM06 | Remediated |
| **SEC-VULN-002** | Stored Cross-Site Scripting (XSS) in Dashboard UI | **HIGH** | `src/dashboard/index.ts` | CWE-79 / OWASP-A03 | Remediated |
| **SEC-VULN-003** | Command Chaining Bypass via Single Ampersand & Newlines | **HIGH** | `src/command-guard/index.ts` | CWE-78 / OWASP-LLM06 | Remediated |
| **SEC-VULN-004** | Open Redirect Destination Extraction Failure in BrowserGuard | **HIGH** | `src/browser-guard/index.ts` | CWE-601 / OWASP-A01 | Remediated |
| **SEC-VULN-005** | Approval Engine Key Ordering Sensitivity (Non-Canonical JSON) | **MEDIUM** | `src/approval-engine/index.ts` | CWE-345 / Parameter Binding | Remediated |
| **SEC-VULN-006** | Double-Encoded Path Traversal & Windows Device Name Bypasses | **MEDIUM** | `src/filesystem-guard/index.ts` | CWE-22 / Path Traversal | Remediated |
| **SEC-VULN-007** | Missing Content-Security-Policy & Host Header Validation | **LOW** | `src/dashboard/index.ts` | CWE-1021 / Security Headers | Remediated |
