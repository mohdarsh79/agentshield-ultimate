# AgentShield Ultimate: License Compatibility Analysis

**Project**: AgentShield Ultimate (`agentshield-ultimate`)  
**Target License**: MIT License for all original code  
**Date**: November 2026  

---

## 1. Licensing Philosophy & Legal Policy

1. **Clean-Room & Original Implementation**:
   All core source code in AgentShield Ultimate is written as a clean-room, original TypeScript/Node.js implementation. Architectural patterns and vulnerability taxonomies are researched from upstream works, but their implementation is independently designed and authored.

2. **No Incompatible Ingestion**:
   - No GPL, AGPL, or proprietary copyleft code is incorporated into AgentShield Ultimate.
   - Any conceptual derivation or structural patterns inspired by Apache 2.0 projects (NVIDIA SkillSpector, Nasiko, Tencent AI-Infra-Guard) are reimplemented from specification to avoid license entanglement, or included strictly under clear boundary isolation with full notice preservation.

3. **MIT License for Original Works**:
   The entirety of AgentShield Ultimate's codebase, documentation, schemas, and tests is licensed under the standard, permissive MIT License.

---

## 2. Upstream License Matrix

| Project | Primary License | Permitted Uses | Patent Grant Included | Re-licensing Policy in AgentShield Ultimate |
| :--- | :--- | :--- | :--- | :--- |
| **AgentShield** (affaan-m) | MIT | Commercial, Modification, Distribution, Private Use | General standard copyright | **Direct heritage**: MIT licensed. Full attribution preserved. |
| **NVIDIA SkillSpector** | Apache 2.0 | Commercial, Modification, Distribution, Sublicensing | Yes (Section 3 of Apache 2.0) | **Independent Implementation**: Concepts and regex/YARA rules reimplemented in TypeScript under MIT. No verbatim code copied. Apache notice preserved. |
| **Nasiko** | Apache 2.0 | Commercial, Modification, Distribution, Sublicensing | Yes (Section 3 of Apache 2.0) | **Independent Implementation**: Runtime governance and ephemeral vault patterns reimplemented in TypeScript under MIT. Notice preserved. |
| **Tencent AI-Infra-Guard** | MIT / Apache 2.0 | Commercial, Modification, Distribution, Sublicensing | Permissive terms | **Independent Implementation**: Red-teaming test vectors and MCP audit concepts reimplemented in TypeScript under MIT. Notice preserved. |

---

## 3. Dependency License Verification

All production runtime dependencies selected for AgentShield Ultimate are strictly verified for license compatibility:
- **MIT License**: `commander`, `chalk`, `zod`, `semver`, `glob`, `yaml`
- **Apache 2.0 / BSD-2/3**: Standard parsing and cryptographic utilities
- **Prohibited in Runtime**: GPL-v2/3, AGPL, CC-BY-NC, SSPL, or any non-commercial/copyleft licenses.

---

## 4. Verification Conclusion

AgentShield Ultimate is 100% compliant with permissive open-source licensing guidelines. Downstream consumers can freely integrate, embed, commercialize, and modify AgentShield Ultimate under the terms of the MIT License.
