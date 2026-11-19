# Browser Security & Ad-Click Prevention

Autonomous browser automation must reject deceptive and advertising surfaces.

## Rules
- Inspect DOM elements prior to clicking. Reject selectors with keywords: `sponsored`, `ad-container`, `commercial_unit`, `googleads`.
- Verify URLs before navigation. Reject punycode homographs (`xn--`) and high-risk TLDs hosting fake login forms.
- Disallow downloading arbitrary executable binary files (.exe, ELF, Mach-O).
