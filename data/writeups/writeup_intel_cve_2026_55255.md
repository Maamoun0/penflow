# Live Threat Advisory: CISA KEV CVE-2026-55255: Langflow Authorization Bypass Through User-Controlled Key Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2026-55255).

## Threat Details
- **CVE Identifier**: `CVE-2026-55255`
- **Vendor / Product**: `Langflow / Langflow`
- **Disclosed Date**: `2026-07-07`
- **Inferred Vulnerability Category**: `idor`

## Advisory Description
Langflow contains an authorization bypass through user-controlled key vulnerability which allows an authenticated attacker to execute any flow belonging to another user by specifying the victim's flow ID in the request.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-55255
