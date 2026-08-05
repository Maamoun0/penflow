# Live Threat Advisory: CISA KEV CVE-2025-68686: Fortinet FortiOS Exposure of Sensitive Information to an Unauthorized Actor Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2025-68686).

## Threat Details
- **CVE Identifier**: `CVE-2025-68686`
- **Vendor / Product**: `Fortinet / FortiOS`
- **Disclosed Date**: `2026-07-27`
- **Inferred Vulnerability Category**: `idor`

## Advisory Description
Fortinet FortiOS contains an exposure of sensitive information to an unauthorized actor vulnerability. This may allow a remote unauthenticated attacker to bypass the patch developed for the symbolic link persistency mechanism observed in some post-exploit cases, via crafted HTTP requests. An attacker would need first to have compromised the product via another vulnerability, at filesystem level.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2025-68686
