# Live Threat Advisory: CISA KEV CVE-2026-56291: Balbooa Forms Unrestricted Upload of File with Dangerous Type Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2026-56291).

## Threat Details
- **CVE Identifier**: `CVE-2026-56291`
- **Vendor / Product**: `Balbooa / Forms`
- **Disclosed Date**: `2026-07-10`
- **Inferred Vulnerability Category**: `rce`

## Advisory Description
Balbooa Forms contains an unrestricted upload of file with dangerous type vulnerability that allows an unauthenticated arbitrary file upload which could allow uploading of executable files leading to full RCE.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-56291
