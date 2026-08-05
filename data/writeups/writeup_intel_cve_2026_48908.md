# Live Threat Advisory: CISA KEV CVE-2026-48908: JoomShaper SP Page Builder Unrestricted Upload of File with Dangerous Type Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2026-48908).

## Threat Details
- **CVE Identifier**: `CVE-2026-48908`
- **Vendor / Product**: `JoomShaper / SP Page Builder`
- **Disclosed Date**: `2026-07-07`
- **Inferred Vulnerability Category**: `info_disclosure`

## Advisory Description
JoomShaper SP Page Builder contains an unrestricted upload of file with dangerous type vulnerability that allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48908
