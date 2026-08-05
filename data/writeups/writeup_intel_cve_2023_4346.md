# Live Threat Advisory: CISA KEV CVE-2023-4346: KNX Association KNX Protocol Connection Authorization Option 1 Overly Restrictive Account Lockout Mechanism Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2023-4346).

## Threat Details
- **CVE Identifier**: `CVE-2023-4346`
- **Vendor / Product**: `KNX Association / KNX Protocol Connection Authorization Option 1`
- **Disclosed Date**: `2026-07-15`
- **Inferred Vulnerability Category**: `idor`

## Advisory Description
KNX Association KNX Protocol Connection Authorization Option 1 contains an overly restrictive account lockout mechanism vulnerability that could allow an attacker to purge all devices without additional security options enabled and set a BCU key to lock the device. 

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2023-4346
