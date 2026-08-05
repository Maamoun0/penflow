# Live Threat Advisory: CISA KEV CVE-2026-63077: JetBrains TeamCity Deserialization of Untrusted Data Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2026-63077).

## Threat Details
- **CVE Identifier**: `CVE-2026-63077`
- **Vendor / Product**: `JetBrains / TeamCity`
- **Disclosed Date**: `2026-08-05`
- **Inferred Vulnerability Category**: `rce`

## Advisory Description
JetBrains TeamCity contains a deserialization of untrusted data vulnerability that could allow unauthenticated remote code execution via the agent polling protocol.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-63077
