# Live Threat Advisory: CISA KEV CVE-2021-27137: DD-WRT Stack-Based Buffer Overflow Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2021-27137).

## Threat Details
- **CVE Identifier**: `CVE-2021-27137`
- **Vendor / Product**: `DD-WRT / DD-WRT`
- **Disclosed Date**: `2026-07-21`
- **Inferred Vulnerability Category**: `rce`

## Advisory Description
DD-WRT contains a stack-based buffer overflow vulnerability that could allow an unauthenticated attacker to overflow an internal buffer used by UPnP and trigger a code execution vulnerability.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2021-27137
