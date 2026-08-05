# Live Threat Advisory: CISA KEV CVE-2026-60137: WordPress Core SQL Injection Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2026-60137).

## Threat Details
- **CVE Identifier**: `CVE-2026-60137`
- **Vendor / Product**: `WordPress / Core`
- **Disclosed Date**: `2026-07-21`
- **Inferred Vulnerability Category**: `sqli`

## Advisory Description
WordPress Core contains a SQL injection vulnerability when a plugin or theme passes untrusted input to the parameter. This vulnerability can be chained with CVE-2026-63030 to allow an unauthenticated attacker to gain remote code execution on default WordPress installations.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60137
