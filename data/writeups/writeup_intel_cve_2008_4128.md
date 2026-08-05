# Live Threat Advisory: CISA KEV CVE-2008-4128: Cisco IOS Cross-Site Request Forgery Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2008-4128).

## Threat Details
- **CVE Identifier**: `CVE-2008-4128`
- **Vendor / Product**: `Cisco / IOS`
- **Disclosed Date**: `2026-07-13`
- **Inferred Vulnerability Category**: `rce`

## Advisory Description
Cisco IOS 12.4 contains multiple cross-site forgery vulnerabilities that allows remote attackers to execute arbitrary commands via (1) a certain "show privilege" command to the /level/15/exec/- URI, and (2) a certain "alias exec" command to the /level/15/exec/-/configure/http URI.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2008-4128
