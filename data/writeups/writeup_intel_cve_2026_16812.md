# Live Threat Advisory: CISA KEV CVE-2026-16812: Arista VeloCloud Orchestrator On-Prem OS Command Injection Vulnerability

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds (CVE-2026-16812).

## Threat Details
- **CVE Identifier**: `CVE-2026-16812`
- **Vendor / Product**: `Arista / VeloCloud Orchestrator`
- **Disclosed Date**: `2026-07-27`
- **Inferred Vulnerability Category**: `rce`

## Advisory Description
Arista VeloCloud Orchestrator On-Prem contains an OS command injection vulnerability that may allow a remote attacker to access privileged internal functionality and impact the VCO host. Successful exploitation may compromise the confidentiality, integrity, and availability of the orchestrator and data managed by the orchestrator.

## Remediation & Mitigation Guidance
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

## References
- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-16812
