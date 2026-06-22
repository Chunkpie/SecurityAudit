# Terms of Service — SecAudit Platform

_Last updated: 2024_

## 1. Acceptance of Terms

By accessing or using the SecAudit Platform ("the Platform"), you agree to be bound by these
Terms of Service. If you do not agree, do not use the Platform.

## 2. Authorization to Scan

**You may only scan websites and infrastructure that you own or for which you have obtained
explicit, written authorization to perform security testing.**

By initiating a scan, you confirm and warrant that:

- You own the target asset, **or**
- You have explicit written authorization from the asset owner to perform security testing, **and**
- Your testing activities comply with all applicable local, state, national, and international laws.

Unauthorized scanning of systems you do not own or have authorization to test may constitute a
criminal offense under computer fraud and abuse laws in many jurisdictions (e.g., the U.S. Computer
Fraud and Abuse Act, the UK Computer Misuse Act). **The Platform operator bears no liability for
unauthorized use by end users.**

Each scan request requires explicit consent confirmation. The Platform records:

- The user ID who initiated the scan
- A timestamp of consent
- The IP address from which the scan was requested

This data is retained as part of the permanent audit trail for legal and compliance purposes.

## 3. Acceptable Use

You agree not to use the Platform to:

- Test targets without proper authorization
- Launch denial-of-service attacks or any testing that could disrupt third-party services
  beyond standard reconnaissance and vulnerability identification
- Extract, exfiltrate, or misuse data discovered during scans for purposes other than
  remediation of your own systems
- Resell or redistribute scan results for targets you do not own without proper authorization
- Circumvent rate limits or abuse the API in a manner that degrades service for other users

## 4. Scan Methodology & Limitations

The Platform performs automated security testing using a combination of network scanning,
HTTP analysis, and vulnerability detection tools (including but not limited to Nmap, Nuclei,
SQLMap, SSLyze, and custom checks). Automated scanning:

- **May produce false positives.** Findings should be manually verified before remediation.
- **May produce false negatives.** A clean scan does not guarantee a system is free of all
  vulnerabilities. The Platform is a tool to aid security assessment, not a guarantee of security.
- **Is not a substitute for professional penetration testing**, code review, or a comprehensive
  security audit performed by qualified security professionals for high-risk or regulated systems.

## 5. Deployment Verdicts

The GO / GO WITH CONDITIONS / NO-GO verdict is generated algorithmically based on detected
findings and their severity. This verdict is advisory and does not constitute a certification,
warranty, or guarantee of security or compliance with any regulatory framework (PCI-DSS, HIPAA,
SOC 2, ISO 27001, etc.). Users are responsible for their own compliance obligations.

## 6. Data Retention & Privacy

- Scan results, findings, and generated reports are retained per your organization's plan settings.
- Audit logs (including consent records) are retained indefinitely for legal compliance.
- We do not sell or share your scan data with third parties.
- You may request deletion of your account and associated data, subject to legal retention
  requirements for audit logs.

## 7. Disclaimer of Warranties

THE PLATFORM IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
NON-INFRINGEMENT. WE DO NOT WARRANT THAT THE PLATFORM WILL IDENTIFY ALL SECURITY VULNERABILITIES.

## 8. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE PLATFORM OPERATOR SHALL NOT BE LIABLE FOR ANY
INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING BUT NOT LIMITED TO
LOSS OF DATA, REVENUE, OR BUSINESS INTERRUPTION, ARISING FROM USE OF THE PLATFORM, INCLUDING
ANY UNAUTHORIZED SCANNING ACTIVITIES CONDUCTED BY USERS.

## 9. Indemnification

You agree to indemnify and hold harmless the Platform operator from any claims, damages, or
legal fees arising from your unauthorized use of the Platform, including any scanning activity
performed without proper authorization.

## 10. Changes to Terms

We may update these Terms from time to time. Continued use of the Platform after changes
constitutes acceptance of the revised Terms.

## 11. Contact

For questions about these Terms, contact: legal@secaudit.local

---

**By clicking "I confirm I own or am authorized to test this target" when starting a scan,
you acknowledge that you have read, understood, and agree to these Terms of Service.**
