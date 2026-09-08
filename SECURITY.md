# Security policy

## Supported versions

There is no supported stable release until v1.0 is tagged. Security fixes currently target the latest `main` revision. This section will be updated when release support windows exist.

## Reporting a vulnerability

Once this repository is public and private vulnerability reporting is enabled, use **Security → Report a vulnerability**. While it is private, or if that control is unavailable, contact the maintainer through an existing private channel to arrange secure disclosure. Enabling and testing the report form is a pre-tag checklist item; this policy does not claim it is already active. Do not open a public issue for a suspected vulnerability and do not include secrets, production Audit logs, customer data, or identifying infrastructure details in a report.

Describe the affected revision, impact, prerequisites, and a minimal reproduction using synthetic data where possible. The maintainer will acknowledge and triage reports as practical, coordinate remediation privately, and publish an advisory when disclosure is appropriate. No response-time SLA is promised.

Security reports should cover AesirGuard Audit itself or its supplied deployment material. Vulnerabilities in a SIEM, host operating system, auditd, or a downstream adapter belong to the corresponding project unless AesirGuard Audit creates or materially amplifies the issue.
