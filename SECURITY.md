# Security policy

## Supported versions

There is no supported stable release until v1.0 is tagged. Security fixes currently target the latest `main` revision. This section will be updated when release support windows exist.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for this repository. Do not open a public issue for a suspected vulnerability and do not include secrets, production Audit logs, customer data, or identifying infrastructure details in a report.

Describe the affected revision, impact, prerequisites, and a minimal reproduction using synthetic data where possible. The maintainer will acknowledge and triage reports as practical, coordinate remediation privately, and publish an advisory when disclosure is appropriate. No response-time SLA is promised.

Security reports should cover audit2json itself or its supplied deployment material. Vulnerabilities in a SIEM, host operating system, auditd, or a downstream adapter belong to the corresponding project unless audit2json creates or materially amplifies the issue.
