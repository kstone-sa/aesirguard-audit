# Roadmap

audit2json is approaching its first stable release. Completed implementation history is recorded in `CHANGELOG.md`, the Git history, and merged pull requests; this document tracks only validation still required for release and plausible future work.

## Current status

The canonical schema v1.0, persistent collector, checkpoint and rotation recovery, security-event normalization, optional renderer, operational diagnostics, synthetic hardening, and Linux amd64/arm64 release packages are implemented.

No stable release has been tagged. The distribution-labelled fixtures are synthetic regression data. Compatibility with real RAW and ENRICHED Linux Audit output on the distributions listed in `docs/compatibility.md` has not yet been empirically validated.

## Before v1.0

- Run controlled local validation on Debian 12/13, Ubuntu 22.04/24.04, RHEL 8/9, and Oracle Linux 8/9.
- Exercise the selected CIS Server Level 1 and Level 2 Audit event families using both RAW and ENRICHED output where available.
- Record the tested distribution, kernel, auditd, rule-set, and rotation configuration without publishing identifying data.
- Convert confirmed record variations into sanitized regression fixtures when safe and useful.
- Re-run the complete test, race, fuzz, benchmark, and package-verification workflows.
- Complete `docs/public-release-checklist.md` and obtain explicit maintainer approval before changing repository visibility or creating the `v1.0` tag.

Until this validation is complete, the documented distribution matrix is a test target, not a compatibility certification.

## After v1.0

Future work will be prioritized from operational evidence and user demand. Candidate areas include:

- additional architecture, errno, permission, signal, and message-type normalization driven by observed records;
- typed socket and network evidence;
- carefully scoped IPC, virtualization, cryptographic, and IPsec event families;
- optional native DEB and RPM packaging if maintaining it is justified;
- performance regression thresholds measured on controlled reference hardware;
- additional distributions, architectures, and Linux Audit versions.

TTY keystroke payloads require an explicit privacy and security design before any normalization is considered.

## Project boundaries

The core remains native Go, standard-library only, and backend-agnostic. Splunk CIM, Microsoft Sentinel ASIM, Elastic ECS, transport acknowledgements, detections, dashboards, and risk models belong in downstream integrations.
