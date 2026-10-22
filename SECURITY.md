# Security policy

This repository is a synthetic-data lab, not a production response system. Do not submit real alerts, credentials, personal data, private IPs, internal hostnames, or confidential indicators to public enrichment services. VirusTotal documents that queried indicators are included in its shared dataset.

Store API keys in an untracked local `.env` or a secret manager. Use least privilege and rotate exposed keys. Do not disable TLS verification. Keep `DRY_RUN=true`; the demo action only edits a local list and never applies a network firewall rule. Treat all alert data as untrusted and do not execute commands or prompts derived from it.

Report vulnerabilities privately to the repository maintainer. Include impact and safe reproduction steps; do not include real credentials or victim data.
