# Threat model: automation itself

## Assets

API credentials, alert contents, analyst identity/decision, TheHive records, audit events, and the integrity of the response policy.

## Trust boundaries and threats

- **Wazuh webhook -> service:** spoofed/replayed alert, oversized payload, malicious strings. Bearer auth, rule threshold, bounded title/description, untrusted data handling. Add network restrictions and request-size limits before any non-lab deployment.
- **Alert content -> public TI providers:** private IP, internal hostname/domain, username, or URL path disclosed. Reject non-global IPs; omit identity/host metadata from enrichment input; support explicit allowlists; keep enrichment opt-in. Organization DNS suffixes need local configuration.
- **TI providers -> scorer:** outages, 429, malformed response, poisoned or stale reputation. Timeouts, retries, cache, source-specific status, no coercion of errors to clean scores, explain score coverage.
- **Notification -> approval callback:** forged click, replay, unauthorized user, duplicate decision. Verify Slack request signature/timestamp or Telegram secret header; one-shot pending decision and expiry; authenticated manual endpoint.
- **Alert data -> response action:** command injection or prompt injection. No LLM or shell command is used; only a fixed action and validated IP can update the local list.
- **Service/container -> host:** exposed ports, weak lab credentials, writable volume compromise. Keep ports local/private, rotate sample secrets, use least privilege, keep dry-run enabled, and never mount firewall control or Docker socket.
- **Audit file:** tampering or accidental secrets. Append JSONL with redacted metadata, no API keys or raw log, restrict volume access, and protect/ship logs before production use.

## Residual risks

The demo uses in-memory approval state, a local file audit log, process-local rate limiting, and a simple suffix/allowlist sanitizer. These are not production controls. Free-tier APIs may retain submitted indicators and rate limits can delay triage. Enrichment scores can be stale or wrong; human review is required.
