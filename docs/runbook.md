# Lab runbook

## Start and verify

1. Copy `.env.example` to `.env`; keep enrichment disabled and dry-run enabled.
2. `docker compose up --build -d`
3. `docker compose ps` and `docker compose logs -f thehive` until dependencies initialize.
4. `Invoke-RestMethod http://localhost:8080/health` and open TheHive at `http://localhost:9000`.
5. Create TheHive 5 user/API key with only alert-creation permissions and set it in local `.env` as `THEHIVE_API_KEY`; set `THEHIVE_URL=http://thehive:9000` from the Python container. Restart `python-service`.
6. Start the synthetic replayer with `docker compose --profile demo run --rm mock-alert-generator`.
7. Inspect TheHive for an alert and `/data/audit.jsonl` in the Docker volume. The generator uses synthetic data.

## API and integration setup

- Set `AUTOMATION_API_TOKEN` in `.env`; configure Wazuh custom integration to post JSON with `Authorization: Bearer ...`.
- For the Wazuh Integrator path, copy `scripts/wazuh-integration.py` to `/var/ossec/integrations/custom-soc-automation` (the filename must match the `<name>` without an extension), make it executable and owned by `root:wazuh` (`chmod 750`, `chown root:wazuh`). Add the contents of `config/wazuh-integration.xml.example` inside the manager's `<ossec_config>`, replace the token/host, and restart `wazuh-manager`. Wazuh passes the alert-file path, API token, and hook URL as script arguments; the example filters at level 7 and posts to the Python webhook. Verify this against [Wazuh's current custom integration contract](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html).
- To import n8n workflow, open n8n, import `n8n/soc-incident-response.json`, create Header Auth credential named `SOC Automation API Token`, and set n8n variable `SOC_AUTOMATION_URL=http://python-service:8080`. Wazuh can post to the displayed webhook test/production URL.
- Configure Slack interactive request URL `/approval/slack`; add the signing secret. The Block Kit action value carries only an opaque alert ID.
- Register Telegram callback webhook to `/approval/telegram` with `secret_token` set to `TELEGRAM_WEBHOOK_SECRET`. Callback queries are handled by the same decision endpoint.
- For direct/manual approval, `Invoke-RestMethod -Method Post -Uri http://localhost:8080/approval/<id> -Headers @{Authorization='Bearer <token>'} -ContentType 'application/json' -Body '{"decision":"reject","actor":"analyst"}'`.

## Enable enrichment deliberately

Review and populate the allowlist with every internal domain/hostname and sensitive indicator. Set API keys and `ENRICH_PUBLIC_IOCS=true`, then restart the Python service. VT public API is limited to four requests in any one-minute window, so caching and serialization may make larger alert runs slow. Only public indicators enter those calls. Avoid uploading files or requesting scans; these clients perform report lookups only.

## Response and rollback

Keep `DRY_RUN=true` first. Approval records are auditable in JSONL. For a file-write exercise only, stop the service, set `DRY_RUN=false`, restart, and approve a synthetic alert containing a **public test indicator that passes the lab validation** only if deliberately configured. Remove it with `python scripts/rollback-lab-block.py <address>`. The default fixtures use documentation IPs which are rejected as non-global; use unit tests for these values and do not test a real public IP without explicit lab criteria.

## Benchmark protocol

Run `python scripts/replay_demo.py --count 30 --output benchmarks/latest-run.json` (after install and with service running), or use `docker compose --profile demo run --rm mock-alert-generator`. Fill the manual baseline CSV using your own stopwatch or timestamps over the same manual steps on 5–10 alerts. Compute savings only from your two measured means/medians. Record API configuration, cache state, host specs, errors, date, and whether timings were warm or cold. `false_positive_labeled_count` remains null until a human labels outcomes; add those labels to your report. Do not claim a benchmark from mocks as a production/SOC performance result.

Manual baseline procedure for each of 5–10 alerts: (1) open the Wazuh alert and record start time, (2) inspect rule context and relevant fields, (3) identify and validate public IOCs, (4) perform the same configured TI lookups and record source errors, (5) calculate/document a triage priority, (6) create the equivalent TheHive alert with observables, (7) send or record the analyst notification, and (8) stop the timer after the alert is ready for analyst decision. Do not perform response actions as part of this timing. Use only synthetic/anonymized alerts and record timings yourself in the CSV.

## Verification checklist

- [ ] Health endpoint responds; below-threshold alert returns ignored.
- [ ] Synthetic public-domain/hash fixture returns processed and audit timestamps.
- [ ] Private/reserved IP and allowlisted values do not get enriched.
- [ ] Source timeout/429 is reported as an error/unknown and does not break alert creation.
- [ ] TheHive receives alert and observables (live lab check required).
- [ ] Reject and expiry run no response action; unauthenticated decisions fail.
- [ ] Approve in dry-run writes no file; configured lab file action includes rollback command.
- [ ] Thirty or more replay rows are recorded; manual baseline uses actual measured times.

