# Approval flow

Each processed alert creates a server-side pending decision record for 24 hours. Slack's signed interactive request or Telegram's configured webhook secret is checked before resolving a callback. The manual API requires the service bearer token. Decisions are one-shot; repeated and expired decisions are rejected. Actor identifier, UTC time, decision, mode, and response result are written to JSONL.

No response is run on notification failure, reject, expiry, missing callback, malformed payload, or missing approval. Approval alone is not enough to run arbitrary commands: the only response type is hard-coded `block_ip`, only public IP observables are eligible, and the result is either a dry-run record or atomic text-file update. Rollback removes the matching IP from that file.

The pending registry is in memory for demo use and is lost on restart; production use requires durable state, replay protection, stronger identity binding, retention policy, and a dedicated authorization review.
