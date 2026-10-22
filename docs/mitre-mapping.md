# Illustrative MITRE ATT&CK mapping

These are mappings for synthetic portfolio scenarios, not claims that a fixture represents an actual adversary technique.

| Synthetic scenario | ATT&CK technique | Rationale |
| --- | --- | --- |
| Repeated authentication failures | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Alert simulates repeated failed logins. |
| Suspicious DNS lookup / external URL | [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) | Illustrates triage of a possible C2 communication indicator; the fixture alone is not proof. |
| File hash detection | [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002/) | Illustrates a suspicious-file triage scenario, without asserting user execution occurred. |
