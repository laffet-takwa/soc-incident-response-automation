# Contributing

Contributions should use synthetic/anonymized fixtures and preserve the explicit human approval boundary. Do not add real API keys, customer data, or automated host-firewall changes.

Set up with Python 3.11+, then run `python -m pip install -e ".[dev]"`, `ruff check .`, and `pytest`. External HTTP behavior must be tested with mocks. Document any service behavior not verified against the live lab as “tested with mocks only.” Add tests for parser, scoring, error, and approval behavior when changing those paths.
