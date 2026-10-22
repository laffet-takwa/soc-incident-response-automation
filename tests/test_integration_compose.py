"""Opt-in live Compose smoke test; requires `docker compose up -d`."""

import os

import pytest
import requests


@pytest.mark.skipif(
    os.getenv("RUN_COMPOSE_INTEGRATION") != "1", reason="opt-in Docker Compose test"
)
def test_python_health_and_thehive_status():
    assert requests.get("http://127.0.0.1:8080/health", timeout=3).status_code == 200
    assert requests.get("http://127.0.0.1:9000/api/status", timeout=5).status_code == 200
