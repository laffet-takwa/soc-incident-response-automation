"""Extract validated public indicators from untrusted alert content."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

IOC_PATTERNS = {
    "ipv4": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    "ipv6": re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])"),
    "domain": re.compile(
        r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])"
    ),
    "url": re.compile(r"(?i)https?://[^\s\"'<>]+"),
    "hash": re.compile(r"(?i)(?<![a-f0-9])(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})(?![a-f0-9])"),
}
HASH_TYPE = {32: "md5", 40: "sha1", 64: "sha256"}
PRIVATE_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".localhost",
    ".test",
    ".invalid",
    ".example",
    ".corp",
    ".home",
    ".intranet",
    ".private",
)


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def _public_domain(value: str) -> bool:
    host = value.lower().rstrip(".")
    if host in {"example.com", "example.net", "example.org"} or host.endswith(
        (".example.com", ".example.net", ".example.org")
    ):
        return False
    if host == "localhost" or host.endswith(PRIVATE_SUFFIXES):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return "." in host


def _public_url(value: str) -> bool:
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return False
    if not host:
        return False
    return (
        _public_ip(host) if ":" in host or re.fullmatch(r"[\d.]+", host) else _public_domain(host)
    )


def _allowlisted(value: str, allowlist: set[str]) -> bool:
    candidate = value.lower().strip()
    host = candidate
    if candidate.startswith(("http://", "https://")):
        try:
            host = urlsplit(candidate).hostname or ""
        except ValueError:
            host = ""
    for protected in allowlist:
        suffix = protected.removeprefix("*.").lstrip(".")
        if candidate == protected or host == suffix or host.endswith("." + suffix):
            return True
    return False


def extract_iocs(text: str, allowlist: set[str] | None = None) -> list[dict[str, str]]:
    """Return deduplicated public IPs/domains/URLs and file hashes."""
    allow = {item.lower().strip() for item in (allowlist or set()) if item.strip()}
    values: dict[tuple[str, str], dict[str, str]] = {}

    for raw in IOC_PATTERNS["url"].findall(text):
        candidate = raw.rstrip(".,);]")
        if _public_url(candidate) and not _allowlisted(candidate, allow):
            values[("url", candidate)] = {"type": "url", "value": candidate}

    for raw in IOC_PATTERNS["ipv4"].findall(text):
        if _public_ip(raw) and not _allowlisted(raw, allow):
            values[("ip", raw)] = {"type": "ip", "value": raw}

    for raw in IOC_PATTERNS["ipv6"].findall(text):
        if _public_ip(raw) and not _allowlisted(raw, allow):
            values[("ip", raw)] = {"type": "ip", "value": raw}

    for raw in IOC_PATTERNS["domain"].findall(text):
        candidate = raw.rstrip(".")
        if _public_domain(candidate) and not _allowlisted(candidate, allow):
            values[("domain", candidate.lower())] = {"type": "domain", "value": candidate.lower()}

    for raw in IOC_PATTERNS["hash"].findall(text):
        candidate = raw.lower()
        if not _allowlisted(candidate, allow):
            values[("hash", candidate)] = {
                "type": "hash",
                "hash_type": HASH_TYPE[len(candidate)],
                "value": candidate,
            }

    return sorted(values.values(), key=lambda item: (item["type"], item["value"]))


def safe_alert_id(value: str) -> str:
    """Build a stable external identifier without trusting source identifiers."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:24]
