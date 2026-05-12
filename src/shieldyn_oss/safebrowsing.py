"""Optional Google Safe Browsing checks (no API keys included)."""

from __future__ import annotations

from typing import Iterable, Set
from urllib.parse import urlparse

import httpx

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def check_urls_safe_browsing(
    urls: Iterable[str],
    api_key: str | None,
    timeout: float = 8.0,
) -> Set[str]:
    """Return URLs flagged by Safe Browsing. Requires an API key."""
    if not api_key:
        return set()

    cleaned = []
    for url in urls:
        if not url:
            continue
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            continue
        cleaned.append(url)

    if not cleaned:
        return set()

    # Dedupe and cap to 500 URLs per request
    unique_urls = list(dict.fromkeys(cleaned))[:500]

    payload = {
        "client": {"clientId": "shieldyn-oss", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in unique_urls],
        },
    }

    try:
        async with httpx.AsyncClient(headers={"User-Agent": "Shieldyn-OSS/0.1"}) as client:
            resp = await client.post(
                f"{SAFE_BROWSING_ENDPOINT}?key={api_key}",
                json=payload,
                timeout=timeout,
            )
            if resp.status_code != 200:
                return set()
            matches = resp.json().get("matches", [])
            return {m["threat"]["url"] for m in matches if "threat" in m}
    except Exception:
        return set()
