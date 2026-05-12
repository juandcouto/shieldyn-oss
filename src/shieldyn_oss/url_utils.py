"""URL parsing helpers for phishing rules."""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bit.do",
    "mcaf.ee",
    "rb.gy",
    "cutt.ly",
    "short.io",
    "tiny.cc",
}

_URL_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+")


def clean_url(url: str) -> str:
    u = url.strip()
    u = re.sub(r"[,.)\]\}>]+$", "", u)
    return u


def extract_urls(content: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from content, including HTML hrefs."""
    if not content:
        return []

    raw_urls = _URL_REGEX.findall(content)

    # Also extract from HTML anchors
    try:
        soup = BeautifulSoup(content, "html.parser")
        html_urls = [link.get("href") for link in soup.find_all("a", href=True)]
        raw_urls.extend(html_urls)
    except Exception:
        pass

    cleaned = []
    for url in raw_urls:
        if not url:
            continue
        u = clean_url(url)
        if not u:
            continue
        if u.startswith("www."):
            u = f"http://{u}"
        if u.startswith("http://") or u.startswith("https://"):
            cleaned.append(u)

    # Dedupe while preserving order
    seen = set()
    unique = []
    for u in cleaned:
        if u in seen:
            continue
        unique.append(u)
        seen.add(u)
    return unique


def is_shortener_url(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
        return host.lstrip("www.") in URL_SHORTENER_DOMAINS
    except Exception:
        return False
