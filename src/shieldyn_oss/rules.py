"""Rule-based phishing detection heuristics."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import List

from bs4 import BeautifulSoup

from .url_utils import extract_urls, is_shortener_url


@dataclass
class RuleBasedResult:
    score: float
    indicators: List[str]
    urgency_count: int
    sensitive_count: int
    threat_count: int


class RuleBasedDetector:
    """Rule-based phishing detection using keyword and URL heuristics."""

    URGENCY_KEYWORDS = [
        "urgent",
        "immediately",
        "action required",
        "verify",
        "suspended",
        "locked",
        "expires",
        "expiring",
        "limited time",
        "act now",
        "confirm",
        "update",
        "security alert",
        "unusual activity",
    ]

    SENSITIVE_KEYWORDS = [
        "password",
        "credit card",
        "ssn",
        "social security",
        "bank account",
        "routing number",
        "pin",
        "cvv",
        "tax id",
        "account number",
        "wire transfer",
    ]

    THREAT_KEYWORDS = [
        "lawsuit",
        "legal action",
        "arrest",
        "police",
        "warrant",
        "court",
        "fine",
        "penalty",
    ]

    IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    def analyze(self, email_content: str, subject: str = "") -> RuleBasedResult:
        indicators: List[str] = []
        score = 0.0

        email_content = email_content or ""
        subject = subject or ""

        full_text = f"{subject} {email_content}"
        lower_text = full_text.lower()

        urgency_count = sum(1 for keyword in self.URGENCY_KEYWORDS if keyword in lower_text)
        if urgency_count > 0:
            indicators.append(f"High urgency language ({urgency_count} phrases)")
            score += min(urgency_count * 10, 30)

        sensitive_count = sum(1 for keyword in self.SENSITIVE_KEYWORDS if keyword in lower_text)
        if sensitive_count > 0:
            indicators.append(f"Requests sensitive information ({sensitive_count} types)")
            score += min(sensitive_count * 15, 35)

        threat_count = sum(1 for keyword in self.THREAT_KEYWORDS if keyword in lower_text)
        if threat_count > 0:
            indicators.append("Threatening language detected")
            score += 25

        ip_matches = re.findall(self.IP_PATTERN, email_content)
        if ip_matches:
            indicators.append("IP address found in URL")
            score += 20

        urls = extract_urls(email_content)
        if any(is_shortener_url(u) for u in urls):
            indicators.append("URL shortener detected")
            score += 15

        if self._has_suspicious_domain(email_content):
            indicators.append("Suspicious domain pattern detected")
            score += 20

        generic_greetings = ["dear customer", "dear user", "dear member", "hello user"]
        if any(greeting in lower_text for greeting in generic_greetings):
            indicators.append("Generic greeting (no personalization)")
            score += 10

        if self._has_mismatched_urls(email_content):
            indicators.append("Mismatched URL detected (display != actual)")
            score += 25

        if self._has_excessive_emphasis(full_text):
            indicators.append("Excessive punctuation or CAPS")
            score += 10

        score = min(score, 100.0)

        return RuleBasedResult(
            score=score,
            indicators=indicators,
            urgency_count=urgency_count,
            sensitive_count=sensitive_count,
            threat_count=threat_count,
        )

    def verdict(self, score: float) -> str:
        if score >= 75:
            return "Phishing attempt confirmed."
        if score >= 50:
            return "High probability of phishing."
        if score >= 25:
            return "Suspicious characteristics detected."
        return "Email appears legitimate."

    def _has_suspicious_domain(self, text: str) -> bool:
        suspicious_patterns = [
            r"paypa1",
            r"g00gle",
            r"micros0ft",
            r"amazan",
            r"bank.*verify",
            r"secure.*login",
            r"account.*update",
        ]
        return any(re.search(pattern, text.lower()) for pattern in suspicious_patterns)

    def _has_mismatched_urls(self, html_content: str) -> bool:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            links = soup.find_all("a", href=True)
            for link in links:
                href = (link.get("href") or "").lower()
                text = (link.get_text() or "").lower()
                if "http" in text and href != text:
                    href_domain = re.search(r"https?://([^/]+)", href)
                    text_domain = re.search(r"https?://([^/]+)", text)
                    if href_domain and text_domain:
                        if href_domain.group(1) != text_domain.group(1):
                            return True
            return False
        except Exception:
            return False

    def _has_excessive_emphasis(self, text: str) -> bool:
        if len(text) > 20:
            caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
            if caps_ratio > 0.3:
                return True
        if text.count("!") > 3:
            return True
        return False
