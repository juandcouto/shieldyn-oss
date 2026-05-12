from shieldyn_oss.rules import RuleBasedDetector


def test_urgency_and_sensitive_keywords_increase_score():
    detector = RuleBasedDetector()
    result = detector.analyze(
        "Please confirm your password immediately.",
        subject="Urgent: action required",
    )
    assert result.score >= 30
    assert any("High urgency" in item for item in result.indicators)
    assert any("Requests sensitive information" in item for item in result.indicators)


def test_mismatched_url_detected():
    detector = RuleBasedDetector()
    html = '<a href="https://evil.example/login">https://good.example/login</a>'
    result = detector.analyze(html)
    assert any("Mismatched URL" in item for item in result.indicators)


def test_verdict_levels():
    detector = RuleBasedDetector()
    assert detector.verdict(80) == "Phishing attempt confirmed."
    assert detector.verdict(55) == "High probability of phishing."
    assert detector.verdict(30) == "Suspicious characteristics detected."
    assert detector.verdict(10) == "Email appears legitimate."
