# Shieldyn OSS Rules

Open-source subset of Shieldyn focused on rule-based phishing detection, URL parsing utilities, and an evaluation harness.

## Scope
Included:
- Rule-based detection heuristics
- URL extraction and shortener detection
- Optional Safe Browsing checks (no keys included)
- Evaluation harness with synthetic samples

Excluded:
- OAuth, billing, multi-tenant infrastructure, deployments
- AI model weights or inference
- Customer data, internal endpoints, or secrets

## Quickstart
```
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m shieldyn_oss.eval data/samples.jsonl
pytest
```

## Usage
```python
from shieldyn_oss.rules import RuleBasedDetector

sample = "Urgent: verify your account"
result = RuleBasedDetector().analyze(sample, subject="Action required")
print(result.score, result.indicators)
```

## Optional Safe Browsing
The Safe Browsing helper is async and requires your own API key.

```python
import asyncio
from shieldyn_oss.safebrowsing import check_urls_safe_browsing

urls = ["https://example.com"]
flagged = asyncio.run(check_urls_safe_browsing(urls, api_key="YOUR_KEY"))
print(flagged)
```

## License
Apache-2.0. See LICENSE.
