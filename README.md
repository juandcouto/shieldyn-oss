# Shieldyn OSS

[![CI](https://github.com/juandcouto/shieldyn-oss/actions/workflows/ci.yml/badge.svg)](https://github.com/juandcouto/shieldyn-oss/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

Open-source subset of Shieldyn focused on rule-based phishing detection, URL parsing utilities, and an evaluation harness.

## What is included
- Rule-based detection heuristics
- URL extraction and shortener detection
- Optional Safe Browsing checks (no keys included)
- Evaluation harness with synthetic samples

## What is not included
- OAuth, billing, multi-tenant infrastructure, deployments
- AI model weights or inference
- Customer data, internal endpoints, or secrets

## Install
```
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quickstart
```
python -m shieldyn_oss.eval data/samples.jsonl
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

## Development
```
pip install -e ".[dev]"
pytest
```

## Security
If you discover a security issue, see SECURITY.md.

## License
Apache-2.0. See LICENSE.
