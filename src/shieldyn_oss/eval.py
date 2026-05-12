"""Evaluation harness for rule-based phishing detection."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
from typing import Iterable, List

from .rules import RuleBasedDetector


@dataclass
class Sample:
    subject: str
    content: str
    label: str  # "phishing" or "safe"


def load_samples(path: str) -> List[Sample]:
    samples: List[Sample] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            samples.append(
                Sample(
                    subject=obj.get("subject", ""),
                    content=obj.get("content", ""),
                    label=obj.get("label", "safe"),
                )
            )
    return samples


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def evaluate_samples(
    samples: Iterable[Sample],
    detector: RuleBasedDetector,
    threshold: float = 50.0,
) -> dict:
    tp = tn = fp = fn = 0

    for sample in samples:
        result = detector.analyze(sample.content, subject=sample.subject)
        predicted = "phishing" if result.score >= threshold else "safe"
        actual = sample.label

        if predicted == "phishing" and actual == "phishing":
            tp += 1
        elif predicted == "safe" and actual == "safe":
            tn += 1
        elif predicted == "phishing" and actual == "safe":
            fp += 1
        elif predicted == "safe" and actual == "phishing":
            fn += 1

    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate phishing rules on samples")
    parser.add_argument("path", help="Path to JSONL samples")
    parser.add_argument("--threshold", type=float, default=50.0, help="Score threshold")
    args = parser.parse_args()

    detector = RuleBasedDetector()
    samples = load_samples(args.path)
    metrics = evaluate_samples(samples, detector, threshold=args.threshold)

    print(json.dumps(metrics, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
