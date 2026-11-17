from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_severity(value: Any) -> str:
    level = str(value or "").strip().lower()
    if level in SEVERITY_RANK:
        return level
    return "low"


def classify_risk(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    findings_list = list(findings or [])
    if not findings_list:
        return {
            "severity": "low",
            "total_findings": 0,
            "score": 0,
            "highest_risk": "No findings",
            "summary": "No suspicious host activity detected.",
            "counts": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        }

    counts = Counter({"low": 0, "medium": 0, "high": 0, "critical": 0})
    for item in findings_list:
        severity = normalize_severity(item.get("severity"))
        counts[severity] += 1

    highest = max(findings_list, key=lambda item: SEVERITY_RANK.get(normalize_severity(item.get("severity")), 0))
    severity = normalize_severity(highest.get("severity"))
    score = sum(SEVERITY_RANK.get(normalize_severity(item.get("severity")), 0) for item in findings_list)
    summary = (
        "Host requires review because at least one high-risk indicator was detected."
        if severity in {"high", "critical"}
        else "Host shows moderate or low-risk indicators that should be monitored."
    )

    return {
        "severity": severity,
        "total_findings": len(findings_list),
        "score": score,
        "highest_risk": highest.get("title") or highest.get("category") or "Unknown finding",
        "summary": summary,
        "counts": {key: counts.get(key, 0) for key in ("low", "medium", "high", "critical")},
    }
