from __future__ import annotations

from typing import Any

from pymongo.database import Database

from backend.app.config import CHAT_SCANNER_CONTEXT_LIMIT

SCAN_TERMS = ("scan", "scanner", "finding", "findings", "alert", "host result", "security result")


def scanner_context_requested(question: str, explicit: bool = False) -> bool:
    lowered = question.lower()
    return explicit or any(term in lowered for term in SCAN_TERMS)


def load_scanner_evidence(db: Database, *, org_id: str, tenant_id: str) -> list[dict[str, Any]]:
    """Read only stored scanner records within the authenticated tenant."""
    cursor = (db["scan_results"].find(
        {"org_id": org_id, "tenant_id": tenant_id},
        {"_id": 0, "scan_id": 1, "created_at": 1, "summary": 1, "details.host": 1,
         "details.generated_at": 1, "details.completeness": 1, "details.findings": 1},
    ).sort("created_at", -1).limit(max(1, CHAT_SCANNER_CONTEXT_LIMIT)))
    records = []
    for item in cursor:
        details = item.get("details") or {}
        # Exclude command lines and other raw host fields. Keep only stored, explicit evidence.
        findings = []
        stored_findings = details.get("findings")
        if not isinstance(stored_findings, list):
            stored_findings = []
        for finding in stored_findings[:50]:
            if not isinstance(finding, dict):
                continue
            findings.append({key: str(finding[key])[:1000] for key in (
                "category", "title", "description", "severity") if finding.get(key) is not None})
        records.append({
            "scan_id": item.get("scan_id"),
            "generated_at": details.get("generated_at") or item.get("created_at"),
            "host": details.get("host"),
            "summary": str(details.get("summary") or item.get("summary") or "")[:1500],
            "completeness": details.get("completeness"),
            "findings": findings,
        })
    return records
