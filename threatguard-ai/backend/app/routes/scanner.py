from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

import backend.app.database.connection as db_connection
from backend.app.database.repositories import ScanRepository, serialize_document
from backend.app.scanner.scanner_service import collect_scan_report
from backend.app.security import enforce_permission, enforce_tenant_context, get_current_user

router = APIRouter(prefix="/scanner", tags=["scanner"])


def _get_db():
    return db_connection.get_db()


@router.post("/scans", status_code=201)
def create_scan(
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    enforce_permission(current_user, "write_threats")
    org_id = payload.get("org_id") or current_user["org_id"]
    tenant_id = payload.get("tenant_id") or current_user["tenant_id"]
    enforce_tenant_context(current_user, org_id, tenant_id)

    if "collectors" in payload and "summary" in payload and isinstance(payload.get("summary"), dict):
        # Pre-collected structured report submitted via CLI or UI
        summary_dict = payload["summary"]
        summary_text = summary_dict.get("summary") or "Scan completed."
        scan_id = payload.get("scan_id") or f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        findings = payload.get("findings") or []
        completeness = payload.get("completeness") or {"status": "complete", "complete": True}
        collectors = payload.get("collectors") or []
        host = payload.get("host") or "unknown-host"
        scanner_name = payload.get("scanner_name") or "native-windows-scanner"
        obs_mode = payload.get("observation_mode") or "live"
        record = ScanRepository(_get_db()).create(
            {
                "org_id": current_user["org_id"],
                "tenant_id": current_user["tenant_id"],
                "scan_id": scan_id,
                "scan_type": scanner_name,
                "status": payload.get("status", "completed"),
                "summary": summary_text,
                "details": {
                    "host": host,
                    "source": payload.get("source", "api_submission"),
                    "observation_mode": obs_mode,
                    "generated_at": payload.get("generated_at"),
                    "summary": summary_dict,
                    "findings": findings,
                    "findings_collected": payload.get("findings_collected", len(findings)),
                    "findings_included": payload.get("findings_included", len(findings)),
                    "completeness": completeness,
                    "collectors": collectors,
                    "defender": payload.get("defender"),
                },
            }
        )
        serialized = serialize_document(record)
        serialized["summary"] = summary_dict
        serialized["findings"] = findings
        serialized["host"] = host
        serialized["completeness"] = completeness
        serialized["collectors"] = collectors
        serialized["observation_mode"] = obs_mode
        return serialized

    findings = payload.get("findings") or []
    report = collect_scan_report(
        host=payload.get("host"),
        scanner_name=payload.get("scanner_name", "native-windows-scanner"),
        findings=findings,
        source=payload.get("source", "api"),
        limit=int(payload.get("limit", 20)),
    )

    record = ScanRepository(_get_db()).create(
        {
            "org_id": current_user["org_id"],
            "tenant_id": current_user["tenant_id"],
            "scan_id": report["scan_id"],
            "scan_type": report["scanner_name"],
            "status": report["status"],
            "summary": report["summary"]["summary"],
            "details": {
                "host": report.get("host"),
                "source": report.get("source"),
                    "observation_mode": report.get("observation_mode"),
                "generated_at": report.get("generated_at"),
                "summary": report.get("summary"),
                "findings": report.get("findings", []),
                    "findings_collected": report.get("findings_collected"),
                    "findings_included": report.get("findings_included"),
                    "completeness": report.get("completeness"),
                    "collectors": report.get("collectors"),
                "defender": report.get("defender"),
            },
        }
    )
    serialized = serialize_document(record)
    serialized["summary"] = report["summary"]
    serialized["findings"] = report["findings"]
    serialized["host"] = report.get("host")
    serialized["completeness"] = report["completeness"]
    serialized["collectors"] = report["collectors"]
    serialized["observation_mode"] = report["observation_mode"]
    return serialized


@router.get("/scans")
def list_scans(
    org_id: str = Query(..., min_length=1),
    tenant_id: str = Query(..., min_length=1),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    enforce_tenant_context(current_user, org_id, tenant_id)
    return ScanRepository(_get_db()).list(org_id=current_user["org_id"], tenant_id=current_user["tenant_id"], page=page, page_size=page_size)


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: str,
    org_id: str = Query(..., min_length=1),
    tenant_id: str = Query(..., min_length=1),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    enforce_tenant_context(current_user, org_id, tenant_id)
    result = _get_db()["scan_results"].find_one({"scan_id": scan_id, "org_id": current_user["org_id"], "tenant_id": current_user["tenant_id"]})
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found for this tenant")
    serialized = serialize_document(result)
    serialized["summary"] = result.get("details", {}).get("summary") or {"severity": "low", "total_findings": 0, "summary": result.get("summary", "")}
    return serialized


@router.get("/scans/{scan_id}/summary")
def get_scan_summary(
    scan_id: str,
    org_id: str = Query(..., min_length=1),
    tenant_id: str = Query(..., min_length=1),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    enforce_tenant_context(current_user, org_id, tenant_id)
    result = _get_db()["scan_results"].find_one({"scan_id": scan_id, "org_id": current_user["org_id"], "tenant_id": current_user["tenant_id"]})
    if result is None:
        raise HTTPException(status_code=404, detail="Scan summary not found")
    return result.get("details", {}).get("summary") or {"severity": "low", "total_findings": 0, "summary": result.get("summary", "")}
