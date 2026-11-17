from __future__ import annotations

import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from backend.app.scanner.defender_scanner import scan_defender_status
from backend.app.scanner.network_scanner import scan_network_connections
from backend.app.scanner.process_scanner import scan_processes
from backend.app.scanner.risk_engine import classify_risk
from backend.app.scanner.startup_scanner import scan_startup_items


def _normalize_finding(item: dict[str, Any]) -> dict[str, Any]:
    finding = dict(item)
    finding.setdefault("severity", "low")
    finding.setdefault("category", "unknown")
    finding.setdefault("title", "Unlabeled finding")
    finding.setdefault("description", "No description provided.")
    return finding


def _completeness(collectors: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = [item["status"] for item in collectors]
    if all(status == "success" for status in statuses):
        status = "complete"
    elif any(status == "success" for status in statuses):
        status = "partial"
    else:
        status = "failed"
    return {"status": status, "complete": status == "complete", "collectors_total": len(collectors),
            "collectors_succeeded": statuses.count("success"),
            "collectors_failed": sum(s in {"failed", "permission_restricted", "unsupported"} for s in statuses)}


def collect_scan_report(
    *, host: str | None = None, scanner_name: str = "native-windows-scanner",
    findings: Iterable[dict[str, Any]] | None = None, source: str = "native_windows_cli",
    limit: int = 20,
) -> dict[str, Any]:
    host_name = host or platform.node() or "unknown-host"
    generated_at = datetime.now(timezone.utc).isoformat()
    if findings is not None:
        # Explicitly supplied observations are for simulated/demo or test reports.
        all_findings = [_normalize_finding(item) for item in findings]
        collectors = [{"collector_name": "provided_findings", "status": "success",
                       "items_collected": len(all_findings), "error_code": None,
                       "error_message": None, "scanned_at": generated_at}]
        defender = {"collector_name": "windows_defender", "status": "unsupported",
                    "items_collected": 0, "error_code": "NOT_RUN_SIMULATED_REPORT",
                    "error_message": "Defender collection is not run for simulated reports.",
                    "scanned_at": generated_at, "available": None, "enabled": None,
                    "defender_status": "unknown"}
        observation_mode = "simulated"
    else:
        collector_results = [scan_processes(), scan_network_connections(), scan_startup_items()]
        defender = scan_defender_status()
        collectors = [{key: result.get(key) for key in (
            "collector_name", "status", "items_collected", "error_code", "error_message", "scanned_at")}
            for result in [*collector_results, defender]]
        all_findings = [_normalize_finding(item) for result in [*collector_results, defender] for item in result.get("findings", [])]
        observation_mode = "live"

    safe_limit = max(0, limit)
    included_findings = all_findings[:safe_limit]
    coverage = _completeness(collectors)
    if observation_mode == "simulated":
        coverage.update({"status": "simulated", "complete": None, "coverage_applicable": False})
    else:
        coverage["coverage_applicable"] = True
    summary = classify_risk(included_findings)
    if observation_mode == "live" and not coverage["complete"]:
        summary.update({"severity": "unknown", "score": None,
                        "summary": "Coverage is incomplete; risk severity and score are withheld.",
                        "coverage_incomplete": True})
    else:
        summary["coverage_incomplete"] = False
    return {
        "scan_id": f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "host": host_name, "scanner_name": scanner_name, "source": source,
        "observation_mode": observation_mode, "status": "completed",
        "generated_at": generated_at, "completeness": coverage,
        "summary": summary, "findings": included_findings,
        "findings_collected": len(all_findings), "findings_included": len(included_findings),
        "collectors": collectors, "defender": defender,
    }


def export_scan_report(report: dict[str, Any], output_path: str | os.PathLike[str] | None = None) -> str | None:
    if output_path is None:
        return None
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return str(destination)


def submit_scan_report(report: dict[str, Any], db=None, *, org_id: str | None = None, tenant_id: str | None = None) -> dict[str, Any]:
    if db is None or org_id is None or tenant_id is None:
        return report
    from backend.app.database.repositories import ScanRepository

    repo = ScanRepository(db)
    payload = {
        "org_id": org_id, "tenant_id": tenant_id, "scan_id": report["scan_id"],
        "scan_type": report["scanner_name"], "status": report["status"],
        "summary": report["summary"]["summary"],
        "details": {key: report.get(key) for key in (
            "host", "source", "observation_mode", "generated_at", "summary", "findings",
            "findings_collected", "findings_included", "completeness", "collectors", "defender")},
    }
    return repo.create(payload)
