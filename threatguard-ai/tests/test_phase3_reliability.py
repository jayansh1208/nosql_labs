from __future__ import annotations

import json
import subprocess

from backend.app.scanner import defender_scanner, scanner_service
from backend.app.scanner.scanner_service import collect_scan_report, export_scan_report


def result(name, *, status="success", items=None, error_code=None, error_message=None, findings=None):
    return {
        "collector_name": name, "status": status, "items_collected": len(items or []),
        "error_code": error_code, "error_message": error_message,
        "scanned_at": "2026-11-14T00:00:00+00:00", "items": items or [], "findings": findings or [],
    }


def test_failed_collectors_do_not_create_fabricated_findings(monkeypatch):
    failed = lambda name: result(name, status="failed", error_code="ACCESS_ERROR", error_message="collection denied")
    monkeypatch.setattr(scanner_service, "scan_processes", lambda: failed("processes"))
    monkeypatch.setattr(scanner_service, "scan_network_connections", lambda: failed("network"))
    monkeypatch.setattr(scanner_service, "scan_startup_items", lambda: failed("startup"))
    monkeypatch.setattr(scanner_service, "scan_defender_status", lambda: failed("windows_defender"))

    report = collect_scan_report()

    assert report["findings"] == []
    assert report["summary"]["score"] is None
    assert report["summary"]["severity"] == "unknown"
    assert report["completeness"]["status"] == "failed"


def test_empty_successful_collectors_produce_zero_findings(monkeypatch):
    monkeypatch.setattr(scanner_service, "scan_processes", lambda: result("processes"))
    monkeypatch.setattr(scanner_service, "scan_network_connections", lambda: result("network"))
    monkeypatch.setattr(scanner_service, "scan_startup_items", lambda: result("startup"))
    monkeypatch.setattr(scanner_service, "scan_defender_status", lambda: result("windows_defender"))

    report = collect_scan_report()

    assert report["findings"] == []
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["score"] == 0
    assert report["completeness"]["complete"] is True


def test_limit_is_applied_to_combined_report(monkeypatch):
    sample_findings = [
        {"category": "process", "title": "one", "severity": "medium"},
        {"category": "network", "title": "two", "severity": "high"},
        {"category": "startup", "title": "three", "severity": "low"},
    ]
    collectors = [result(name, findings=[finding]) for name, finding in zip(
        ("processes", "network", "startup"), sample_findings
    )]
    monkeypatch.setattr(scanner_service, "scan_processes", lambda: collectors[0])
    monkeypatch.setattr(scanner_service, "scan_network_connections", lambda: collectors[1])
    monkeypatch.setattr(scanner_service, "scan_startup_items", lambda: collectors[2])
    monkeypatch.setattr(scanner_service, "scan_defender_status", lambda: result("windows_defender"))

    report = collect_scan_report(limit=1)

    assert len(report["findings"]) == 1
    assert report["findings"][0]["title"] == "one"
    assert report["findings_collected"] == 3
    assert report["findings_included"] == 1


def test_defender_access_denied_is_unknown_and_restricted(monkeypatch):
    monkeypatch.setattr(defender_scanner, "IS_WINDOWS", True)
    monkeypatch.setattr(defender_scanner.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(
        args[0], 1, "", "Get-MpComputerStatus : Access denied (HRESULT 0x80041003)"
    ))

    status = defender_scanner.scan_defender_status()

    assert status["status"] == "permission_restricted"
    assert status["defender_status"] == "unknown"
    assert status["enabled"] is None
    assert status["error_code"] == "ACCESS_DENIED"
    assert "Access denied" in status["error_message"]


def test_failed_collectors_and_export_preserve_status_and_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner_service, "scan_processes", lambda: result(
        "processes", status="failed", error_code="POWERSHELL_EXIT_1", error_message="access denied"
    ))
    monkeypatch.setattr(scanner_service, "scan_network_connections", lambda: result("network"))
    monkeypatch.setattr(scanner_service, "scan_startup_items", lambda: result("startup"))
    monkeypatch.setattr(scanner_service, "scan_defender_status", lambda: result("windows_defender"))
    report = collect_scan_report()
    assert any(item["collector_name"] == "processes" and item["status"] == "failed"
               for item in report["collectors"])

    output = tmp_path / "report.json"
    export_scan_report(report, output)
    saved = json.loads(output.read_text(encoding="utf-8"))
    process = next(item for item in saved["collectors"] if item["collector_name"] == "processes")
    assert process["error_code"] == "POWERSHELL_EXIT_1"
    assert process["error_message"] == "access denied"
    assert process["scanned_at"] == "2026-11-14T00:00:00+00:00"
    assert saved["completeness"]["status"] == "partial"
