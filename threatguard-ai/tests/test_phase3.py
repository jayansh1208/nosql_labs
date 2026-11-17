import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import backend.app.database.connection as db_connection
import backend.app.main as app_module
import backend.app.routes.auth as auth_routes
import backend.app.routes.scanner as scanner_routes
import backend.app.security as security_module
from backend.app.database.init_db import initialize_database
from backend.app.scanner.risk_engine import classify_risk
from backend.app.scanner.scanner_service import collect_scan_report

TEST_DB_NAME = os.getenv("THREATGUARD_TEST_DB", f"threatguard_test_{uuid.uuid4().hex}")


def _clear_test_records(db):
    for collection_name in db.list_collection_names():
        db[collection_name].delete_many({})


@pytest.fixture
def test_db():
    from pymongo import MongoClient

    client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27030"))
    db = client[TEST_DB_NAME]
    _clear_test_records(db)
    initialize_database(db)
    yield db
    _clear_test_records(db)
    client.close()


def test_risk_classification_and_scan_report_generation():
    findings = [
        {"severity": "high", "category": "process", "title": "Suspicious service"},
        {"severity": "medium", "category": "network", "title": "Open listener"},
        {"severity": "low", "category": "startup", "title": "Persistent task"},
    ]
    summary = classify_risk(findings)
    assert summary["severity"] == "high"
    assert summary["total_findings"] == 3

    report = collect_scan_report(
        host="windows-host",
        scanner_name="phase3-unit",
        findings=findings,
        source="unit-test",
    )
    assert report["host"] == "windows-host"
    assert report["summary"]["severity"] == "high"
    assert len(report["findings"]) == 3


def test_scanner_route_requires_auth_and_persists_results(
    test_db, create_test_user, login_test_user
):
    auth_routes.get_db = lambda: test_db
    db_connection.get_db = lambda: test_db
    scanner_routes._get_db = lambda: test_db
    security_module.get_db = lambda: test_db

    app = TestClient(app_module.app)

    # Public registration must remain disabled.
    registration = app.post(
        "/auth/register",
        json={
            "org_id": "org-1",
            "tenant_id": "tenant-a",
            "email": "scan-user@example.com",
            "password": "S3cur3!Pass",
            "display_name": "Scanner User",
            "role": "security_analyst",
        },
    )
    assert registration.status_code == 403

    # Create a user directly in the isolated test database.
    create_test_user(
        test_db,
        org_id="org-1",
        tenant_id="tenant-a",
        email="scan-user@example.com",
        display_name="Scanner User",
    )

    headers = login_test_user(app, email="scan-user@example.com")

    scan_payload = {
        "host": "windows-host",
        "scanner_name": "phase3-route",
        "findings": [
            {
                "severity": "high",
                "category": "process",
                "title": "Suspicious process",
                "description": "Unexpected binary",
            },
        ],
    }

    response = app.post(
        "/scanner/scans",
        json=scan_payload,
        headers=headers,
    )
    assert response.status_code == 201

    body = response.json()
    assert body["summary"]["severity"] == "high"
    assert body["host"] == "windows-host"

    assert test_db.scan_results.count_documents(
        {"org_id": "org-1", "tenant_id": "tenant-a"}
    ) >= 1

    list_response = app.get(
        "/scanner/scans",
        params={"org_id": "org-1", "tenant_id": "tenant-a"},
        headers=headers,
    )
    assert list_response.status_code == 200
    assert list_response.json()["total"] >= 1
def test_cli_exports_json_file(tmp_path):
    import importlib.util

    module_path = Path(__file__).resolve().parents[1] / "scanner" / "cli.py"
    spec = importlib.util.spec_from_file_location("scanner_cli_module", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)

    output_path = tmp_path / "scan-output.json"
    exit_code = module.main([
        "--host",
        "windows-host",
        "--scanner-name",
        "phase3-cli",
        "--output",
        str(output_path),
        "--limit",
        "1",
    ])
    assert exit_code == 0
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["host"] == "windows-host"
    assert "findings" in data
    assert len(data["findings"]) <= 1
    assert data["observation_mode"] == "live"
    assert "completeness" in data
    assert all("status" in collector and "scanned_at" in collector for collector in data["collectors"])
