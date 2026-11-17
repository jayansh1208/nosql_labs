from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

import backend.app.database.connection as db_connection
import backend.app.main as app_module
import backend.app.routes.auth as auth_routes
import backend.app.routes.dashboard as dashboard_routes
import backend.app.routes.scanner as scanner_routes
import backend.app.security as security_module
from backend.app.database.init_db import initialize_database


@pytest.fixture
def dashboard_db():
    db_name = os.getenv("THREATGUARD_TEST_DB", f"threatguard_dash_test_{uuid.uuid4().hex}")
    client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27030"), serverSelectionTimeoutMS=5000)
    db = client[db_name]
    for collection_name in db.list_collection_names():
        db[collection_name].delete_many({})
    initialize_database(db)
    try:
        yield db
    finally:
        for collection_name in db.list_collection_names():
            db[collection_name].delete_many({})
        client.close()


def test_dashboard_metrics_unauthorized():
    client = TestClient(app_module.app)
    response = client.get("/dashboard/metrics")
    assert response.status_code == 401


def test_dashboard_metrics_and_user_listing(
    monkeypatch, dashboard_db, create_test_user, login_test_user
):
    monkeypatch.setattr(db_connection, "get_db", lambda: dashboard_db)
    monkeypatch.setattr(auth_routes, "get_db", lambda: dashboard_db)
    monkeypatch.setattr(security_module, "get_db", lambda: dashboard_db)
    monkeypatch.setattr(dashboard_routes, "get_db", lambda: dashboard_db)
    monkeypatch.setattr(scanner_routes, "_get_db", lambda: dashboard_db)

    client = TestClient(app_module.app)

    # Create admin user
    create_test_user(
        dashboard_db,
        org_id="org-dash",
        tenant_id="tenant-dash-1",
        email="dash-admin@example.com",
        role="super_admin",
        display_name="Dashboard Admin",
    )
    headers = login_test_user(client, email="dash-admin@example.com")

    # Insert test threat
    dashboard_db["threats"].insert_one({
        "org_id": "org-dash",
        "tenant_id": "tenant-dash-1",
        "threat_id": "thr-dash-01",
        "title": "Privilege Escalation Alert",
        "description": "Suspicious admin process",
        "severity": "high",
        "lifecycle_status": "Active",
        "source": "Host Scanner",
        "confidence": 0.95,
        "tags": ["process"],
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    })

    # Insert threat for different tenant (must be isolated)
    dashboard_db["threats"].insert_one({
        "org_id": "org-dash",
        "tenant_id": "tenant-dash-2",
        "threat_id": "thr-dash-other",
        "title": "Other Tenant Threat",
        "description": "Cross-tenant threat test",
        "severity": "critical",
        "lifecycle_status": "Active",
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    })

    # Query metrics
    response = client.get("/dashboard/metrics", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["status"] == "ok"
    assert data["system_status"]["backend"] == "ok"
    assert data["system_status"]["mongo"] == "connected"
    assert data["metrics"]["total_threats"] == 1
    assert data["metrics"]["severity_distribution"]["high"] == 1
    assert data["metrics"]["severity_distribution"]["critical"] == 0
    assert data["metrics"]["lifecycle_distribution"]["Active"] == 1
    assert len(data["recent_threats"]) == 1
    assert data["recent_threats"][0]["threat_id"] == "thr-dash-01"

    # Test pre-collected report submission preserves live mode
    scan_report_payload = {
        "scan_id": "scan-precollected-001",
        "scanner_name": "native-windows-scanner",
        "host": "test-workstation",
        "source": "cli_test",
        "observation_mode": "live",
        "status": "completed",
        "completeness": {"status": "complete", "complete": True},
        "summary": {
            "severity": "medium",
            "total_findings": 1,
            "score": 2,
            "highest_risk": "Open listener",
            "summary": "One open listener detected.",
        },
        "findings": [
            {
                "severity": "medium",
                "category": "network",
                "title": "Open listener",
                "description": "Port 8080 listening",
            }
        ],
        "collectors": [{"collector_name": "processes", "status": "success", "items_collected": 10}],
    }
    submit_res = client.post("/scanner/scans", json=scan_report_payload, headers=headers)
    assert submit_res.status_code == 201
    saved_scan = submit_res.json()
    assert saved_scan["scan_id"] == "scan-precollected-001"
    assert saved_scan["observation_mode"] == "live"
    assert saved_scan["summary"]["severity"] == "medium"

    # Verify metrics updated
    metrics_res = client.get("/dashboard/metrics", headers=headers)
    assert metrics_res.json()["metrics"]["total_scans"] == 1
    assert len(metrics_res.json()["recent_scans"]) == 1

    # Test GET /auth/users
    users_res = client.get("/auth/users", headers=headers)
    assert users_res.status_code == 200
    users_data = users_res.json()
    assert users_data["total"] >= 1
    assert all("password_hash" not in u for u in users_data["items"])
