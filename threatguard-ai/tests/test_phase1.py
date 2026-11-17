import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient
from pymongo.errors import OperationFailure

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import backend.app.main as app_module
import backend.app.routes.auth as auth_routes
import backend.app.routes.threats as threat_routes
import backend.app.security as security_module
from backend.app.database.init_db import initialize_database
from backend.app.database.repositories import ThreatRepository

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27030")
TEST_DB_NAME = os.getenv("THREATGUARD_TEST_DB", f"threatguard_test_{uuid.uuid4().hex}")


def _clear_test_records(db):
    for collection_name in db.list_collection_names():
        db[collection_name].delete_many({})


@pytest.fixture
def test_db():
    client = MongoClient(MONGO_URI)
    db = client[TEST_DB_NAME]
    _clear_test_records(db)
    initialize_database(db)
    yield db
    _clear_test_records(db)
    client.close()


def valid_threat_payload(org_id: str = "org-1", tenant_id: str = "tenant-a", threat_id: str = "thr-001") -> dict:
    return {
        "org_id": org_id,
        "tenant_id": tenant_id,
        "threat_id": threat_id,
        "title": "Privilege escalation attempt",
        "description": "Suspicious account activity in admin console.",
        "severity": "high",
        "lifecycle_status": "Active",
        "source": "SIEM",
        "confidence": 0.91,
        "tags": ["identity", "admin"],
    }


def test_database_initialization_creates_required_collections(test_db):
    expected = {
        "organizations",
        "tenants",
        "users",
        "threats",
        "scan_results",
        "mitigations",
        "kb_documents",
        "kb_chunks",
        "chat_sessions",
        "audit_logs",
        "metrics_snapshots",
    }
    assert expected.issubset(set(test_db.list_collection_names()))


def test_collection_creation_and_schema_validation(test_db):
    unique_payload = valid_threat_payload()
    repo = ThreatRepository(test_db)
    repo.create(unique_payload)
    assert test_db.threats.count_documents({"tenant_id": "tenant-a"}) == 1


def test_valid_threat_insertion(test_db):
    repo = ThreatRepository(test_db)
    result = repo.create(valid_threat_payload())
    assert result["threat_id"] == "thr-001"
    assert result["lifecycle_status"] == "Active"


def test_invalid_threat_status_rejection(test_db):
    repo = ThreatRepository(test_db)
    payload = valid_threat_payload(threat_id="thr-002")
    payload["lifecycle_status"] = "Unknown"
    with pytest.raises(ValueError):
        repo.create(payload)

    with pytest.raises(OperationFailure):
        test_db.threats.insert_one({
            "org_id": "org-1",
            "tenant_id": "tenant-a",
            "threat_id": "thr-003",
            "title": "Bad status",
            "description": "invalid schema",
            "severity": "low",
            "lifecycle_status": "Unknown",
            "created_at": __import__("datetime").datetime.utcnow(),
        })


def test_api_cross_tenant_read_and_update_are_rejected(
    test_db, create_test_user, login_test_user
):
    auth_routes.get_db = lambda: test_db
    security_module.get_db = lambda: test_db
    threat_routes.get_db = lambda: test_db

    app = TestClient(app_module.app)

    create_test_user(
        test_db,
        org_id="org-1",
        tenant_id="tenant-a",
        email="analyst-a@example.com",
    )

    headers = login_test_user(app, email="analyst-a@example.com")

    payload = valid_threat_payload(threat_id="thr-api-001")
    created = app.post("/threats", json=payload, headers=headers)
    assert created.status_code == 201, created.text

    wrong_tenant_get = app.get(
        "/threats",
        params={"org_id": "org-1", "tenant_id": "tenant-b"},
        headers=headers,
    )
    assert wrong_tenant_get.status_code == 403

    wrong_tenant_update = app.patch(
        "/threats/thr-api-001/status",
        json={
            "org_id": "org-1",
            "tenant_id": "tenant-b",
            "lifecycle_status": "Resolved",
        },
        headers=headers,
    )
    assert wrong_tenant_update.status_code == 403

def test_missing_tenant_id_rejection(test_db):
    repo = ThreatRepository(test_db)
    payload = valid_threat_payload(threat_id="thr-004")
    payload.pop("tenant_id")
    with pytest.raises(ValueError):
        repo.create(payload)


def test_tenant_a_cannot_read_tenant_b_threats(test_db):
    repo = ThreatRepository(test_db)
    repo.create(valid_threat_payload())
    result = repo.list(org_id="org-1", tenant_id="tenant-b", page=1, page_size=20)
    assert result["total"] == 0
    assert result["items"] == []


def test_tenant_a_cannot_update_tenant_b_threats(test_db):
    repo = ThreatRepository(test_db)
    created = repo.create(valid_threat_payload(threat_id="thr-005"))
    with pytest.raises(ValueError):
        repo.update_status(str(created["_id"]), org_id="org-1", tenant_id="tenant-b", lifecycle_status="Resolved")


def test_pagination(test_db):
    repo = ThreatRepository(test_db)
    for index in range(25):
        repo.create(valid_threat_payload(threat_id=f"thr-{index:03d}"))

    page_one = repo.list(org_id="org-1", tenant_id="tenant-a", page=1, page_size=10)
    page_two = repo.list(org_id="org-1", tenant_id="tenant-a", page=2, page_size=10)

    assert page_one["total"] == 25
    assert len(page_one["items"]) == 10
    assert len(page_two["items"]) == 10
    assert page_one["items"][0]["threat_id"] != page_two["items"][0]["threat_id"]


def test_index_creation(test_db):
    indexes = test_db.threats.index_information()
    index_names = list(indexes.keys())
    assert any("tenant_id" in name and "lifecycle_status" in name for name in index_names)
    assert any("tenant_id" in name and "severity" in name for name in index_names)


def test_repeated_initialization_preserves_existing_data(test_db):
    repo = ThreatRepository(test_db)
    record = repo.create(valid_threat_payload(threat_id="thr-010"))
    before = test_db.threats.count_documents({})
    initialize_database(test_db)
    after = test_db.threats.count_documents({})
    assert before == after == 1
    assert test_db.threats.find_one({"_id": record["_id"]}) is not None


def test_auth_registration_and_successful_login(
    test_db, create_test_user, login_test_user
):
    auth_routes.get_db = lambda: test_db
    security_module.get_db = lambda: test_db
    app = TestClient(app_module.app)

    payload = {
        "org_id": "org-1",
        "tenant_id": "tenant-a",
        "email": "analyst@example.com",
        "password": "S3cur3!Pass",
        "display_name": "Alice Analyst",
        "role": "security_analyst",
    }

    register = app.post("/auth/register", json=payload)
    assert register.status_code == 403

    create_test_user(
        test_db,
        org_id="org-1",
        tenant_id="tenant-a",
        email="analyst@example.com",
        display_name="Alice Analyst",
    )

    headers = login_test_user(app, email="analyst@example.com")

    me = app.get("/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["email"] == payload["email"]
    assert "password_hash" not in me.json()

    assert test_db.audit_logs.count_documents(
        {"action": "login_success"}
    ) >= 1


def test_incorrect_password_and_missing_authentication(test_db):
    auth_routes.get_db = lambda: test_db
    security_module.get_db = lambda: test_db
    app = TestClient(app_module.app)
    payload = {
        "org_id": "org-1",
        "tenant_id": "tenant-a",
        "email": "wrongpass@example.com",
        "password": "S3cur3!Pass",
        "display_name": "Wrong Pass",
        "role": "security_operator",
    }
    app.post("/auth/register", json=payload)

    bad_login = app.post("/auth/login", json={"email": payload["email"], "password": "bad-password"})
    assert bad_login.status_code == 401
    assert test_db.audit_logs.count_documents({"action": "login_failed"}) >= 1

    missing_auth = app.get("/auth/me")
    assert missing_auth.status_code == 401


def test_invalid_and_expired_jwt_are_rejected(test_db):
    auth_routes.get_db = lambda: test_db
    security_module.get_db = lambda: test_db
    app = TestClient(app_module.app)
    invalid = app.get("/auth/me", headers={"Authorization": "Bearer invalid.token.value"})
    assert invalid.status_code == 401

    expired_payload = {
        "sub": "usr-expired",
        "user_id": "usr-expired",
        "email": "expired@example.com",
        "org_id": "org-1",
        "tenant_id": "tenant-a",
        "role": "auditor",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=15),
    }
    expired = jwt.encode(expired_payload, "change-me-to-a-strong-random-secret", algorithm="HS256")
    expired_response = app.get("/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert expired_response.status_code == 401


def test_role_based_permission_denial_and_password_hashing(
    test_db, create_test_user, login_test_user
):
    auth_routes.get_db = lambda: test_db
    security_module.get_db = lambda: test_db
    app = TestClient(app_module.app)

    org_id = "org-1"
    tenant_id = "tenant-a"
    email = "auditor@example.com"
    password = "S3cur3!Pass"

    register = app.post(
        "/auth/register",
        json={
            "org_id": org_id,
            "tenant_id": tenant_id,
            "email": email,
            "password": password,
            "display_name": "Auditor User",
            "role": "auditor",
        },
    )
    assert register.status_code == 403

    create_test_user(
        test_db,
        org_id=org_id,
        tenant_id=tenant_id,
        email=email,
        password=password,
        role="auditor",
        display_name="Auditor User",
    )

    headers = login_test_user(app, email=email)

    denied = app.post(
        "/threats",
        json={
            "org_id": org_id,
            "tenant_id": tenant_id,
            "threat_id": "thr-role-001",
            "title": "Role test",
            "description": "Auditor should not create threats",
            "severity": "high",
            "lifecycle_status": "Active",
            "source": "SIEM",
            "confidence": 0.8,
            "tags": ["test"],
        },
        headers=headers,
    )
    assert denied.status_code == 403

    stored = test_db.users.find_one({"email": email})
    assert stored is not None
    assert stored["password_hash"] != password
    assert stored["password_hash"].startswith("$2b$")


def test_cross_tenant_access_denied_and_audit_event_recorded(
    test_db, create_test_user, login_test_user
):
    auth_routes.get_db = lambda: test_db
    security_module.get_db = lambda: test_db
    app = TestClient(app_module.app)

    create_test_user(
        test_db,
        org_id="org-1",
        tenant_id="tenant-a",
        email="tenant-a@example.com",
        display_name="Tenant A",
    )

    create_test_user(
        test_db,
        org_id="org-1",
        tenant_id="tenant-b",
        email="tenant-b@example.com",
        display_name="Tenant B",
    )

    headers_a = login_test_user(app, email="tenant-a@example.com")

    denied = app.get(
        "/threats",
        params={"org_id": "org-1", "tenant_id": "tenant-b"},
        headers=headers_a,
    )

    assert denied.status_code == 403

    assert test_db.audit_logs.count_documents(
        {"action": "cross_tenant_denied"}
    ) >= 1