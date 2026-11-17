import uuid

import pytest

from backend.app.database.repositories import (
    OrganizationRepository,
    TenantRepository,
    UserRepository,
)
from backend.app.security import hash_password


@pytest.fixture
def create_test_user():
    def _create(
        db,
        *,
        org_id="org-test",
        tenant_id="tenant-test",
        email="analyst@example.com",
        password="S3cur3!Pass",
        role="security_analyst",
        display_name=None,
    ):
        organizations = OrganizationRepository(db)
        tenants = TenantRepository(db)
        users = UserRepository(db)

        if not db.organizations.find_one({"org_id": org_id}):
            organizations.create({
                "org_id": org_id,
                "name": org_id,
                "status": "active",
            })

        existing_tenant = db.tenants.find_one({"tenant_id": tenant_id})
        if existing_tenant:
            if existing_tenant.get("org_id") != org_id:
                raise ValueError(
                    f"Tenant {tenant_id} already belongs to another organization"
                )
        else:
            tenants.create({
                "org_id": org_id,
                "tenant_id": tenant_id,
                "name": tenant_id,
                "status": "active",
            })

        if users.get_by_email(email, org_id=org_id, tenant_id=tenant_id):
            raise ValueError(f"Test user already exists: {email}")

        user = users.create({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "user_id": str(uuid.uuid4()),
            "email": email,
            "display_name": display_name or email,
            "role": role,
            "status": "active",
            "password_hash": hash_password(password),
        })

        return {
            "user": user,
            "email": email,
            "password": password,
            "org_id": org_id,
            "tenant_id": tenant_id,
            "role": role,
        }

    return _create


@pytest.fixture
def login_test_user():
    def _login(client, *, email, password="S3cur3!Pass"):
        response = client.post(
            "/auth/login",
            json={"email": email, "password": password},
        )
        assert response.status_code == 200, response.text

        token = response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _login