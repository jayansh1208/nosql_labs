"""Development-only, one-time bootstrap for the first ThreatGuard administrator.

This module is intentionally a local administrative command, not an HTTP route. It
never supplies a default password and refuses to run outside development mode.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from typing import Mapping

from backend.app.config import APP_ENV
from backend.app.database.connection import get_db
from backend.app.database.init_db import initialize_database
from backend.app.database.repositories import OrganizationRepository, TenantRepository, UserRepository
from backend.app.security import hash_password


REQUIRED_ENVIRONMENT = (
    "THREATGUARD_BOOTSTRAP_ADMIN_EMAIL",
    "THREATGUARD_BOOTSTRAP_ADMIN_PASSWORD",
    "THREATGUARD_BOOTSTRAP_ORG_ID",
    "THREATGUARD_BOOTSTRAP_ORG_NAME",
    "THREATGUARD_BOOTSTRAP_TENANT_ID",
    "THREATGUARD_BOOTSTRAP_TENANT_NAME",
)


def _required_values(environment: Mapping[str, str]) -> dict[str, str]:
    missing = [name for name in REQUIRED_ENVIRONMENT if not environment.get(name, "").strip()]
    if missing:
        raise ValueError(f"Missing required bootstrap environment variables: {', '.join(missing)}")
    password = environment["THREATGUARD_BOOTSTRAP_ADMIN_PASSWORD"]
    if len(password) < 12:
        raise ValueError("THREATGUARD_BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters.")
    return {name: environment[name].strip() for name in REQUIRED_ENVIRONMENT}


def bootstrap_initial_super_admin(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Create one administrator, preserving all existing records and database volumes."""
    if APP_ENV.lower() != "development":
        raise ValueError("The bootstrap command is available only when APP_ENV=development.")
    values = _required_values(environment or os.environ)
    db = get_db()
    initialize_database(db)
    users = UserRepository(db)
    if db["users"].count_documents({"role": "super_admin"}, limit=1):
        raise ValueError("A super_admin already exists; bootstrap is one-time only.")

    organizations = OrganizationRepository(db)
    if db["organizations"].find_one({"org_id": values["THREATGUARD_BOOTSTRAP_ORG_ID"]}) is None:
        organizations.create({
            "org_id": values["THREATGUARD_BOOTSTRAP_ORG_ID"],
            "name": values["THREATGUARD_BOOTSTRAP_ORG_NAME"],
            "description": "Created by the one-time development bootstrap command.",
            "status": "active",
        })

    tenants = TenantRepository(db)
    if db["tenants"].find_one({"tenant_id": values["THREATGUARD_BOOTSTRAP_TENANT_ID"]}) is None:
        tenants.create({
            "org_id": values["THREATGUARD_BOOTSTRAP_ORG_ID"],
            "tenant_id": values["THREATGUARD_BOOTSTRAP_TENANT_ID"],
            "name": values["THREATGUARD_BOOTSTRAP_TENANT_NAME"],
            "status": "active",
            "metadata": None,
        })

    if users.get_by_email(
        values["THREATGUARD_BOOTSTRAP_ADMIN_EMAIL"],
        org_id=values["THREATGUARD_BOOTSTRAP_ORG_ID"],
        tenant_id=values["THREATGUARD_BOOTSTRAP_TENANT_ID"],
    ):
        raise ValueError("The requested bootstrap email already exists for this tenant.")

    record = users.create({
        "org_id": values["THREATGUARD_BOOTSTRAP_ORG_ID"],
        "tenant_id": values["THREATGUARD_BOOTSTRAP_TENANT_ID"],
        "user_id": f"usr-{uuid.uuid4().hex[:12]}",
        "email": values["THREATGUARD_BOOTSTRAP_ADMIN_EMAIL"],
        "display_name": "Initial administrator",
        "role": "super_admin",
        "status": "active",
        "password_hash": hash_password(values["THREATGUARD_BOOTSTRAP_ADMIN_PASSWORD"]),
    })
    return {"user_id": record["user_id"], "email": record["email"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create the first ThreatGuard development administrator.")
    parser.add_argument("--confirm", action="store_true", help="Confirm that this one-time local action is intended.")
    args = parser.parse_args(argv)
    if not args.confirm:
        parser.error("Pass --confirm after setting the required THREATGUARD_BOOTSTRAP_* environment variables.")
    try:
        result = bootstrap_initial_super_admin()
    except ValueError as exc:
        print(f"Bootstrap not completed: {exc}", file=sys.stderr)
        return 2
    print(f"Created initial super administrator: {result['email']} ({result['user_id']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
