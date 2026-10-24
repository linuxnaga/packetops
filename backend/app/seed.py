"""Development seed data: two tenants with one user per role. Refuses to run in production.

    python -m app.seed            # create/refresh tenants and users, print dev tokens
"""

from __future__ import annotations

import sys

from app.core.config import get_settings
from app.core.security import ROLES, issue_dev_token
from app.db import get_db, utcnow
from app.db.migrations import migrate

TENANTS = [("ten_acme0000000000000000", "acme", "Acme Networks"), ("ten_globex000000000000000", "globex", "Globex Corp")]


def seed() -> list[dict]:
    if get_settings().is_production:
        raise SystemExit("Refusing to seed development users in production")
    migrate()
    db = get_db()
    users = []
    for tid, slug, name in TENANTS:
        db.tenants.update_one({"_id": tid}, {"$set": {"slug": slug, "name": name, "updated_at": utcnow()},
                                             "$setOnInsert": {"created_at": utcnow(), "retention_days": 90}}, upsert=True)
        for role in ROLES:
            uid = f"usr_{slug}_{role}".replace("-", "_")
            email = f"{role.replace('_', '-')}@{slug}.example"
            db.users.update_one({"_id": uid}, {"$set": {"tenant_id": tid, "email": email, "roles": [role],
                                                        "display_name": f"{name} {role.replace('_', ' ')}", "disabled": False},
                                               "$setOnInsert": {"created_at": utcnow()}}, upsert=True)
            users.append(db.users.find_one({"_id": uid}))
    return users


def main() -> None:
    users = seed()
    show_tokens = "--tokens" in sys.argv
    for u in users:
        line = f"{u['tenant_id']:<26} {u['roles'][0]:<13} {u['email']}"
        if show_tokens:
            line += f"\n    {issue_dev_token(u)}"
        print(line)
    print("\nDev login: POST /api/v1/auth/dev-login {\"email\": \"analyst@acme.example\"}")


if __name__ == "__main__":
    main()
