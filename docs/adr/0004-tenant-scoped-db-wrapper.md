# 0004: Tenant isolation in a DB wrapper

**Status:** accepted

## Context
Multi-tenant data in one database leaks if any query forgets its tenant filter.

## Decision
Services never touch raw collections. `TenantDB(tenant_id)` wraps every collection and injects `tenant_id` into every find, update, delete, aggregate and insert. Storage keys are built by `tenant_key()`, which validates each path segment. Resources from another tenant return 404, not 403, so their existence is not revealed.

## Consequences
- Isolation does not depend on each developer remembering a filter. `tests/test_api_security.py` exercises cross-tenant access on every resource type.
- System jobs (the retention sweep) run with an explicit per-tenant system principal.
