"""Authorization gate for active operations.

KINGDOM X performs passive lookups (DNS, RDAP, TLS read, local diagnostics) with
no ceremony, but anything that *touches a third party actively* — port scans,
web fuzzing, header probing that could be logged as an attack — requires a
recorded, explicit statement that the operator is allowed to test that target.

The gate is deliberately annoying:

* the operator must type the exact target back,
* the statement must name an authorization basis,
* the record is written to the audit log with a timestamp,
* the record expires, so a stale authorisation cannot be reused a month later.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from kingdomx.core.errors import AuthorizationError, UnsafeTargetError
from kingdomx.core.logging_setup import get_logger

log = get_logger("core.authorization")

#: Default validity window for a recorded authorisation.
DEFAULT_VALIDITY_HOURS = 24

#: Bases an operator may assert. Free text is not accepted.
AUTHORIZATION_BASES: tuple[str, ...] = (
    "owned",          # I own this system
    "employer",       # my employer owns it and I have written permission
    "client_contract",# a signed engagement covers it
    "lab",            # isolated lab / intentionally vulnerable target
    "ctf",            # competition rules permit it
    "bug_bounty",     # program scope covers it
    "written_consent",# other written consent on file
)

#: Targets that are always acceptable lab material.
BUILTIN_LAB_TARGETS: tuple[str, ...] = (
    "127.0.0.1",
    "::1",
    "localhost",
    "scanme.nmap.org",
)

MAX_BASIS_TEXT = 200


@dataclass
class Authorization:
    """A recorded permission to test one target."""

    id: str
    target: str
    basis: str
    statement: str
    created_at: float
    expires_at: float
    actor: str = "operator"
    scope: tuple[str, ...] = ()

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    @property
    def valid(self) -> bool:
        return not self.expired and bool(self.target) and self.basis in AUTHORIZATION_BASES

    def covers(self, target: str) -> bool:
        needle = (target or "").strip().lower()
        if not self.valid:
            return False
        if needle == self.target.lower():
            return True
        return any(needle == extra.lower() for extra in self.scope)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "basis": self.basis,
            "statement": self.statement,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "valid": self.valid,
            "expired": self.expired,
            "scope": list(self.scope),
        }


class AuthorizationStore:
    """In-memory authorisation records for the current session.

    Deliberately *not* persisted to the database: permission to scan should not
    silently survive a restart and reappear weeks later.
    """

    def __init__(self) -> None:
        self._records: dict[str, Authorization] = {}

    def grant(
        self,
        target: str,
        basis: str,
        statement: str,
        *,
        confirm: str | None = None,
        hours: int = DEFAULT_VALIDITY_HOURS,
        scope: Iterable[str] = (),
    ) -> Authorization:
        """Record an authorisation. ``confirm`` must equal ``target`` exactly."""
        clean_target = (target or "").strip()
        if not clean_target:
            raise AuthorizationError("authorization requires a target")
        if confirm is None or confirm.strip() != clean_target:
            raise AuthorizationError(
                "confirmation mismatch",
                detail="type the exact target back to record authorisation",
            )
        basis_key = (basis or "").strip().lower()
        if basis_key not in AUTHORIZATION_BASES:
            raise AuthorizationError(
                f"unknown authorization basis: {basis or '<empty>'}",
                detail="accepted: " + ", ".join(AUTHORIZATION_BASES),
            )
        text = (statement or "").strip()
        if len(text) < 12:
            raise AuthorizationError(
                "authorization statement too short",
                detail="please describe the permission you hold in at least 12 characters",
            )
        if len(text) > MAX_BASIS_TEXT:
            text = text[:MAX_BASIS_TEXT]
        if hours < 1 or hours > 24 * 30:
            raise AuthorizationError("validity must be between 1 hour and 30 days")

        now = time.time()
        record = Authorization(
            id=uuid.uuid4().hex[:16],
            target=clean_target,
            basis=basis_key,
            statement=text,
            created_at=now,
            expires_at=now + hours * 3600,
            scope=tuple(str(item).strip() for item in scope if str(item).strip()),
        )
        self._records[record.id] = record
        log.info(
            "authorization recorded id=%s target=%s basis=%s",
            record.id,
            clean_target,
            basis_key,
        )
        return record

    def get(self, record_id: str) -> Authorization | None:
        return self._records.get(record_id)

    def find_for(self, target: str) -> Authorization | None:
        for record in self._records.values():
            if record.covers(target):
                return record
        return None

    def revoke(self, record_id: str) -> bool:
        return self._records.pop(record_id, None) is not None

    def purge_expired(self) -> int:
        stale = [key for key, record in self._records.items() if record.expired]
        for key in stale:
            del self._records[key]
        return len(stale)

    def all(self) -> list[Authorization]:
        return list(self._records.values())


#: Process-wide store.
STORE = AuthorizationStore()


def require_authorization(
    target: str,
    *,
    store: AuthorizationStore | None = None,
    lab_targets: Iterable[str] = BUILTIN_LAB_TARGETS,
) -> Authorization | None:
    """Raise unless ``target`` is a built-in lab target or has a live record."""
    clean = (target or "").strip().lower()
    if not clean:
        raise UnsafeTargetError("empty target")
    for lab in lab_targets:
        if clean == lab.lower() or clean.endswith("." + lab.lower()):
            return None
    active_store = store or STORE
    record = active_store.find_for(clean)
    if record is None:
        raise AuthorizationError(
            f"no authorization recorded for {clean}",
            detail=(
                "active testing requires recorded permission. "
                "Grant it with: kingdomx authz --target "
                + clean
                + " --basis owned"
            ),
        )
    if record.expired:
        raise AuthorizationError(
            f"authorization for {clean} expired",
            detail="re-run the authorization command to renew it",
        )
    return record


def describe_bases() -> list[dict[str, str]]:
    return [
        {"key": "owned", "description": "I own or administer this system"},
        {"key": "employer", "description": "My employer owns it and permits testing"},
        {"key": "client_contract", "description": "A signed engagement covers this target"},
        {"key": "lab", "description": "Isolated lab / intentionally vulnerable target"},
        {"key": "ctf", "description": "Competition rules permit it"},
        {"key": "bug_bounty", "description": "The program scope includes it"},
        {"key": "written_consent", "description": "Other written consent is on file"},
    ]
