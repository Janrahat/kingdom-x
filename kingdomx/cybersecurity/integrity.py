"""File integrity monitoring.

Hash a set of files, store the manifest, and later report what changed. Uses
SHA-256 by default; MD5 is available only for legacy comparison and is flagged.

Nothing here leaves the machine: it hashes local files and writes a JSON manifest.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from kingdomx.cybersecurity.severity import Finding, Report, Severity

#: Never follow these; hashing them is meaningless or dangerous.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "*.pyc", "__pycache__/*", "*.git/*", ".git/*", "node_modules/*",
    "*.log", "*.tmp", "*.swp", "*.db-wal", "*.db-shm",
)

#: Files above this are summarised rather than hashed in full.
MAX_HASH_BYTES = 512 * 1024 * 1024

READ_CHUNK = 1024 * 1024


@dataclass
class FileRecord:
    path: str
    size: int
    mtime: float
    sha256: str
    mode: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "mtime": self.mtime,
            "sha256": self.sha256,
            "mode": self.mode,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileRecord":
        return cls(
            path=str(data["path"]),
            size=int(data.get("size", 0)),
            mtime=float(data.get("mtime", 0)),
            sha256=str(data.get("sha256", "")),
            mode=int(data.get("mode", 0)),
        )


@dataclass
class Manifest:
    """A stored baseline."""

    root: str
    created_at: float
    algorithm: str
    files: dict[str, FileRecord] = field(default_factory=dict)
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "root": self.root,
            "created_at": self.created_at,
            "algorithm": self.algorithm,
            "file_count": len(self.files),
            "files": {path: rec.to_dict() for path, rec in self.files.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Manifest":
        files = {
            path: FileRecord.from_dict(rec) for path, rec in (data.get("files") or {}).items()
        }
        return cls(
            root=str(data.get("root", "")),
            created_at=float(data.get("created_at", 0)),
            algorithm=str(data.get("algorithm", "sha256")),
            files=files,
            version=int(data.get("version", 1)),
        )

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> "Manifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)


def hash_file(path: str | Path, *, algorithm: str = "sha256") -> tuple[str, int]:
    """Stream-hash a file, returning ``(hexdigest, bytes_read)``."""
    algo = algorithm.lower()
    if algo not in {"sha256", "sha1", "md5"}:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    digest = hashlib.new(algo)
    total = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > MAX_HASH_BYTES:
                break
    return digest.hexdigest(), total


def _excluded(relative: str, excludes: Iterable[str]) -> bool:
    parts = relative.split(os.sep)
    for pattern in excludes:
        if fnmatch.fnmatch(relative, pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


def build_manifest(
    root: str | Path,
    *,
    algorithm: str = "sha256",
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    max_files: int = 50000,
) -> Manifest:
    """Hash every regular file under ``root``."""
    base = Path(root).expanduser().resolve()
    if not base.exists():
        raise FileNotFoundError(f"path does not exist: {base}")

    files: dict[str, FileRecord] = {}
    patterns = tuple(excludes)
    candidates = [base] if base.is_file() else sorted(base.rglob("*"))
    for candidate in candidates:
        if len(files) >= max_files:
            break
        if candidate.is_symlink() or not candidate.is_file():
            continue
        relative = candidate.name if base.is_file() else str(candidate.relative_to(base))
        if _excluded(relative, patterns):
            continue
        try:
            digest, size = hash_file(candidate, algorithm=algorithm)
            stat = candidate.stat()
        except (OSError, PermissionError):
            continue
        files[relative] = FileRecord(
            path=relative,
            size=size,
            mtime=stat.st_mtime,
            sha256=digest,
            mode=stat.st_mode & 0o777,
        )

    return Manifest(
        root=str(base),
        created_at=time.time(),
        algorithm=algorithm,
        files=files,
    )


@dataclass
class DiffResult:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    permission_changed: list[str] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified or self.permission_changed)

    def counts(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "modified": len(self.modified),
            "permission_changed": len(self.permission_changed),
            "unchanged": self.unchanged,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": sorted(self.added),
            "removed": sorted(self.removed),
            "modified": sorted(self.modified),
            "permission_changed": sorted(self.permission_changed),
            "unchanged": self.unchanged,
            "counts": self.counts(),
        }


def compare(baseline: Manifest, current: Manifest) -> DiffResult:
    """Two-way diff between two manifests."""
    result = DiffResult()
    base_paths = set(baseline.files)
    curr_paths = set(current.files)

    result.added = sorted(curr_paths - base_paths)
    result.removed = sorted(base_paths - curr_paths)
    for path in sorted(base_paths & curr_paths):
        old = baseline.files[path]
        new = current.files[path]
        if old.sha256 != new.sha256:
            result.modified.append(path)
        elif old.mode != new.mode:
            result.permission_changed.append(path)
        else:
            result.unchanged += 1
    return result


def integrity_report(
    root: str | Path,
    *,
    baseline_path: str | Path | None = None,
    algorithm: str = "sha256",
) -> Report:
    """Compare ``root`` against a baseline, creating one when absent."""
    report = Report(module="integrity", target=str(root), started_at=time.time())
    try:
        current = build_manifest(root, algorithm=algorithm)
    except FileNotFoundError as exc:
        report.errors.append(str(exc))
        report.finished_at = time.time()
        return report

    report.meta = {
        "files_hashed": len(current.files),
        "algorithm": algorithm,
        "root": current.root,
        "total_bytes": sum(rec.size for rec in current.files.values()),
    }

    if baseline_path is None:
        report.passed(
            "Baseline not requested",
            "integrity",
            detail=f"Hashed {len(current.files)} files for reference.",
        )
        report.finished_at = time.time()
        return report

    baseline_file = Path(baseline_path)
    if not baseline_file.is_file():
        current.save(baseline_file)
        report.passed(
            "Baseline created",
            "integrity",
            detail=f"Wrote {len(current.files)} file hashes to {baseline_file}.",
            evidence="Re-run to compare against this baseline.",
        )
        report.meta["baseline_created"] = str(baseline_file)
        report.finished_at = time.time()
        return report

    try:
        baseline = Manifest.load(baseline_file)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        report.errors.append(f"baseline is unreadable: {exc}")
        report.finished_at = time.time()
        return report

    diff = compare(baseline, current)
    report.meta["diff"] = diff.to_dict()

    if diff.modified:
        severity = Severity.HIGH if len(diff.modified) > 20 else Severity.MEDIUM
        report.issue(
            title=f"{len(diff.modified)} file(s) modified since the baseline",
            severity=severity,
            category="integrity",
            detail="Content hash changed. Confirm the change was intended.",
            evidence=", ".join(diff.modified[:12])
            + (" …" if len(diff.modified) > 12 else ""),
            remediation="Review the diff; if unexpected, treat the host as compromised and "
            "restore from a known-good copy.",
        )
    if diff.removed:
        report.issue(
            title=f"{len(diff.removed)} file(s) removed since the baseline",
            severity=Severity.MEDIUM,
            category="integrity",
            detail="A deleted file can indicate tampering or log wiping.",
            evidence=", ".join(diff.removed[:12]) + (" …" if len(diff.removed) > 12 else ""),
        )
    if diff.added:
        report.issue(
            title=f"{len(diff.added)} new file(s) since the baseline",
            severity=Severity.LOW,
            category="integrity",
            detail="Unexpected new executables are worth inspecting.",
            evidence=", ".join(diff.added[:12]) + (" …" if len(diff.added) > 12 else ""),
        )
    if diff.permission_changed:
        report.issue(
            title=f"{len(diff.permission_changed)} file(s) changed permissions",
            severity=Severity.MEDIUM,
            category="integrity",
            detail="A newly world-writable executable is a privilege-escalation path.",
            evidence=", ".join(diff.permission_changed[:12]),
            remediation="Restore the expected mode with chmod.",
        )
    if not diff.has_changes:
        report.passed(
            "No changes since the baseline",
            "integrity",
            detail=f"{diff.unchanged} files matched their recorded hashes.",
        )

    report.finished_at = time.time()
    return report


def world_writable(root: str | Path, *, limit: int = 200) -> list[dict[str, Any]]:
    """Find world-writable files and directories under ``root``."""
    base = Path(root).expanduser().resolve()
    found: list[dict[str, Any]] = []
    if not base.exists():
        return found
    for candidate in base.rglob("*"):
        if len(found) >= limit:
            break
        try:
            stat = candidate.lstat()
        except OSError:
            continue
        if stat.st_mode & 0o002:
            found.append(
                {
                    "path": str(candidate.relative_to(base)),
                    "mode": oct(stat.st_mode & 0o777),
                    "is_dir": candidate.is_dir(),
                    "world_writable": True,
                }
            )
    return found


def suid_files(root: str | Path, *, limit: int = 200) -> list[dict[str, Any]]:
    """Find setuid/setgid files under ``root``."""
    base = Path(root).expanduser().resolve()
    found: list[dict[str, Any]] = []
    if not base.exists():
        return found
    for candidate in base.rglob("*"):
        if len(found) >= limit:
            break
        try:
            stat = candidate.lstat()
        except OSError:
            continue
        mode = stat.st_mode
        if mode & 0o4000 or mode & 0o2000:
            found.append(
                {
                    "path": str(candidate.relative_to(base)),
                    "mode": oct(mode & 0o7777),
                    "setuid": bool(mode & 0o4000),
                    "setgid": bool(mode & 0o2000),
                    "owner_uid": stat.st_uid,
                }
            )
    return found


def permission_report(root: str | Path) -> Report:
    """Audit permissions: world-writable and setuid files."""
    report = Report(module="permissions", target=str(root), started_at=time.time())
    writable = world_writable(root)
    suid = suid_files(root)

    if writable:
        report.issue(
            title=f"{len(writable)} world-writable path(s) found",
            severity=Severity.HIGH if len(writable) > 5 else Severity.MEDIUM,
            category="permissions",
            detail="Any local user can modify these. For a script or config, that is "
            "local privilege escalation.",
            evidence=", ".join(item["path"] for item in writable[:10]),
            remediation="chmod o-w on each path (or the whole tree, if that is intended).",
        )
    else:
        report.passed("No world-writable paths", "permissions")

    if suid:
        report.issue(
            title=f"{len(suid)} setuid/setgid file(s) found",
            severity=Severity.MEDIUM,
            category="permissions",
            detail="Setuid binaries run with the owner's privileges. Keep the list short "
            "and every entry known.",
            evidence=", ".join(item["path"] for item in suid[:10]),
        )
    else:
        report.passed("No setuid/setgid files", "permissions")

    report.meta = {"world_writable": writable, "suid": suid}
    report.finished_at = time.time()
    return report
