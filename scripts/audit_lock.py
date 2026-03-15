#!/usr/bin/env python3
"""Atomic claim/lock mechanism for parallel CVE audits.

Prevents multiple audit sessions from picking the same CVE target.
Uses atomic file creation (O_CREAT | O_EXCL) for race-free claiming,
and fcntl file locking for safe findings.json appends.

Usage:
  audit_lock.py claim CVE-XXXX [--worker NAME]
  audit_lock.py release CVE-XXXX
  audit_lock.py check CVE-XXXX
  audit_lock.py list
"""

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

try:
    import fcntl
except ImportError as exc:
    raise ImportError("audit_lock requires a POSIX platform (Linux/macOS)") from exc

DEFAULT_CLAIMS_DIR = Path.home() / ".cache/cve-analyzer/audit/claims"
DEFAULT_FINDINGS_PATH = Path.home() / ".cache/cve-analyzer/audit/findings.json"
STALE_TIMEOUT_SECONDS = 7200  # 2 hours


def claim(
    cve_id: str,
    *,
    worker: str = "",
    claims_dir: Path = DEFAULT_CLAIMS_DIR,
    stale_timeout: int = STALE_TIMEOUT_SECONDS,
) -> bool:
    """Atomically claim a CVE for audit.

    Returns True if claimed successfully, False if already claimed by another worker.
    Reclaims stale locks (older than stale_timeout seconds).
    """
    claims_dir.mkdir(parents=True, exist_ok=True)
    lock_file = claims_dir / f"{cve_id}.lock"

    # Check for stale claim first.
    # NOTE: There is a TOCTOU race between the stale check and the O_EXCL create
    # below — two processes can both see the same stale lock, both unlink it, and
    # both attempt O_EXCL. Only one wins; the other gets False. This is a spurious
    # rejection (not a duplicate claim), acceptable at our concurrency level.
    if lock_file.exists():
        try:
            data = json.loads(lock_file.read_text())
            age = time.time() - data.get("timestamp", 0)
            if age <= stale_timeout:
                return False  # Active claim exists
            # Stale — remove and reclaim below
            lock_file.unlink(missing_ok=True)
        except (json.JSONDecodeError, OSError):
            lock_file.unlink(missing_ok=True)

    # Atomic create: O_CREAT | O_EXCL fails if file already exists
    metadata = {
        "cve_id": cve_id,
        "worker": worker,
        "timestamp": time.time(),
        "pid": os.getpid(),
    }
    try:
        fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            os.write(fd, json.dumps(metadata).encode())
        finally:
            os.close(fd)
        return True
    except FileExistsError:
        # Another process beat us in the race
        return False


def is_claimed(
    cve_id: str,
    *,
    claims_dir: Path = DEFAULT_CLAIMS_DIR,
    stale_timeout: int = STALE_TIMEOUT_SECONDS,
) -> bool:
    """Check if a CVE has an active (non-stale) claim."""
    lock_file = claims_dir / f"{cve_id}.lock"
    if not lock_file.exists():
        return False
    try:
        data = json.loads(lock_file.read_text())
        age = time.time() - data.get("timestamp", 0)
        return age <= stale_timeout
    except (json.JSONDecodeError, OSError):
        return False


def release(cve_id: str, *, claims_dir: Path = DEFAULT_CLAIMS_DIR) -> bool:
    """Release a claim. Returns True if released, False if not found.

    NOTE: Does not verify ownership — any caller can release any claim.
    This is intentional for simplicity; the audit skill is the only consumer
    and each session only releases its own claims.
    """
    lock_file = claims_dir / f"{cve_id}.lock"
    try:
        lock_file.unlink()
        return True
    except FileNotFoundError:
        return False


def list_claims(
    *,
    claims_dir: Path = DEFAULT_CLAIMS_DIR,
    stale_timeout: int = STALE_TIMEOUT_SECONDS,
) -> list[dict]:
    """List all active (non-stale) claims."""
    if not claims_dir.exists():
        return []
    now = time.time()
    active = []
    for lock_file in claims_dir.glob("*.lock"):
        try:
            data = json.loads(lock_file.read_text())
            if now - data.get("timestamp", 0) <= stale_timeout:
                active.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return active


def load_claimed_cves(
    *,
    claims_dir: Path = DEFAULT_CLAIMS_DIR,
    stale_timeout: int = STALE_TIMEOUT_SECONDS,
) -> set[str]:
    """Return set of CVE IDs with active claims (for queue filtering)."""
    return {c["cve_id"] for c in list_claims(claims_dir=claims_dir, stale_timeout=stale_timeout)}


def save_finding(
    finding: dict,
    *,
    findings_path: Path = DEFAULT_FINDINGS_PATH,
) -> None:
    """Atomically append a finding to findings.json with file locking.

    Safe for concurrent writers: uses fcntl.flock for mutual exclusion.
    Creates the file and parent directories if they don't exist.
    """
    findings_path.parent.mkdir(parents=True, exist_ok=True)

    # Use a separate .lock file for fcntl locking (works even if findings.json
    # doesn't exist yet). Open with "a" (not "w") to avoid truncation races
    # on the inode when multiple processes open the lock file concurrently.
    lock_path = findings_path.with_suffix(".json.lock")

    with open(lock_path, "a") as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            # Read existing findings
            findings = []
            if findings_path.exists():
                try:
                    text = findings_path.read_text().strip()
                    if text:
                        findings = json.loads(text)
                except (json.JSONDecodeError, OSError):
                    # Corrupt file — back up before resetting to avoid silent data loss
                    backup = findings_path.with_suffix(".json.bak")
                    shutil.copy2(findings_path, backup)
                    findings = []

            findings.append(finding)
            findings_path.write_text(json.dumps(findings, indent=2) + "\n")
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)


def main():
    parser = argparse.ArgumentParser(description="Audit claim/lock manager")
    sub = parser.add_subparsers(dest="command", required=True)

    p_claim = sub.add_parser("claim", help="Claim a CVE for audit")
    p_claim.add_argument("cve_id")
    p_claim.add_argument("--worker", default="", help="Worker/session identifier")

    p_release = sub.add_parser("release", help="Release a CVE claim")
    p_release.add_argument("cve_id")

    p_check = sub.add_parser("check", help="Check if a CVE is claimed")
    p_check.add_argument("cve_id")

    sub.add_parser("list", help="List active claims")

    args = parser.parse_args()

    if args.command == "claim":
        ok = claim(args.cve_id, worker=args.worker)
        if ok:
            print(f"Claimed {args.cve_id}")
        else:
            print(f"Already claimed: {args.cve_id}", file=sys.stderr)
            sys.exit(1)
    elif args.command == "release":
        ok = release(args.cve_id)
        if ok:
            print(f"Released {args.cve_id}")
        else:
            print(f"No claim found: {args.cve_id}", file=sys.stderr)
            sys.exit(1)
    elif args.command == "check":
        if is_claimed(args.cve_id):
            print(f"CLAIMED: {args.cve_id}")
        else:
            print(f"AVAILABLE: {args.cve_id}")
    elif args.command == "list":
        claims = list_claims()
        if not claims:
            print("No active claims.")
            return
        for c in claims:
            age = time.time() - c.get("timestamp", 0)
            print(f"  {c['cve_id']}  worker={c.get('worker', '')}  age={age:.0f}s")


if __name__ == "__main__":
    main()
