# CVE-2026-47211 canonical code evidence

Case: `alias-04967329955171a53cc2731f` / CVE-2026-47211 / GHSA-C4M7-2GWP-VW76.

## Rechecked edge

- Origin: `d30b61759b8efe4554978438abbcc5a9d698d055`, PR #49 member. Its parent `9ed95f0f6498ba50beb7590a2c0f3192eff23353` has no `OUROBOROS_CLI_PATH` in the adapter. The commit first reads that variable and passes the resolved path to the Claude Agent SDK. Its commit object has `Co-Authored-By: Claude Opus 4.5`.
- Carrier: `4aaf9147a6c6f76aecc775defcd1a542537cf01f`, GitHub's single-parent squash for PR #49. Its parent `797441d9005cf35aa4c4d12cb074710b1cb6e0d1` and the member's parent have the identical tree `cf189687b37ccafb50a4d4edfb36d70265359bab`. Compared with the member, the carrier only adds the later validation edits (whitespace normalization, executable-bit check, fallback logging). It is not an origin.
- Vulnerable source: `3da3cebc59da717cac32813f19dd1b821775df6c` later begins loading the current-directory `.env`; both it and the carrier are ancestors of the fix.
- Direct fix: `4e70b760b4eb157469b58645339ba831f6513d37`. It marks the project `.env` untrusted, deny-lists `OUROBOROS_CLI_PATH`, and keeps the user-owned home `.env` trusted.
- Release witness: carrier is in `v0.4.0`; project-`.env` source is in `v0.7.0`; the fix is first in `v0.39.0`, matching the first-party advisory.

The patch keeps `d30…` in `candidate_set`, `4aaf…` only in `carrier_set`, and `4e70…` in `minimum_fix_set`. It also repairs the legacy nested `squash_audit.introducer_sha` so the row no longer names the squash aggregate as the introducer.

## Evidence payload

- Candidate displayed hunks: two exact unified-diff hunks from `d30…`, covering environment selection and SDK execution handoff.
- Fix displayed hunks: the exact loader trust-boundary hunks from `4e70…`.
- Candidate hunk SHA-256: `d7dc0fc30783606cace15eaf0bcdeb53d7738ba0db1bc231722ab446f5255149`
- Fix hunk SHA-256: `f8042190564a9c526bc43f7d718db7608a98b72519974f2f0391bff8d3b9f17a`
- Candidate allowlist: `src/ouroboros/providers/claude_code_adapter.py`
- Fix allowlist: `src/ouroboros/config/loader.py`
- Advisory: `https://github.com/Q00/ouroboros/security/advisories/GHSA-c4m7-2gwp-vw76`

Validation is intentionally local and read-only: every commit and parent is a Git commit object; every displayed hunk is reproduced from the named commit/path; both content hashes recompute; every required anchor occurs in its role; `json.loads` and `scripts.ledger_store.validate_update` pass against live revision 3. The patch is not applied.

