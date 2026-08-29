# Audit protocol

How a case gets judged. One principle: **no mechanical scanning** —
fully understand the vulnerability's root cause and its complete
lifecycle before judging the AI role.

Vulnerability first, AI second. One vulnerability, one clean analysis
context — no leftover verdicts from other cases. The leader still
passes same-mechanism ledger/site hits, the advisory, and the clone.
The BIC is the smallest commit that first wrote the vulnerable lines —
a move, refactor, revert, or squash aggregate is not a BIC. But a
first-write that is the smallest surviving object in public history
IS a valid BIC when its immediate parent is verifiable and no finer
public member can be reconstructed; never invert the search to first
find an AI-marked commit and then call it the BIC. Judge the AI role
from signals on that BIC only.

Withdrawn/rejected advisories are `FALSE_POSITIVE`, not `NOT_AI`:
`NOT_AI` means a real vulnerability with human authorship, while
`FALSE_POSITIVE` means the advisory itself was wrong or was withdrawn.
Check the CVE.org record (and vendor disposition) before closing; the
GitHub advisory's `withdrawn_at` field is not authoritative.

Record the judgment in the ledger. Do not publish `ALIAS-*` cases or
use the introducer commit date as `published_at`. Field semantics,
file ownership, and landing gates live in `docs/DATA-SCHEMA.md`,
`docs/AGENT-OWNERSHIP.md`, `scripts/audit_record_gates.py`, and
`scripts/publish_tp_ledger.py`.
