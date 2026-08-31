# Fail-rereview ledger patch draft

`fail-rereview-ledger-patches.jsonl` contains two complete live-row updates.
It is a draft only and has not been applied.

## GHSA-8X4M-QW58-3PCX

- Live class `alias-303ca6a3bcd91ac79f484238`, expected revision `1`.
- Set `status=BLOCKED`, `ledger_best=BLOCKED`, `site_scope=null`, and
  `site_tier=null`; this removes the case from the AI publication set.
- Removed the stale `round3_research` chain that bound this payment advisory
  to the unrelated `2566a1a0... -> 81ba7632...` header-serialization issue.
- Explicit top-level negative overrides use empty `candidate_set`,
  `carrier_set`, and `minimum_fix_set`, plus null vulnerable/fixed releases.
  No stale candidate or fix can be recovered from those authoritative fields.
- Added a `causal_research` BLOCKED record explaining that `1092d43e...` is an
  aggregate 0.4.8 fix lead, not a substitute for the ten missing atomic
  BIC/parent/AI/fix chains.

## GHSA-8G98-M4J9-QWW5

- Live class `alias-a57df415a930e4db1ef3b6f7`, expected revision `1`.
- Retain `status=AI_ROOT_CAUSE`, `ledger_best=AI_ROOT_CAUSE`, and
  `site_scope=AI_ROOT_CAUSE`, but set `site_tier=null` because release
  containment is still unknown.
- Limit the row to the PayPal-webhook signature-validation mechanism:
  candidate `c139c021f68a09d22c2af88641b61c00f67f2af4`, no carrier, and direct
  fix `57b7634391959dbbdb39b387ac4dc68157cd58a1`.
- Gates are six `PASS` values plus `release=UNKNOWN`, sourced from
  `provisional-closure-20260831/fail-rereview-a`.
- Both release fields are explicitly null. The scope and unresolved reason
  require recovery of the named 7.0.5-7.0.8 published artifacts.
- Removed the stale aggregate `narrow70` record and added a PayPal-only
  `causal_research` record. The draft does not claim complete remediation of
  path traversal, purchase-token replay, PBKDF2, or the four-flaw aggregate.

## Validation

The JSONL has exactly two parseable lines and two unique class IDs. A fresh
read of the live ledger confirmed revisions `1` and `1`; both complete rows
passed `scripts.ledger_store.validate_update(old, new)`. The targeted P7MM row
in `ready-ledger-patches.jsonl` independently passed against live revision
`2` after its three-field correction.

No database apply, ledger export, publisher run, generated-data change, test
change, or commit was performed.
