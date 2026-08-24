# Baseline 48 authority audit

## Verdict first

Exact conservation: **48 = 47 KEEP_BASELINE + 1 DOWNGRADE**. One original identity per row. CVE aliases are stored and are not counting units. This packet does not admit causality, does not rebuild the canonical ledger, and does not support a more-than-200 claim. Worker outcome is an **authority audit proposal pending leader replay**.

The only valid later downgrade among the 48 is **GHSA-4FXP-2M36-QV64**. Terminal final-candidate review `COMPLETE_BOUNDED_REVIEW` at `frozen_at_utc=2026-08-13T22:03:11Z`, role `final_review`, keyed to this `case_id` / `row_key`, verdict **NARROW** on `identity_gate`. No replacement identity was inferred.

None of the other 47 have a later terminal independent or final red-team NARROW/REJECT that meets the authority rule (explicit terminal status + ended/frozen timestamp + review role + case_id/row_key). Timestamp-less redbase NARROW, older independent-review NARROW, inventory, routing, glob order, and mere contrary worker votes do not un-admit those identities.

## Authority rule applied

A later packet may DOWNGRADE an original identity only when all of the following hold:

1. The packet is terminal (completion token, not PARTIAL / HOLD / STATUS_ABSENT / forced in-flight).
2. An ended or frozen timestamp is explicit.
3. The review role is independent red-team or final review, not worker, census, inventory, or routing.
4. The row is keyed by the original `case_id` or `row_key`.
5. The keyed verdict is NARROW or REJECT for that same identity, not an unrelated mechanism.
6. The edge is not inferred from glob order or from a contrary vote without those fields.

KEEP_BASELINE means the fp211 `counting.fp211_released_publication_admitted=true` flag still stands for that identity. It is not a new admission.

## Mandatory downgrade

| Field | Value |
|---|---|
| Identity | `GHSA-4FXP-2M36-QV64` |
| Ordinal / row_key | 148 / `post:prospero-permission-save@canonical` |
| Disposition | DOWNGRADE |
| Authoritative packet | `autoresearch/herdr-260813-ghsa200-final-candidate-review-codex` |
| Role / status / freeze | `final_review` / `COMPLETE_BOUNDED_REVIEW` / `2026-08-13T22:03:11Z` |
| Path / hash | `cases.jsonl` / `e275437954890dca07855b5fcfa545f8f1a366fb85a7ee9f067da5b710b2b3da` |
| Verdict / gate | NARROW / `identity_gate` |
| Replacement | none |

Reason: the frozen repository advisory object is 404. The frozen global GHSA is unreviewed, has an empty `vulnerabilities` array, and has no repository or source-code-location object. Topology and release close on first-party commits and GitHub releases, but those facts do not substitute for the contract identity object. Baseline-increm-even KEEP of this id is an older proposal and is superseded. Redbase-even UNKNOWN is not NARROW/REJECT and has no freeze timestamp. Later HOLD overlay `canonical71` records named edge `E-4FXP-ID`; that overlay is not this worker's authority source.

## Other 47: no valid later downgrade

Searched terminal packets under `autoresearch/herdr-260813-ghsa200-*` plus posthold artifacts (`canonical71`, next-canonical design, publication-structural QA, proposal census). Nonterminal, inventory, and routing packets cannot mutate overlay state.

Contrary NARROW/UNKNOWN votes that **do not** qualify:

| Identity | Packet | Role | Verdict | Why not authority |
|---|---|---|---|---|
| GHSA-7F6V-3GX7-27Q8 | redbase-even | redteam | NARROW | No freeze timestamp; no named SUPERSEDES_EDGE; later overlays still count it |
| GHSA-G8P2-7WF7-98MQ | redbase-even | redteam | NARROW | same |
| GHSA-PFVM-W89X-94JW | redbase-even | redteam | NARROW | same |
| GHSA-76RV-2R9V-C5M6 | redbase-odd | redteam | NARROW | same |
| GHSA-9HFR-GW99-8RHX | redbase-odd | redteam | NARROW | same |
| GHSA-Q6RR-FM2G-G5X8 | redbase-odd and baseline-increm-odd | redteam / independent_gate_closing_review | NARROW | No freeze timestamp; not keyed by final-review; canonical71 still counts it |
| GHSA-6Q7J-XR26-3H2C | redbase-odd and baseline-increm-odd | redteam / independent_gate_closing_review | NARROW | same |
| GHSA-Q9PG-JJ6X-J9P6 | baseline-increm-even | independent_gate_closing_review | NARROW | No freeze timestamp; older independent vote; canonical71 still counts it |
| GHSA-FVVP-RJ8G-C7GC | baseline-increm-odd | independent_gate_closing_review | NARROW | same |

Nine of the 47 were later ACCEPT at final-candidate review (`GHSA-56C3-VFP2-5QQJ`, `GHSA-5RV5-XJ5J-3484`, `GHSA-5XXX-QHH7-9287`, `GHSA-7P8R-X3MC-P8W7`, `GHSA-8WC8-HF36-MJH9`, `GHSA-JM78-9FVV-MHGR`, `GHSA-M4WX-M65X-GHRR`, `GHSA-MV93-W799-CJ2W`, `GHSA-VC8F-X9PP-WF5P`). Those ACCEPT rows confirm KEEP_BASELINE. They are not net-new and they are not downgrades.

Net-new red-teams (netnew22, Actual/Gogs, B3, contributor, incomplete-rem, medium5, near-closed upgrades) review other identities or explicitly exclude the frozen 48. Their NARROW/REJECT rows cannot un-admit these 48.

## Conservation

| Set | Count |
|---:|---:|
| Original fp211 released-publication-admitted identities | 48 |
| KEEP_BASELINE | 47 |
| DOWNGRADE | 1 |
| Replacement identities inferred | 0 |
| Missing / extra / duplicate rows | 0 |

Equation: `48 = 47 + 1`.

## Claim boundary

- Canonical ledgers, publication data, and other workers' directories were not edited.
- No commit and no push.
- No vulnerability semantics were re-audited from scratch.
- Scope stayed at these 48 identities.
- Worker PASS/KEEP is not in play; this packet proposes authority dispositions only.
- Publication remains HOLD.
- A more-than-200 claim is not supported.
