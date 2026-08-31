# Fix-data gap A: canonical closure

## GHSA-8JQH-598V-RFXC

- Canonical row: `alias-23266042a88424523b7b8f48`, live revision `2` when this patch was prepared.
- Primary-source clone: `.ai-slop/state/repos/arnasdon_wacrm`.
- AI origin: `b7b362ae427ccf4b33b8e8cd147f16410f3ce800`; its parent `66dd4ef97edfc734c423a4252bd4ebd19e1cff80` has no `src/lib/automations/engine.ts`. The new `send_webhook` branch sends `cfg.url` directly to `fetch` with account-controlled headers and no destination guard.
- Direct fix: `7d1ddbfdb8296058ab787f7c57b8943c0214d14d`, a single-parent PR member. It imports and applies `isDeliverableUrl`, rejects redirect bouncing, and bounds the request. Officially named `23838a9959550e975d732ae08a44a3a2f0cc084b` is PR #352's two-parent merge; its relevant tree delta is identical, but it is not the atomic fix.
- Candidate is an ancestor of the direct fix. Both objects and their parents are locally available, so no `unresolved_reason` is warranted.
- Primary sources: [repository advisory](https://github.com/ArnasDon/wacrm/security/advisories/GHSA-8jqh-598v-rfxc), [origin](https://github.com/ArnasDon/wacrm/commit/b7b362ae427ccf4b33b8e8cd147f16410f3ce800), [direct fix](https://github.com/ArnasDon/wacrm/commit/7d1ddbfdb8296058ab787f7c57b8943c0214d14d), [merge](https://github.com/ArnasDon/wacrm/commit/23838a9959550e975d732ae08a44a3a2f0cc084b).
- Curated hunk hashes: candidate `1aceacde866e96d3c3e7bed432fef4f3a66c54e63e5f15555320d1221dcec7e7`; fix `c3f5c0b0c45ffe3c5a8375fbabcad461087d6c4c51a8c9d8abf0f445589b39f8`.

## GHSA-W28W-GP39-M4P6

The decisive primary-source analysis and exact two-hunk fix extraction are in `fixgap-a-w28w-research.md`. The published case belongs to kept row `alias-50a179b091fae05cd3c940e9` revision `2`; `alias-3a0294dfd1f9cff8531aacfd` is only the folded duplicate and is intentionally untouched. Direct fix `e4a0ebf49e3a78d5d7796c8480bf9a4f0c54d19e` is used instead of PR merge `047756f4c8caf91c5868eeb42520c938393277b0`. No `unresolved_reason` is warranted.

## Boundary

This artifact only prepares two optimistic-lock ledger updates. It does not apply, export, publish, or commit them.
