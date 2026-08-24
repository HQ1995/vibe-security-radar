# GHSA 200 Released Publication Review

Date: 2026-08-13
Lane: `autoresearch/herdr-260813-ghsa200-redbase/`
Contract hash: `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`

## Verdict

I reviewed the exact 48 rows selected by:

`row["counting"]["fp211_released_publication_admitted"] is true`

from `autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl`.

Final split:

- `KEEP`: 26
- `UNKNOWN`: 22
- `NARROW`: 0
- `REJECT`: 0
- `BLOCKED`: 0

## What was tested

I did not accept frozen PASS labels or prior prose as proof. I replayed first-party evidence from the local clone cache at `/home/hanqing/.cache/ghsa200-worker-clones/redbase/clones` and from the npm registry where the release artifact is a package version.

The exact 48 admitted ordinals are:

`2, 6, 12, 14, 18, 19, 23, 26, 27, 32, 39, 42, 43, 44, 46, 49, 54, 57, 58, 63, 64, 65, 66, 73, 76, 81, 106, 111, 112, 118, 119, 135, 137, 147, 148, 160, 161, 162, 163, 164, 166, 167, 171, 176, 179, 182, 185, 210`

## KEEP rows

I kept only rows where independent release containment replayed cleanly:

- `2`, `6`, `12`, `14`, `18`, `19`, `23`, `26`, `27`, `32`, `39`
- `43`, `44`, `46`, `49`, `54`, `57`, `63`, `64`, `73`
- `111`, `162`, `164`, `182`, `185`, `210`

These rows had first-party tag/version containment that could be replayed directly.
For the npm-style rows, the package registry `gitHead` matched the fixed and vulnerable version boundaries.

## UNKNOWN rows

The remaining 22 rows were left UNKNOWN because the canonical row did not give independent release evidence, or because the row could not be tied out to a first-party release artifact in this pass:

`42, 58, 65, 66, 76, 81, 106, 112, 118, 119, 135, 137, 147, 148, 160, 161, 163, 166, 167, 171, 176, 179`

## Notes on the contract revision

The leader contract was revised to `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
The incomplete-remediation clarification applies only to rows where an AI security attempt rewrites a boundary and later same-mechanism closure directly amends the residual bypass.

That clarification did not change this lane's final split, because the 48 admitted rows here were resolved by direct release/tag containment replay rather than by reopening old-bug preservation arguments.

## Replay basis

All commands used for the review are recorded in `replay.txt`.
