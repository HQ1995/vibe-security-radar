# Current proposal-gap census versus canonical84

## Verdict first

**Zero genuine unresolved first-party GHSA proposals** among terminal worker PASS/KEEP/ACCEPT rows after canonical84 exclusion and later red-team supersession. Census only; this packet does not claim PASS.

`genuine_unresolved_count_is_final` is **false**. Scanned **173** packets, **441** files (170 result.json, 169 cases.jsonl, 69 selected JSONL, 33 adjudication JSONL). Parsed **10608/10608** cases.jsonl rows, **464/464** selected rows, **416/416** adjudication rows. Terminal positive GHSA ids: **100**. Canonical84 counted: **84**. Already canonical among those positives: **84**. ID conservation: **True**.

## Accepted set

canonical84 ledger `autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl` sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06` counted **84** first-party GHSA identities. Negative-control capsule `autoresearch/orchestrator-260814-ghsa200-canonical84/negative_controls.json` sha256 `740f6d5e4bae66b87fe821537d2cb48fffeb6d83365e79659a584b484ab7c00c` REJECT identities: `GHSA-2MHJ-FHVG-V428`, `GHSA-73HC-M4HX-79PJ`, `GHSA-HHJV-JQ77-CMVX`.

## Hostile and counter-redteam authority

canonical84 negative-control REJECT outranks any earlier worker or recovery PASS on the same first-party identity. Terminal packets classified hostile-redteam or counterredteam/negative_control are ranked below by ledger authority_rank then role. An AI-marked squash carrier cannot transfer authorship to a human member.
- score `10039` rank `39` role `negative_control` terminal `True` `autoresearch/herdr-260814-ghsa200-pimcore-2mhj-counterredteam-grok46-xhigh` status `TERMINAL`
- score `10000` rank `None` role `negative_control` terminal `True` `autoresearch/herdr-260814-ghsa200-ai-route-surface20-grok46-xhigh` status `TERMINAL`
- score `8000` rank `None` role `hostile_redteam` terminal `True` `autoresearch/herdr-260814-ghsa200-425g-hostile-redteam-grok46-medium` status `TERMINAL`
- score `8000` rank `None` role `hostile_redteam` terminal `True` `autoresearch/herdr-260814-ghsa200-chfm-jxx9-hostile-redteam-grok46-high` status `TERMINAL`
- score `8000` rank `None` role `hostile_redteam` terminal `True` `autoresearch/herdr-260814-ghsa200-hc8v-hostile-redteam-grok46-xhigh` status `TERMINAL`
- score `8000` rank `None` role `hostile_redteam` terminal `True` `autoresearch/herdr-260814-ghsa200-hhjv-hostile-redteam-grok46-high` status `TERMINAL`

## Class counts

- `ALREADY_CANONICAL`: 84
- `SUPERSEDED_DOWNGRADED`: 16

## Genuine unresolved (needs leader red-team; not admission)

Empty. `cases.jsonl` has zero rows.

## Later superseded or downgraded

- `GHSA-2MHJ-FHVG-V428` `autoresearch/herdr-260814-ghsa200-pimcore-2mhj-recovery-redteam-grok46-xhigh` `PASS` — canonical84 negative-control authority REJECT supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260814-ghsa200-pimcore-2mhj-counterredteam-grok46-xhigh:REJECT). An AI-marked squash carrier cannot transfer authorship to a human member when that is the recorded fatal rule, and other recorded REJECT rules likewise bind.
- `GHSA-2X93-H3HG-2XFP` `autoresearch/herdr-260813-ghsa200-upgrade-b` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-even:NARROW; autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high:NARROW).
- `GHSA-33RQ-M5X2-FVGF` `autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260814-ghsa200-batch5-two-redteam-grok46-xhigh:NARROW).
- `GHSA-4FXP-2M36-QV64` `autoresearch/herdr-260813-ghsa200-baseline-increm-even` `KEEP` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260813-ghsa200-final-candidate-review-codex:NARROW).
- `GHSA-4MR5-G6F9-CFRH` `autoresearch/herdr-260813-ghsa200-upgrade-b` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-even:NARROW; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low:NARROW).
- `GHSA-6R28-9PPF-4HJ5` `autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260814-ghsa200-batch9-three-redteam-grok46-xhigh:NARROW).
- `GHSA-7C3W-FXGH-FRC7` `autoresearch/herdr-260813-ghsa200-final-candidate-review-codex` `ACCEPT` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh:NARROW).
- `GHSA-94P4-4CQ8-9G67` `autoresearch/herdr-260813-ghsa200-upgrade-b` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-odd:NARROW; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low:NARROW).
- `GHSA-9C3V-684M-579C` `autoresearch/herdr-260813-ghsa200-upgrade-b` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-odd:NARROW; autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high:NARROW).
- `GHSA-CHFM-XGC4-47RJ` `autoresearch/herdr-260814-ghsa200-residual-leftover4-grok46-low` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260814-ghsa200-chfm-jxx9-hostile-redteam-grok46-high:REJECT).
- `GHSA-F229-3862-4942` `autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260814-ghsa200-batch5-two-redteam-grok46-xhigh:NARROW).
- `GHSA-F38V-77QJ-H4JQ` `autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high` `PASS` — canonical84 SUPERSEDES_EDGE records a later nonpositive override (autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh:NARROW).
- `GHSA-HHJV-JQ77-CMVX` `autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh` `PASS` — canonical84 negative-control authority REJECT supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260814-ghsa200-hhjv-hostile-redteam-grok46-high:REJECT). An AI-marked squash carrier cannot transfer authorship to a human member when that is the recorded fatal rule, and other recorded REJECT rules likewise bind.
- `GHSA-JXX9-PX88-PJ69` `autoresearch/herdr-260814-ghsa200-residual-leftover4-grok46-low` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260814-ghsa200-chfm-jxx9-hostile-redteam-grok46-high:REJECT).
- `GHSA-P538-C434-8V24` `autoresearch/herdr-260813-ghsa200-upgrade-b` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-odd:NARROW; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low:NARROW).
- `GHSA-V396-V7Q4-X2QJ` `autoresearch/herdr-260813-ghsa200-upgrade-b` `PASS` — Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-even:NARROW; autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high:NARROW).

## Duplicate or alias

None.

## Nonterminal or invalid schema

Terminal classified invalid-schema positives: 0.
Nonterminal packet positive ids absent from canonical84 (excluded from genuine): 0.

## Already canonical

84 terminal positive identities are already counted in canonical84. They are not gap proposals.

## Parse / schema notes

9 notes/failures (first 40):
- `{"count": 2, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-commitfirst-gn/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 7, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-contributor-redteam/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 1, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 3, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-red-upgrade-a/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 1, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-red-upgrade-b-direct/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 1, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-red-upgrade-b-ord211-release/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 22, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-redbase-even/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 18, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-redbase-odd/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 26, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-redbase/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`

## Method

Only structured result.json named ID lists, cases.jsonl, selected JSONL, and adjudication JSONL with explicit PASS/KEEP/ACCEPT (or KEEP_* / ACCEPT_* / PASS_*) were treated as proposals. Prose, routing signals, counts without IDs, stale labels, snapshot/work/pages/clone trees, and this census packet were excluded. Later terminal hostile/counter red-team or independent-review NARROW/REJECT, canonical84 SUPERSEDES_EDGE nonpositive overrides, and every REJECT row in canonical84/negative_controls.json reclassify an earlier worker proposal. Snapshot, work, pages, and clone trees were not scanned and are not retained here.
