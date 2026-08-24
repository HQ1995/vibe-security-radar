# GHSA proposal census

## Verdict first

**1 terminal genuine unabsorbed first-party GHSA proposal(s)** (not a final count). In-flight packets narupa/narupb/netred are excluded until terminal. Census only; not admission.

`genuine_unabsorbed_count_is_final` is **false**. Scanned **126** files (89 `result.json`, 37 `cases.jsonl`) across **64** packets. Parsed **8556/8556** case lines. Terminal positive GHSA ids: **74**. Terminal set difference vs 48 and 32: **7**. ID conservation: **True**. Arithmetic: 45 + 22 + 7 = 74.

## Comparison sets

- (a) Strict released baseline: **48** first-party GHSA ids (CONFIRM/HIGH and `release_gate=PASS` on fp211 mechanisms, bound through `public_cases.jsonl`).
- (b) Final candidate review: **32** rows in `herdr-260813-ghsa200-final-candidate-review-codex/cases.jsonl`.

## Census class counts (unabsorbed = positives − 48 − 32)

- `GENUINE_UNABSORBED`: 1
- `SUPERSEDED`: 6

## Genuine unabsorbed

- `GHSA-6P9M-Q3JP-47H4` packet `autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium/cases.jsonl` status `TERMINAL` verdict `PASS` mechanism `gogs.lfs.localstorage.upload.dedupe-shortcut.unhashed-oid-bind` candidate `['85ebf175c0f953253247717f72f50fd6aba2d362', '90f99d5f672ba95cf8cdb1a1d915acb079adb5ef']` fix `['f35a767af74e05342bafc6fdda02c791816426f8', 'e2fae5d0455d4f92c6382433d21c3a16da077d64']` — Seven-gate PASS/ACCEPT/KEEP proposal with a first-party GHSA id, absent from both the 48 baseline and the 32-row final review (including post-freeze recoveries).

## In-flight excluded (not counted)

Forced IN_FLIGHT_EXCLUDED until terminal: `narrow-recovery-a-grok46-xhigh` (narupa), `narrow-recovery-b-grok46-high` (narupb), `netnew22-redteam-grok46-xhigh` (netred). Other nonterminal packets are also excluded from the terminal positive set.

In-flight proposal ids absent from both the 48 and the 32:
- `GHSA-7GH7-258J-4MPQ` from `autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh`
- `GHSA-F38V-77QJ-H4JQ` from `autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high`
- `GHSA-G3XQ-3GMV-QQ8G` from `autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high`
- `GHSA-PV2J-RGHR-V5R9` from `autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high`

Regression: `GHSA-F38V-77QJ-H4JQ`, `GHSA-G3XQ-3GMV-QQ8G`, and `GHSA-PV2J-RGHR-V5R9` are not superseded by older upgrade-b or remediation NARROW if a later independent recovery review closes gates. Those packets are currently in-flight, so the ids appear in the in-flight list rather than as a final genuine count.

## Other terminal difference rows

- `GHSA-2X93-H3HG-2XFP` `SUPERSEDED` `autoresearch/herdr-260813-ghsa200-upgrade-b/cases.jsonl` `PASS` — A later terminal red-team or independent-review downgrade supersedes an earlier PASS/KEEP (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-even:NARROW). Older worker/inventory NARROW is not used as override.
- `GHSA-4MR5-G6F9-CFRH` `SUPERSEDED` `autoresearch/herdr-260813-ghsa200-upgrade-b/cases.jsonl` `PASS` — A later terminal red-team or independent-review downgrade supersedes an earlier PASS/KEEP (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-even:NARROW). Older worker/inventory NARROW is not used as override.
- `GHSA-94P4-4CQ8-9G67` `SUPERSEDED` `autoresearch/herdr-260813-ghsa200-upgrade-b/cases.jsonl` `PASS` — A later terminal red-team or independent-review downgrade supersedes an earlier PASS/KEEP (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-odd:NARROW). Older worker/inventory NARROW is not used as override.
- `GHSA-9C3V-684M-579C` `SUPERSEDED` `autoresearch/herdr-260813-ghsa200-upgrade-b/cases.jsonl` `PASS` — A later terminal red-team or independent-review downgrade supersedes an earlier PASS/KEEP (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-odd:NARROW). Older worker/inventory NARROW is not used as override.
- `GHSA-P538-C434-8V24` `SUPERSEDED` `autoresearch/herdr-260813-ghsa200-upgrade-b/cases.jsonl` `PASS` — A later terminal red-team or independent-review downgrade supersedes an earlier PASS/KEEP (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-odd:NARROW). Older worker/inventory NARROW is not used as override.
- `GHSA-V396-V7Q4-X2QJ` `SUPERSEDED` `autoresearch/herdr-260813-ghsa200-upgrade-b/cases.jsonl` `PASS` — A later terminal red-team or independent-review downgrade supersedes an earlier PASS/KEEP (autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam:NARROW; autoresearch/herdr-260813-ghsa200-increm-patchdelta-even:NARROW). Older worker/inventory NARROW is not used as override.

## Parse / schema failures

3 notes/failures:
- `{"count": 2, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-commitfirst-gn/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 1, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`
- `{"count": 26, "kind": "SCHEMA_NOTE", "path": "autoresearch/herdr-260813-ghsa200-redbase/result.json", "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists"}`

## Frozen hashes

- `CONTRACT.md`: `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- `baseline.json`: `d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132`
- `canonical_ledger.jsonl`: `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`
- `final_candidate_review_codex/cases.jsonl`: `e275437954890dca07855b5fcfa545f8f1a366fb85a7ee9f067da5b710b2b3da`
- `final_candidate_review_codex/result.json`: `4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528`
- `final_mechanisms.jsonl`: `0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2`
- `public_cases.jsonl`: `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`

## Non-proposals excluded

Source envelopes, routing signals, CVE-primary rows, counts without row IDs, and duplicate snapshot copies were not treated as proposals. See `skipped_non_proposal` in result.json.

