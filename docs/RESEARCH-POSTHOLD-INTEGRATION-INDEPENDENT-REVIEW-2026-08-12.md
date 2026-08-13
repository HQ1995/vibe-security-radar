# Post-hold canonical integration independent review

Review completed: 2026-08-13 (America/New_York)
Pinned canonical: `20b795ccaa2cbbe22723998e931d1200f043c865`

## Verdict

**HOLD the integration as a whole.** The pinned canonical blob is still a 211-component source envelope, not a confirmed 200: `strict/broad/widest = 132/199/211`, released states `PASS/NARROW/REJECT/UNKNOWN = 126/43/23/7`, `integration_ready=false`, and `final_count=null`.

The reviewed corrections are useful and mostly apply-safe, but they do not share a single composed, hash-bound transaction and the accepted verifier patch does not validate these external correction schemas. Integrate only from the exact pinned ledger after composing the accepted items below, regenerate all derived hashes/counts, then run the hardened verifier. Do not publish a 200 claim from any intermediate projection.

## Authenticated inputs

- Canonical ledger: `cf53395e97fffcf5080edeadb8b31ff3b263bb44bef940f22c044ea6eac35bb8`
- Canonical result / summary / source manifest: `c34edf2b6542178e15cb3421a1249c28e214f9855b86f52c5c5c129f469a99d5` / `782a68e4485428656f603d67f09c0c80f71355bbcfad05896c65a52ce32e6132` / `92cb752303f674be618643c85150b5f36e6881e6b49a4a3c6a4564bd8d310f5b`
- All 11 named terminal-package JSON/JSONL files parse. The 28 directly named local input path/hash pairs recovered from their manifests match. Package result SHA-256 values are listed in the replay section.

## ACCEPT — safe correction content

| Packet | Accepted content | Boundary |
|---|---|---|
| `identity-closure-final` | Apply all 15 formal-identity corrections: add 8 omitted GHSAs, retain all 22 existing IDs, and correct WACRM repository to `ArnasDon/wacrm`. | Identity/repository fields only; no causal, mechanism, state, or counting change. Preserve all recorded 404s. |
| `fingerprint-unknown-closure` | Mark `post:scriban-lazy-range@canonical` as the same mechanism series as `post:scriban-array-multiply@canonical`; materialize it as `DUPLICATE`, point `duplicate_of` to the array-multiply row, and clear all counting flags. Keep the other 19 pairs separate. | This removes one canonical incomplete-released component/envelope row. Do not turn same fix/candidate/repository into formal-alias evidence. |
| `fingerprint-unknown-closure-2` | Keep all 30 adjudicated pairs separate. | Four equal-score pairs were explicitly deferred; no global duplicate-closure claim. |
| `promotion-final-consolidation` | The 21 exact preconditioned `NARROW -> PASS` row patches are safe to compose; preserve 5 NARROW and 1 UNKNOWN. | Promotion-only, unapplied; 93/93 packet preconditions passed, but the packet itself says not publication/integration authorization. |
| `release-three-unknowns` | Taylored `PASS -> UNKNOWN`; Prompty `PASS -> NARROW` plus formal `CVE-2026-73299` amendment; BSV ARC remains PASS with the first-party origin/release edge filled. | Missing artifacts stay UNKNOWN. The Prompty named merge is not in the patched npm artifact. |
| `release-remaining-crossred` | Accept the semantic finding for `post:gitpython-split-mode@canonical`: it is the same mechanism series as the already-counted kwarg-option row. Materialize it as `DUPLICATE`, set `duplicate_of`, and clear all counting flags. | Do **not** apply the raw `REJECT + duplicate_of` patch: hardened v3 rejects that combination. This removes one canonical incomplete-released component/envelope row. |
| `min-blockers-final` | Keep direct-CDP row `strict-200-v3:alias-e082...` NARROW; change trusted-proxy-origin row `strict-200-v3:alias-d67...` `PASS -> REJECT`. | The trusted-proxy predicate is human-origin; the listed AI SHA belongs to a pairing sibling. |
| `verifier-hardened-v3` | Accept patch `e41c367df2f83e8f0b939b4c410e24c6342166bb192f60aaa39b0eb13ec1ae11`. The current worktree diff from the pinned commit is byte-identical to it. | 9/9 mutations caught and 7/7 canonical tests passed in the isolated packet. It does not replay external evidence or apply corrections; its pinned `211`/tier assertions must be regenerated deliberately for the new canonical contract. |
| Koel | Add exactly one released PASS component, `AI_INCOMPLETE_REMEDIATION`, `not_origin=true`, IDs `{GHSA-RJG7-R26H-CFP2, CVE-2026-54494}`. | AI classifier residual is NAT64/6to4; member/carrier tree `1a3e0ca9...`; vulnerable `v9.7.0`, fixed `v9.7.1`. |
| SIPSorcery | Add exactly one released PASS STRICT component, GHSA-only `GHSA-PFVM-W89X-94JW`. | Member `6edd60f5...`, carrier `dd767827...`, fix member/carrier `5d432d4b...` / `ccb0b5a8...`; `10.0.13 -> 10.0.14`. |
| Relyra | Add exactly one `STRICT_RELEASED` component in **NARROW** state, formal alias `{GHSA-JV46-XFWM-36J7, CVE-2026-49454}`; do not count it as confirmed PASS. | Both independent terminal red-teams close causality, but one says PASS/STRICT and one says NARROW. Store corrected published Hex `1.1.0 -> 1.2.0` and minimum fix `{2e456897...}`; keep `8910200...` as a distinct advisory companion. |

## HOLD / reject list

- **Koel siblings stay out:** JR4P (missing `bail`, wrong edge), 7J2F (human enclosure origin), and 6QVR (human redirect/DNS-rebinding incomplete remediation). Shared repository and later fix `5f6ce2ce...` do not collapse their distinct source/sink/invariant boundaries into RJG7.
- **SIPSorcery duplicate packets do not add rows:** `grok-red`, `crossred`, `new-c-cpp-dotnet`, and `fresh-delta-precutoff-novel` describe one PFVM row. `EXCLUDED_DUPLICATE` is temporal/concurrent packet dedup, not a duplicate of canonical and not a reason to discard the row.
- **Relyra is NARROW, not HOLD and not PASS:** `/tmp/herdr-ai-slop-relyra-crossred` and `relyra-causal-red` independently close the readable atomic Cursor origin, but-for path, formal alias, and Hex `1.1.0 -> 1.2.0` containment. The older HOLD blockers are gone. Preserve a `STRICT_RELEASED` NARROW row because the terminal packets disagree on whether the advisory's nonexistent Hex `1.0.0` floor and over-wide two-SHA fix set are claim-grade defects. Resolve that policy globally before PASS promotion.
- **Raw GitPython duplicate patch stays out:** only its normalized `DUPLICATE` form is acceptable; `REJECT + duplicate_of` would fail the accepted verifier.
- **Do not apply stale projections as totals.** `sipsorcery-count-reconcile` starts from `count-projection-fast` (`131/198/211`) and a Koel neighbor overlay, not pinned canonical `132/199/211`. Its `+1 SIPSorcery` row is accepted, but its reported `132/200/213` totals are not canonical integration totals.
- **No final 200 and no `integration_ready=true`.** Even after accepted state corrections and three new components, numerous released NARROW/REJECT/UNKNOWN rows remain; the original inherited-coverage blocker is also not closed by these packets.

## Projected state for integration QA (not canonical)

From the pinned canonical, compose the non-overlapping state changes: `+21 NARROW->PASS`, one `PASS->NARROW`, one `PASS->UNKNOWN`, one `PASS->REJECT`, collapse one existing PASS component and one existing REJECT component to non-counting duplicates, add Koel and SIPSorcery as PASS, and add Relyra as NARROW. The resulting check target is:

| Metric | Pinned | Projected |
|---|---:|---:|
| Canonical counted components | 211 | **212** |
| Physical component-row instances | 214 | **217** |
| Released PASS / NARROW / REJECT / UNKNOWN | 126 / 43 / 23 / 7 | **145 / 24 / 23 / 8** |
| Strict / broad / widest envelopes | 132 / 199 / 211 | **134 / 200 / 212** |
| Confirmed released PASS | 126 | **145** |

The two exact-mechanism duplicates are both counted at the pinned base; hardened duplicate semantics therefore subtract two components and two broad/widest rows. Identity amendments add public IDs, not components. These figures are arithmetic QA expectations only; the rebuilt builder/verifier output remains authoritative.

## Replay

```zsh
HEAD=20b795ccaa2cbbe22723998e931d1200f043c865
git show "$HEAD":autoresearch/orchestrator-260812-posthold-canonical/ledger.jsonl | sha256sum

for f in \
  /tmp/herdr-ai-slop-identity-closure-final/result.json \
  /tmp/herdr-ai-slop-fingerprint-unknown-closure/result.json \
  /tmp/herdr-ai-slop-fingerprint-unknown-closure-2/result.json \
  /tmp/herdr-ai-slop-promotion-final-consolidation/result.json \
  /tmp/herdr-ai-slop-release-three-unknowns/result.json \
  /tmp/herdr-ai-slop-release-remaining-crossred/result.json \
  /tmp/herdr-ai-slop-min-blockers-final/result.json \
  /tmp/herdr-ai-slop-verifier-hardened-v3/result.json \
  /tmp/herdr-ai-slop-three-candidate-reconciliation/result.json \
  /tmp/herdr-ai-slop-sipsorcery-count-reconcile/result.json \
  /tmp/herdr-ai-slop-relyra-causal-red/result.json; do
  jq -e . "$f" >/dev/null && sha256sum "$f"
done

# Assert the three proposed identities are absent from the pinned ledger.
git show "$HEAD":autoresearch/orchestrator-260812-posthold-canonical/ledger.jsonl |
  rg -i 'RJG7-R26H-CFP2|PFVM-W89X-94JW|JV46-XFWM-36J7|CVE-2026-54494|CVE-2026-49454' || true

# Recheck the accepted verifier patch already present in the dirty worktree.
git diff --binary "$HEAD" -- \
  autoresearch/orchestrator-260812-posthold-canonical/test_canonical.py \
  autoresearch/orchestrator-260812-posthold-canonical/verify.py | sha256sum
```

Terminal result package hashes, in the order above:

```text
7d4c81f923420adc8a6ef66b0f44365eef630ae42384ec1df13307028998a013
f07deb27b471538e866c590567577f0e950b35f61ecc335199bbaf861e284f31
04c74213343188e4db3995aea5dbc05c6782ac4c8aebbc78bab4f9eae4217a6b
6d62eda917052daddb9456f21ef897c6ff318cde827034ffbe27e3fc23a5a882
09b7f6f62ccf70e0529cb2c0141c21678a080a29ef83c47567cfdd7cecf3ed1a
32c987fd36907b7292e86a6bbfb3efb002171272862b39085259a5240805ceab
46e4bdc104e62fc0177b3badfff87fd1d7efd57d3d87607e23690964bf6e575a
c9a5e8b113badccb52bc91de4e8c1627624d7ff757e02a399dc61f10b137727a
4196c181e9a1ffd5c39a798363b82a65c312da48b5dc5358d982c6893b87f6c9
d4c1225dfc1de1ff16d6c4e64338975af5fe8d827381539d752e8d64adbdf8ff
9ac6897f86d8f276dbc04955d0f592b79226b1e2098090568547642dcc88c38e
```

## Final decision

**ACCEPT** the enumerated correction content, the two normalized non-counting duplicates, hardened verifier patch, Koel once, SIPSorcery once, and Relyra as `STRICT_RELEASED`/NARROW. **HOLD** the raw GitPython `REJECT + duplicate_of` patch, Relyra PASS promotion, all Koel siblings, duplicate packet rows, stale projection totals, final-count publication, and the integration transaction until a single composed rebuild passes the hardened verifier and retains `integration_ready=false` while blockers remain.
