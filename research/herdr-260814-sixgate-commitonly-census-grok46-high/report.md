# Six-causal-gate commit-only census

Verdict first: inventory only. PASS_PROPOSAL=0. Countable PASS=0. Canonical88 stays 88 and was not edited.

Active objective is false-positive-free AI-causal GHSA cases. Release containment is a separate publication tier. This packet ranks commit-only candidates for independent replay. It does not admit or promote a row.

## Selection

Scanned structured terminal cases.jsonl, case.json, facts/gates.json, and result.json gate objects under autoresearch herdr-260813-* and herdr-260814-*. snapshot/work/pages/clones were not scanned. Inventory packets are not winning authority. Missing gates were never inferred from verdict text.

Complete explicit six-causal-gate rows: 6950. Terminal non-inventory complete rows: 5793. Scan files: 497.

A GHSA mechanism is inventoried only when the latest strongest terminal row records identity, AI hunk, topology, scoped but-for, fix reversal, and uniqueness as PASS, and release is UNKNOWN, NARROW, FAIL, or COMMIT_ONLY. Equal-or-stronger causal disagreement is fail-closed. Shared SHA is not a duplicate. Canonical88 strict identities are excluded.

Ranked inventory rows: **7**. Unique IDs: **7**. Negative controls: **5**. Fail-closed latest-not-six (older six-open existed): 4.

## Ranked inventory

Highest rank requires a primary first-party advisory or exact repo fix, an atomic AI marker, explicit candidate and minimum fix sets, no equal-strength but-for conflict, and only release open.

1. GHSA-H2V8-4C3F-VQGV rank_class=1 release=UNKNOWN repo=brentmid/evernote-mcp-server auth=herdr-260814-h2v8-release-closure-grok46-high
   mechanism evernote-mcp.auth.openBrowser.exec.url-interpolation
   candidate e08547bcdb42aaa86190c6e2dfc64159fcd3a146 fix 1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579
   Positive control. Dedicated release-closure rebuilt six PASS with n_parents=1 Claude markers. CF4-b2 but_for NARROW is weaker and superseded; retained as a conflict ref.

2. GHSA-8G98-M4J9-QWW5 rank_class=1 release=UNKNOWN repo=tailot/taylored auth=herdr-260814-ghsa200-fp211-unknown4a-grok46-low
   mechanism taylored.paypal-webhook.unverified-body.purchase-token
   candidate c139c021f68a09d22c2af88641b61c00f67f2af4 fix 57b7634391959dbbdb39b387ac4dc68157cd58a1

3. GHSA-VH5J-5FHQ-9XWG rank_class=1 release=UNKNOWN repo=tailot/taylored auth=herdr-260814-ghsa200-fp211-unknown4a-grok46-low
   mechanism taylored.get-patch.token_used_at.select-then-update-race
   candidate 57b7634391959dbbdb39b387ac4dc68157cd58a1 fix fdf67a6fba0deae30912905a79fb5a9e83751a79

4. GHSA-G8MR-85JM-7XHM rank_class=1 release=NARROW repo=vitest-dev/vitest auth=herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium
   mechanism vitest.browser.rpc.cdp-ungated-when-allowWrite-false
   candidate af88b1f5d82844a4761ea9a977156c98e2b14ca8 fix 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7

5. GHSA-HR7P-WG7R-HG9M rank_class=1 release=FAIL repo=flytohub/flyto-core auth=herdr-260814-cf2-af-new-surface-grok46-low
   mechanism env_interpolation_bypasses_env_get_denylist
   candidate 68af171dcf42b89fb5d3f5f3f60c2ae25f91e5ce fix d5f89d71303e3c1e6418d347c5c55fcd173cc8cc

6. GHSA-98HH-7GHG-X6RQ rank_class=2 release=FAIL repo=openclaw/openclaw auth=herdr-260814-ghsa200-directroot-batch19-grok46-medium
   mechanism sets:[["483fba41b9f9fb57964f31b90a2ddacb185d54d7"],["355abe5eba28012e6a95b9923a32831fcf870344"]]
   candidate 483fba41b9f9fb57964f31b90a2ddacb185d54d7 fix 355abe5eba28012e6a95b9923a32831fcf870344

7. GHSA-C65F-X25W-62JV rank_class=2 release=FAIL repo=jahlives/openssl_encrypt auth=herdr-260814-ghsa200-directroot-batch6-grok46-low
   mechanism sets:[["4c7ae852c784c9986d087c5956a77fa563a05a35","fafdfeed1b279cfe61e86cd8adc132b206eef8d4"],["809416b74d2749cdcffb484cd65b057e1685cc13"]]
   candidate fafdfeed1b279cfe61e86cd8adc132b206eef8d4,4c7ae852c784c9986d087c5956a77fa563a05a35 fix 809416b74d2749cdcffb484cd65b057e1685cc13

## H2V8 independent verify

GHSA-H2V8-4C3F-VQGV packet hashes: cases.jsonl `db9b6c7c456e2909c9c6395edf7bcb828e76b432b3b981389fadea3010b8d0f9`, result.json `dbdff9bbb5526db941a04f681c2f7609950505bf2cc3b87340e903cadee8c568`, assignment.jsonl `f8c2ae028b9e803584892f7774a8ea23068ded1c8623cbd35ac5242d06d28d51`.
Gates: identity/ai_hunk/topology/but_for/fix_reversal/uniqueness PASS. release UNKNOWN. Candidate e08547bcdb42aaa86190c6e2dfc64159fcd3a146. Fix 1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579. n_parents=1.

## Negative controls

Release-open rows whose latest strongest terminal vector also has a causal FAIL. They are not inventory.

- GHSA-VP55-5C2V-3597 release=UNKNOWN causal_FAIL=ai_hunk_gate,but_for_gate,fix_reversal_gate auth=herdr-260814-cf4-b2-remediation-grok46-high
- GHSA-C5CP-VX83-JHQX release=UNKNOWN causal_FAIL=ai_hunk_gate,but_for_gate,fix_reversal_gate auth=herdr-260814-cf2-kn-remediation-grok46-xhigh
- GHSA-8QXC-57HF-HC9J release=FAIL causal_FAIL=ai_hunk_gate,but_for_gate auth=herdr-260814-dr2-grok46-high
- GHSA-F29H-2H58-48R7 release=FAIL causal_FAIL=ai_hunk_gate,but_for_gate,fix_reversal_gate auth=herdr-260814-dr2-grok46-high
- GHSA-M8XG-8XG9-MXHM release=UNKNOWN causal_FAIL=ai_hunk_gate,but_for_gate,fix_reversal_gate auth=herdr-260814-cf2-kn-remediation-grok46-xhigh

## Fail-closed examples

GHSA-4FXP-2M36-QV64 had older six-PASS rows with release UNKNOWN, but later terminal confirm11-closure records identity_gate NARROW. Excluded.
GHSA-8JQH-598V-RFXC unknown4a records six PASS, but same-date independent unknown9 records identity and topology NARROW. Fail-closed exclusion.
GHSA-2X93/9C3V/V396 later red-team rows record but_for NARROW and often release PASS. Excluded.
GHSA-8G98 and GHSA-VH5J share SHA 57b76343 in opposite candidate/fix roles and remain distinct fingerprints.

## Claim boundary

This is not a count of admitted AI-causal cases. Worker PASS remains a proposal. Publication and more-than-200 stay HOLD. Canonical88 ledger and summary were read, hashed, and left unchanged.

Status TERMINAL. No network. No new clones. No promotion. No commit.
