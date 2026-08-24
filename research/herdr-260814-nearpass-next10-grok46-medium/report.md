# Near-pass next-10 routing inventory

TERMINAL inventory. This packet does not call a PASS and does not infer causality.

Baseline canonical94 ledger SHA256 7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096, strict 94.
CONTRACT SHA256 cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3.
Scanned 442 frozen English ASCII JSON/JSONL result files under herdr-260814-* plus canonical94. Replay validates those hashes and does not scan the live tree.

Newest terminal identities 1648 = 32 canonical94 + 1312 REJECT/FAIL + 1 commit-only + 7 explicit gate FAIL + 142 other verdict + 154 eligible. Eligible 154 = 10 queued + 144 leftover. Assigned 10 = 0 reviewed + 10 unreviewed. PASS=0. Canonical count is unchanged. Greater-than-200 remains unsupported.

No PASS_PROPOSAL absent from canonical94 still lacked independent hostile review. Selection prefers one closable gate (release, topology, or fix reversal). Conflicts are marked and ranked lower, not resolved. Inherited PASS labels, packet summaries, shared SHAs, and same-repo fixes are not proof.

## Queued 10

### 1. GHSA-8JQH-598V-RFXC UNKNOWN

Repository: ArnasDon/wacrm
Newest terminal: autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low verdict UNKNOWN
Missing gates: release_gate
Conflicts: marked=false verdict_set=UNKNOWN
Candidate set: b7b362ae427ccf4b33b8e8cd147f16410f3ce800
Carrier set: empty
Minimum fix set: 7d1ddbfdb8296058ab787f7c57b8943c0214d14d
Source packets: autoresearch/herdr-260814-final-unknown9-grok46-high, autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low
Why hostile review: Newest terminal UNKNOWN keeps six gates at PASS and only release_gate UNKNOWN, with no explicit FAIL. Hostile review should test recovered first-party artifact containment for ArnasDon/wacrm webhook SSRF and must not inherit the UNKNOWN label.

### 2. GHSA-8G98-M4J9-QWW5 NARROW

Repository: tailot/taylored
Newest terminal: autoresearch/herdr-260814-causalonly-release-recheck-grok46-high verdict NARROW
Missing gates: release_gate
Conflicts: marked=true verdict_set=NARROW,PASS_PROPOSAL,UNKNOWN
Candidate set: c139c021f68a09d22c2af88641b61c00f67f2af4
Carrier set: empty
Minimum fix set: 57b7634391959dbbdb39b387ac4dc68157cd58a1
Source packets: autoresearch/herdr-260814-causal-consensus-a-grok46-high, autoresearch/herdr-260814-causalonly-release-recheck-grok46-high, autoresearch/herdr-260814-commitonly-taylored-grok46-medium, autoresearch/herdr-260814-final-unknown9-grok46-high, autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low, autoresearch/herdr-260814-legacy-unknown3-grok46-medium, autoresearch/herdr-260814-sixgate-commitonly-census-grok46-high
Why hostile review: Newest terminal NARROW is a six-causal PASS with only release_gate NARROW. Older packets conflict as PASS_PROPOSAL, UNKNOWN, and commit-only census. Conflict is recorded, not resolved. Hostile review should recover an exact 7.0.5-class artifact and must not trust inherited PASS.

### 3. GHSA-VH5J-5FHQ-9XWG NARROW

Repository: tailot/taylored
Newest terminal: autoresearch/herdr-260814-causalonly-release-recheck-grok46-high verdict NARROW
Missing gates: release_gate
Conflicts: marked=true verdict_set=NARROW,PASS_PROPOSAL,UNKNOWN
Candidate set: 57b7634391959dbbdb39b387ac4dc68157cd58a1
Carrier set: 5e5a80b5ffd0b6fccf7bdc2d8793e8b01cb83844
Minimum fix set: fdf67a6fba0deae30912905a79fb5a9e83751a79
Source packets: autoresearch/herdr-260814-causal-consensus-a-grok46-high, autoresearch/herdr-260814-causalonly-release-recheck-grok46-high, autoresearch/herdr-260814-commitonly-taylored-grok46-medium, autoresearch/herdr-260814-final-unknown9-grok46-high, autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low, autoresearch/herdr-260814-legacy-unknown3-grok46-medium, autoresearch/herdr-260814-sixgate-commitonly-census-grok46-high
Why hostile review: Distinct first-party identity from GHSA-8G98. Newest terminal NARROW leaves only release_gate open. Shared SHA 57b76343 is the 8G98 closer here and is not a case merge. Older PASS_PROPOSAL/UNKNOWN labels conflict and are not proof.

### 4. GHSA-G8MR-85JM-7XHM NARROW

Repository: vitest-dev/vitest
Newest terminal: autoresearch/herdr-260814-causalonly-release-recheck-grok46-high verdict NARROW
Missing gates: release_gate
Conflicts: marked=true verdict_set=NARROW,PASS_PROPOSAL
Candidate set: af88b1f5d82844a4761ea9a977156c98e2b14ca8
Carrier set: empty
Minimum fix set: 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7
Source packets: autoresearch/herdr-260814-causal-consensus-a-grok46-high, autoresearch/herdr-260814-causalonly-release-recheck-grok46-high, autoresearch/herdr-260814-cf3-confirm5-grok46-high, autoresearch/herdr-260814-commitonly-h2v8-vitest-grok46-high, autoresearch/herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium, autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low, autoresearch/herdr-260814-sixgate-commitonly-census-grok46-high
Why hostile review: Newest terminal NARROW leaves only release_gate open on vitest-dev/vitest. Older PASS_PROPOSAL and commit-only vitest packets conflict and are not inherited. Hostile review should test recovered browser-mode artifacts without transferring commit-only SHAs.

### 5. GHSA-5GVR-V6QV-H5MM NARROW

Repository: thedotmack/claude-mem
Newest terminal: autoresearch/herdr-260814-nearclosed-k-grok46-xhigh verdict NARROW
Missing gates: fix_reversal_gate
Conflicts: marked=true verdict_set=NARROW,REJECT
Candidate set: c6f932988a71e4eb0bf15108c91eec7d9eb64349
Carrier set: empty
Minimum fix set: f32fda8b35e9fe9329f87da65c31149362a03f97
Source packets: autoresearch/herdr-260814-cf3-twogate7-grok46-high, autoresearch/herdr-260814-ghsa200-fp211-unseen-twogate8-grok46-medium, autoresearch/herdr-260814-legacy-nearest4-grok46-medium, autoresearch/herdr-260814-nearclosed-k-grok46-xhigh
Why hostile review: Newest terminal NARROW leaves only fix_reversal_gate open. An older legacy packet REJECT remains in the evidence set. Conflict is marked and ranked lower; this packet does not choose between NARROW and REJECT. Hostile review should replay the named closer against the advisory invariant.

### 6. GHSA-M63V-2G9W-2W6V NARROW

Repository: fission/fission
Newest terminal: autoresearch/herdr-260814-cf3-confirm5-grok46-high verdict NARROW
Missing gates: topology_gate, release_gate
Conflicts: marked=false verdict_set=NARROW
Candidate set: 2db76f65dbfe4f657b4a4efb506ed63b24623e92
Carrier set: e484df8460bb4e8026e24210120602aa7f181f64
Minimum fix set: 695d3e97e3a20463ab7c8c081843e69e65e952e5
Source packets: autoresearch/herdr-260814-cf3-confirm5-grok46-high, autoresearch/herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium, autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low
Why hostile review: Newest terminal NARROW is limited to topology_gate and release_gate, both closable. Candidate versus carrier SHAs are recorded and are not transferred. Hostile review should resolve squash ancestry and released containment independently.

### 7. GHSA-P5RM-JG5C-8C77 NARROW

Repository: microsoft/kiota
Newest terminal: autoresearch/herdr-260814-cf3-confirm5-grok46-high verdict NARROW
Missing gates: topology_gate, release_gate
Conflicts: marked=false verdict_set=NARROW
Candidate set: f51f4971ea3459cd410b363b34e156a116b530f4
Carrier set: de3d18d9fe31ced4ac749728d3a2f94811f59268
Minimum fix set: 430008e9d700b3fe80f206c672415cfbd8e830e7
Source packets: autoresearch/herdr-260814-cf3-confirm5-grok46-high, autoresearch/herdr-260814-fresh-strict-grok46-xhigh, autoresearch/herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium, autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low
Why hostile review: Newest terminal NARROW is limited to topology_gate and release_gate on microsoft/kiota. Carrier de3d18d9 is not authorship. Hostile review should close those two gates without inheriting confirm5 PASS labels.

### 8. GHSA-X8QQ-M4QC-RPJ5 NARROW

Repository: Roskus/prospero-flow-crm
Newest terminal: autoresearch/herdr-260814-cf3-confirm5-grok46-high verdict NARROW
Missing gates: identity_gate, release_gate
Conflicts: marked=false verdict_set=NARROW
Candidate set: 56ea64c80fd36840fe3c84d0c6a6a38296a8f111, 86f406519fd208f9be09cd7cf32cd24d292779fd
Carrier set: empty
Minimum fix set: 9a859c4de3d49674916773d346c60d89ad7febe0
Source packets: autoresearch/herdr-260814-cf3-confirm5-grok46-high, autoresearch/herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium, autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low
Why hostile review: Newest terminal NARROW leaves identity_gate and release_gate open. Candidate set has two SHAs; shared SHA is not dedupe. Hostile review should test first-party identity plus recovered artifacts and must not treat same-repo GHSA-4FXP as this case.

### 9. GHSA-65H7-C7C4-MGHX NARROW

Repository: mlflow/mlflow
Newest terminal: autoresearch/herdr-260814-cf4-b3-history-grok46-xhigh verdict NARROW
Missing gates: ai_hunk_gate, release_gate
Conflicts: marked=false verdict_set=NARROW
Candidate set: 3094ab608b1d91bff5830d5a89aa042ccd3c9acc
Carrier set: 3094ab608b1d91bff5830d5a89aa042ccd3c9acc
Minimum fix set: 64aa0ab7207f9c649b59ba1a5f40d82196817389
Source packets: autoresearch/herdr-260814-cf4-b3-history-grok46-xhigh
Why hostile review: Newest terminal NARROW leaves ai_hunk_gate and release_gate open. candidate_set equals carrier_set SHA 3094ab60; that equality is not proof of atomic AI hunk or released containment. Hostile review should refuse squash transfer and recover artifacts.

### 10. GHSA-Q9J6-XCVX-PX63 NARROW

Repository: coollabsio/coolify
Newest terminal: autoresearch/herdr-260814-nearclosed-g-grok46-low verdict NARROW
Missing gates: but_for_gate, fix_reversal_gate
Conflicts: marked=false verdict_set=NARROW
Candidate set: bbb2aa9ad4e0c14517d32272b5e6d83318fde493
Carrier set: 4d4254b591ede243b38df7b678cf36619cb25825
Minimum fix set: 48ba4ece3c1b43cb4b9627438c0ff4e4251e3511, f267a28cb2badc7e712c4592af4d79d090fe5063
Source packets: autoresearch/herdr-260814-cf3-nextqueue-grok46-medium, autoresearch/herdr-260814-ghsa200-nearpass-twogate12-grok46-medium, autoresearch/herdr-260814-nearclosed-g-grok46-low
Why hostile review: Newest terminal NARROW leaves but_for_gate and closable fix_reversal_gate. Carrier 4d4254b5 is not the candidate. Hostile review should test material delta versus the Coolify advisory closer without inheriting nearclosed PASS labels.

## Leftover eligible 144

Not queued. Includes one-gate but_for NARROW rows, empty-gate UNKNOWN routing packets, and other NARROW/UNKNOWN identities without a newer FAIL. They remain eligible for a later queue and are not counted here.

This inventory does not call a PASS. This inventory does not infer causality.
