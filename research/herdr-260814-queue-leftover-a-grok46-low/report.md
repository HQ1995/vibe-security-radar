# Queue leftover-a audit (five leftover_ids)

Terminal: 5=5+0 reviewed. PASS=0. Canonical93 stays 93 HOLD. Worker PASS is proposal-only and this packet emits none. Greater-than-200 remains unsupported.

## Freeze

Source packet `autoresearch/herdr-260814-nextqueue-v2-grok46-low` result sha256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` leftover_ids prefix exactly GHSA-R54C-2XMF-2CF3, GHSA-V5MV-P594-2X33, GHSA-V95X-XHQ5-4929, GHSA-WVMP-6R4V-J6CV, GHSA-375F-4R2H-F99J. Those five are not in queued_ids or assignment.jsonl. Did not audit the remaining six leftover_ids. assignment sha256 `5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3` cases sha256 `5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf`.
CONTRACT.md sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical93 ledger sha256 `6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d`.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` committer 2026-08-14T03:33:36+00:00 (read-only cache). Shared caches were not mutated. No temporary clone retained. Matcher `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.

Assigned exactly the five leftover prefix IDs. All five absent from canonical93 strict IDs. Routing, same-repo fix, shared SHA, AI-on-fix, carrier trailer transfer, old-bug preservation, sibling fields, and incomplete hardening that only reduces risk are not causal proof. NA/NARROW/UNKNOWN/BLOCKED is not PASS.

## Verdicts

### GHSA-R54C-2XMF-2CF3 REJECT

Identity PASS: first-party GHSA-r54c-2xmf-2cf3, repo modelscope/ms-swift, CWE-502, PyPI ms-swift. Advisory sha256 `b157a1e6c92b7ae10a1b58d1b1a10b0fae67fa7223939361756aedc67058f27a`.
Mechanism: `torch.load` of adapter `WEIGHTS_NAME` in `swift/tuners/base.py`.
Fix `cc47463bcd25a8720437cf945130f43052eec5e4` parent `1314d4966c2d7f287008925b87aed4a2df1885e1` raises NotImplementedError. Parent blob `fafc0883abce55d975055352ade4d9f5b3cbdd58`, fixed blob `cd909abbc9290976a52652d9b588946b551c5476`.
Blame `510b623756d067331bbe36590c213cb20ac33f69` Jintao 2024-01-23, no AI marker.
Gemini candidate `95ee4d63a4c16408518770a9a9e80398b6d87935` is GRPO entropy mask. ai_hunk FAIL, but_for FAIL.
Tag `v3.6.3` peeled `340bf41a26b00de7957bcb7a9275c5babf695a21` has the parent blob with torch.load. Tag `v3.7.0` peeled `eefc8432d4ef26007652c51270e868e5e282f853` contains the NotImplementedError. release PASS. uniqueness PASS.

### GHSA-V5MV-P594-2X33 REJECT

Identity PASS: first-party GHSA-v5mv-p594-2x33. Advisory sha256 `5f1c94f91c26a2aa0437ad2ac6ee1dd3f3ec67bb23d63bc9376eebacc26dcb2c`.
Mechanism: noncanonical URI host vs transport authority / Host header.
Closers `3aeea0406aab88cbbd86531313d7cebf8ae149a4` and `744101956d78b7c1384d0cbf379db13e859167bf` add HostValidator blobs `8a2414fa805928ef97be524b14c464b8fbcdcac3` and `bf8cc3d315478c375d88687785a90baa99e3044f`.
AI candidate `fb92d95f80a9da51bf8f2a5b26d8e8ea3b6d99ed` is CI/PHPStan; HostValidator is absent there. Sibling cookie Domain (GHSA-F7VP) is a different mechanism; shared closer SHA is not proof. ai_hunk FAIL. Local clone has no 7.15.2/8.0.1 tags. release UNKNOWN.

### GHSA-V95X-XHQ5-4929 REJECT

Identity PASS: first-party GHSA-v95x-xhq5-4929 kumactl TLS. Advisory sha256 `e64a566549e81ccd3f3a0f3688520998b865251b0c0f5f0aacc52742ffd34add`.
Closer `2ecadac1aa2fd8cded4c2ab768949f4c2ec83e2a` parent `7aaf172cf61e3b1fff312a9167a8f9f0747c228e` stops default InsecureSkipVerify in `pkg/util/http/tls.go` (parent blob `5ed50a6ca64225d58b9948ff5cc14b9d8ca48fd8`, fixed `6b7404714566e703bb1d045a5bb39bf640730528`).
Copilot `efb80db2ce4fe8b44feb71b7709c3f992bf00742` is protobuf/CI formatting. ai_hunk FAIL. No advisory tags in the local clone. release UNKNOWN. uniqueness PASS vs canonical93 and vs GHSA-WVMP (different client).

### GHSA-WVMP-6R4V-J6CV REJECT

Identity PASS: first-party GHSA-wvmp-6r4v-j6cv kuma-dp TLS. Advisory sha256 `255038d5481021ba1f6f64978469f25d59ff60c37ec3a0e9a0de2228e96bbea3`.
Same closer; `remote_bootstrap.go` parent blob `50a1a6cb8e2bd2ab694f827daf0e4ef7bbbbea35`, fixed `f67880d6b550659503e7deab324166701025f817`.
Same Copilot candidate does not touch that file. Shared SHA with GHSA-V95X is not dedupe. ai_hunk FAIL. release UNKNOWN.

### GHSA-375F-4R2H-F99J REJECT

Identity PASS: first-party GHSA-375f-4r2h-f99j. Advisory sha256 `cacc2db628a090e5c240f3becc8e143072bda02760060f7b5a4691a5647425cf`.
Mechanism: `determine_scheme` trusts client URI scheme. Origin `ff2f829326cd5dcf7335939aef9775269d881e28` 2023-06-08 Mat Trudel.
Closer `45feea20dea8af7ffd7245271107b695c040e667` single parent `f2ca636eb6df385219957e8934e9fc6efa1630d1`; pipeline blobs `079352afc19ee8eee9335136aa34b3d0819e865b` -> `06aaa47d13b0c86b4aba3e896c273bf3f230f96f`.
Claude `a330b13588f874fee170e508f75c6ee5037737d9` only `.github/workflows/elixir.yml`. Inherited old bug. ai_hunk FAIL. No v1.11.0 tag locally. release UNKNOWN.

## Conservation

assigned 5 = reviewed 5 + unreviewed 0. Equation 5=5+0. Holds. Did not pad. PASS_PROPOSAL=0. Canonical93 untouched.

Stop. No ledger, site, scripts, or other-packet edits. No credentials. No GitHub API.
