# Hostile review: GHSA-8G98-M4J9-QWW5, GHSA-VH5J-5FHQ-9XWG, GHSA-G8MR-85JM-7XHM

**NARROW all three.** Countable PASS remains 0. Packet delta 0. Canonical94 stays **94 HOLD**.

Independent hostile seven-gate replay of three conflicted near-pass rows. Prior PASS_PROPOSAL/NARROW/UNKNOWN packets are routing only and are not proof. Worker PASS is proposal only; this packet emits none. Exact seven PASS is required for PASS_PROPOSAL. OSV introduced is not causality. A tag or version string is not an artifact.

Conservation: assigned=3, reviewed=3, unreviewed=0. Equation `3=3+0`.

Network evidence used anonymous public git, GitHub HTML, advisory-database JSON, and npm/codeload tarballs only after a clean process environment. Credential-bearing variables are unset and never printed. Anonymous failure is BLOCKED; credentials are not used as a fallback.

## 1. GHSA-8G98-M4J9-QWW5 NARROW

tailot/taylored. Hypothesized candidate `c139c021f68a09d22c2af88641b61c00f67f2af4`, empty carrier, closer `57b7634391959dbbdb39b387ac4dc68157cd58a1`.

### Identity

Published repository advisory GHSA-8g98-m4j9-qww5 names tailot/taylored and npm package taylored. Repo HTML affected 7.0.5, patched 7.0.8. github-reviewed JSON: CWE-22, CWE-294, CWE-345, CWE-916; range introduced 7.0.5 fixed 7.0.8; no aliases; withdrawn null. Global catalog HTTP 200. Body text also says the issues sit in 7.0.7 and that versions prior to 7.0.7 lacked Taysell. Git contradicts that sentence. Identity still names a first-party GHSA, repo, package, and mechanism. Normalized identity SHA256 `f4fedb15f8a2111c0cea29d6395ded0a6cd1fe485323445869adbac9ad7e6d5b`.

identity_gate: PASS.

### Topology and AI hunk

`c139c021` is single-parent onto `610281a664bd4e8c8d0c7052116bedaea5c8a4c6`. Author google-labs-jules[bot]. Subject 7.0.5. Empty body. Parent package.json 6.8.21 has no backend-in-a-box. Candidate adds templates/backend-in-a-box/index.js blob `0dd0853c` with unsanitized patchId joins, unverified webhook JSON, no token_used_at, PBKDF2 100000. package.json at the candidate is 7.0.6.

Closer `57b76343` is a direct child, also Jules-authored. Human `5e5a80b5` (subject 7.0.8, package.json 7.0.9) is a later single-parent rewrite, not a merge. carrier_set empty. Do not transfer.

ai_hunk_gate: PASS. topology_gate: PASS.

### But-for and fix reversal

Removing the candidate eliminates the Taysell template. but_for_gate: PASS.

`57b76343` adds webhook verification, token_used_at SELECT-then-UPDATE, and PBKDF2 310000. It does not add path.basename. CWE-22 remains on blob `8a5317f9`. Advisory item 1 (path traversal) and patched version 7.0.8 land on human `5e5a80b5`, not on the hypothesized closer. Incomplete reversal of the advisory bundle.

fix_reversal_gate: NARROW.

### Release

Package ecosystem npm / name taylored. git ls-remote tags: only `8.2.4` peel `05da9137527cb7be236bb8e63f1c3b0dffcc6b2a`. GitHub Releases: "There aren't any releases here". pypi and crates.io HTTP 404.

npm packument time lists 7.0.5, 7.0.6, 7.0.7, 7.0.8 historically. Live `registry.npmjs.org/taylored/7.0.5` through `7.0.8` and matching tarballs are HTTP 404. jsdelivr/unpkg 7.0.5 HTTP 404. A packument timestamp is not an immutable tarball.

Only retrievable artifact: taylored@8.2.4 tarball sha256 `932bd516fdc4e42ba349cd5c2fd3937021bb0a731eb593262d1807df811ef9ec`, shasum `81a6dec8a56a47698872ebe77df3e78d80631aa6`. dist/templates/backend-in-a-box/index.js git blob `706a6e1d` equals tag 8.2.4 and contains path.basename, PAYPAL_WEBHOOK_ID, PBKDF2 310000, and atomic `token_used_at IS NULL`. Candidate and closer are both ancestors of 8.2.4. Same-first-tag. No vulnerable artifact contains the candidate without a complete later closer.

release_gate: NARROW.

### Uniqueness

Absent from canonical94 strict 94. Distinct from GHSA-VH5J. Shared SHA 57b76343 is not duplication.

uniqueness_gate: PASS.

## 2. GHSA-VH5J-5FHQ-9XWG NARROW

Same repo. Hypothesized candidate `57b7634391959dbbdb39b387ac4dc68157cd58a1`, hypothesized carrier `5e5a80b5ffd0b6fccf7bdc2d8793e8b01cb83844`, closer `fdf67a6fba0deae30912905a79fb5a9e83751a79`.

### Identity

Published GHSA-vh5j-5fhq-9xwg. CWE-362 race on /get-patch. Repo HTML affected 8.1.2, patched 8.1.3. github-reviewed package npm taylored, last known `<= 8.1.2`, fixed 8.1.3. No aliases. Not withdrawn. Repo HTML package label shows the template path; advisory-database name remains taylored. Normalized identity SHA256 `09de4af70be2e8832a22d07a3a7fca661eed55966e728d4236b17784278ab198`.

identity_gate: PASS.

### Topology and AI hunk

`57b76343` is Jules-authored, parent `c139c021`, and introduces token_used_at with SELECT-then-UPDATE. `5e5a80b5` is human, n_parents=1, not a merge. carrier_set empty. Closer `fdf67a6f` author vincenzo, parent `f4d21045` (package.json 8.1.2) to 8.1.3.

ai_hunk_gate: PASS. topology_gate: PASS.

### But-for and fix reversal

AI_INCOMPLETE_REMEDIATION patch-delta: the candidate is an explicit token-invalidation guard; GHSA-vh5j covers the residual two-statement race; `fdf67a6f` amends the same endpoint to `UPDATE ... AND token_used_at IS NULL`. Parent blob `5356a651` still has the advisory SELECT/UPDATE pair. Residual is not a sibling path. Rollback to unlimited replay is not a failure for this class.

but_for_gate: PASS. fix_reversal_gate: PASS.

### Release

npm 8.1.2 and 8.1.3 HTTP 404. Same git tag set as case 1: only 8.2.4, which already contains the atomic closer (ancestor of peel `05da9137` and of npm gitHead `9b3bb75b`). Same-first-tag. Countable incomplete rem also requires a released artifact with the attempted guard and without the final closure. That artifact is unpublished.

release_gate: NARROW.

### Uniqueness

Absent from canonical94 strict 94. Distinct mechanism from GHSA-8G98. Shared SHA is not duplication.

uniqueness_gate: PASS.

## 3. GHSA-G8MR-85JM-7XHM NARROW

vitest-dev/vitest. Alias CVE-2026-53633. Hypothesized candidate `af88b1f5d82844a4761ea9a977156c98e2b14ca8`, empty carrier, closer `385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7`.

### Identity

Published GHSA-g8mr-85jm-7xhm. Title: Exposed Browser Mode API Can Proxy CDP and Overwrite Config Files, Leading to RCE. CWE-749, CWE-862. npm `@vitest/browser` ranges `>=3.0.0,<=3.2.4` patched 3.2.5; `>=4.0.0,<=4.1.7` patched 4.1.8; `>=5.0.0-beta.0,<=5.0.0-beta.3` patched 5.0.0-beta.4. npm vite-plus `<=0.1.23` patched 0.1.24. Not withdrawn. CVE is an alias, not a second case. vite-plus is enumerated as advisory-named; this pairing is not mapped into vite-plus. Normalized identity SHA256 `68b456ebbcb07bafe0e82a7589c0a73cce8e43d648a0fea1119a4fe3f9f016e4`.

identity_gate: PASS.

### Topology and AI hunk

`af88b1f5` is a v3 backport (#10445), Co-authored-by Codex. Parent `5a7d56e2`. Closer `385a1aef` is its direct child (#10456), also Codex-marked. n_parents=1 both. Empty carrier. Do not transfer v4 closer `e4067b3b` or v5 closer `63e3b2ee`.

Parent and v3.2.4 rpc.ts blob `7619c5f0` already have ungated `sendCdpEvent`. Candidate rpc.ts blob `358ac355` adds `canWrite` on snapshot write/remove and does not edit CDP. The advisory hunk is not the AI hunk.

ai_hunk_gate: NARROW. topology_gate: PASS.

### But-for and fix reversal

Removing the candidate leaves ungated CDP. CDP is an untouched sibling of the new fs guard and is already in last-affected 3.2.4. Incomplete-remediation sibling/old-hole rule fails.

but_for_gate: NARROW.

Closer `385a1aef` adds `assertCdpAllowed` on sendCdpEvent/trackCdpEvent. v3.2.5 rpc.ts blob `72818584` equals that closer. The closer reverses the CDP invariant on this branch. AI-on-fix is not origin.

fix_reversal_gate: PASS.

### Release

GitHub Releases v3.2.4 and v3.2.5 exist (`released this`). Annotated tags peel to `c666d149a4516761bae92ca56ce1336d2fd352c3` and `2cbad0a923c48c6144266df3cd25f93547cb5221`.

npm `@vitest/browser@3.2.4` tarball sha256 `a24c6adef75dbebadbadbb1eef2723ad5dd44e4c3509e4c46370310646cb5f38`, shasum `4238600dc8343b8a9c032266c743f7d38ae3da84`. dist/index.js git blob `3ca37317` has sendCdpEvent, no canWrite, no assertCdpAllowed. Candidate is not an ancestor of v3.2.4.

npm `@vitest/browser@3.2.5` tarball sha256 `0f4e1678d753e9f0cd70d0f29326561dafcb1242156b8010fa83c914fb19120b`, shasum `e49cbf823c8eb4f4cdd46642f21d5216d428d679`. dist/index.js git blob `e1ef861c` has sendCdpEvent, canWrite, and assertCdpAllowed. Candidate and closer are both ancestors of v3.2.5. Same-first-tag.

v4.1.7/4.1.8 and v5.0.0-beta.3/beta.4 npm tarballs and GitHub Releases exist. 4.1.7 and beta.3 have canWrite without assertCdpAllowed, but they do not contain hypothesized candidate `af88b1f5`. Those lines use other closer SHAs. Do not transfer.

release_gate: NARROW.

### Uniqueness

Absent from canonical94 strict 94. CVE alias is not a second case.

uniqueness_gate: PASS.

## Claim boundary

No row has seven exact PASS. No PASS_PROPOSAL. Canonical94 is untouched. Publication and more-than-200 stay HOLD.
