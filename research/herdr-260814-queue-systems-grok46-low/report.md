# Queue systems audit (five identities)

Terminal: 5=5+0 reviewed. PASS=0. Canonical93 stays 93 HOLD. Worker PASS is proposal-only and this packet emits none. Greater-than-200 remains unsupported.

## Freeze

Source packet `autoresearch/herdr-260814-nextqueue-v2-grok46-low` assignment sha256 `5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3` cases sha256 `5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf`.
CONTRACT.md sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical93 ledger sha256 `6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d`.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` committer 2026-08-14T03:33:36+00:00 (read-only cache). Shared caches were not mutated. No temporary clone retained.

Assigned exactly: GHSA-G6W2-Q45F-XRP4, GHSA-WWJ6-VGHV-5P64, GHSA-X744-4WPC-V9H2, GHSA-F7VP-7XGX-4W4R, GHSA-HRXH-6V49-42GF. All five absent from canonical93 strict IDs. Routing, shared SHA, trailer on a squash/merge carrier, AI-on-fix, inherited old bugs, sibling fields, incomplete hardening, and a fix in the same repo are not causal proof.

## Verdicts

### GHSA-G6W2-Q45F-XRP4 REJECT

Identity PASS: first-party GHSA-g6w2-q45f-xrp4, repo NeoRazorX/facturascripts, CWE-79, packagist facturascripts/facturascripts. Advisory sha256 `ed04984c14992e1e09d02df02907d5991176b3b40b211937ebcd39ccd73938fe`.
Mechanism: Twig `| raw` on MiniLog SQL error text in `Core/View/Macro/Utils.html.twig`.
Fix `2afd98cecd26c5f8357e0e321d86063ad1012fc3` removes `| raw`. Parent blob `b7bea7d3f2e2575703c1705cf999eace0fa68a8d`, fixed blob `32b0b937f3c44005919ba6205d7d5de22a1222f4`.
Blame of the vulnerable lines is `232e7776d2a99bebd1a90b5023f2346139b19fc8` Carlos Garcia 2022-02-24, no AI marker.
Eight pre-fix AI candidates do not touch that file. Inherited old bug. ai_hunk FAIL, but_for FAIL. Tag `v2025.8` peeled `a6e8e0595da4cf176afa71d3635fc163ebf97670` contains the fix, but the ecosystem event says `2025.81` without a hashed packagist archive here, so release NARROW not PASS.

### GHSA-WWJ6-VGHV-5P64 REJECT

Identity PASS: first-party GHSA-wwj6-vghv-5p64. Advisory sha256 `162f1c047d5441c8457bf7a6c0b12f5811554e3e6161e8c4a88ff031b71daa6d`.
Mechanism: writable virtio-pmem DAX root (`/dev/pmem0`) so a container with CAP_MKNOD can mutate the guest image.
Closer `6a672503973bf7c687053e459bfff8a9652e16bf` is merge-from-fork disabling Cloud Hypervisor pmem (parents `88203cbf8dee04f25bef22a2c53b0795f81cf8a5` `336b922d4f7fe5dc94087de2af3992a1a786d0d9`). Authorship is not transferred across the merge.
AI candidates are infra, tests, GPU/qemu packaging. None author the pmem path. ai_hunk FAIL. Tag `3.27.0` peeled `855f4dc7fac1a4822938212f447413d2a9416bd1` contains the merge; Go pseudo-version zip is not hashed here, release NARROW.

### GHSA-X744-4WPC-V9H2 REJECT

Identity PASS: first-party GHSA-x744-4wpc-v9h2, incomplete fix of GHSA-v23v-6jw2-98fq. Advisory sha256 `cc88107a4e0cecba2dc3646f87f43a26e7320593d16654f9e5f359f910b13bb8`.
Mechanism: AuthZ plugin sees empty body on oversized requests.
Closer merge `e89edb19ad7de0407a5d31e3111cb01aa10b5a38` rewrites `pkg/authorization/authz.go` blob `b635e0173366bce3a2a56d753a1e5bac887cc5c6`. Tag `docker-v29.3.1` object `34ddcab43729d02fc486ceea8f01e0effd8bd4ec` has the same blob but the merge SHA is not an ancestor of the tag, so release NARROW.
AI candidates are client docs and API refactors. Incomplete-remediation would require an AI-authored authz body-size boundary; that is absent. ai_hunk FAIL. Sibling/AI-on-unrelated is not PASS.

### GHSA-F7VP-7XGX-4W4R REJECT

Identity PASS: first-party GHSA-f7vp-7xgx-4w4r residual of GHSA-g446-98w2-8p5w. Advisory sha256 `e27db185e104ecefa52ac29e416e07b3ee48d140bc709639a5eb5ff3743c0664`.
Mechanism: `SetCookie::matchesDomain` still grants subdomain scope to hex/mixed-base and percent-escaped Domain spellings.
Closers `3aeea0406aab88cbbd86531313d7cebf8ae149a4` and `744101956d78b7c1384d0cbf379db13e859167bf`.
Sole AI candidate `fb92d95f80a9da51bf8f2a5b26d8e8ea3b6d99ed` is CI/PHPStan/Psalm; CookieJar change is instanceof punctuation. Not the Domain matcher. ai_hunk FAIL. Local clone has no 7.15.2/8.0.1 tags. release UNKNOWN.

### GHSA-HRXH-6V49-42GF REJECT

Identity PASS: first-party GHSA-hrxh-6v49-42gf. Advisory sha256 `854802206785e00bd7bd6cf355050ea7822ee2d14e0e56fd21f044073fb2d7a3`.
Mechanism: xDS RBAC Metadata/RequestedServerName fail-open; HTTP/2 Rapid Reset control-buffer accounting; NOT-rule panic on unsupported fields.
Closer `4ea465d4ab98013f72a142fe0fc89c19770b2935` (#9236).
AI candidate `57c9ff14e05b535ee6995ba49bc882b287a175de` has a gemini-code-assist trailer on a human-authored SafeRegex full-string fix of a different RBAC regression. Same `matchers.go` file is sibling fields, not residual of that regex boundary. Trailer is not AI hunk of this advisory. Local clone has no v1.82.1 tag. release UNKNOWN. ai_hunk FAIL.

## Conservation

assigned 5 = reviewed 5 + unreviewed 0. Equation 5=5+0. Holds. Did not pad. PASS_PROPOSAL=0. Canonical93 untouched.

Stop. No ledger, site, scripts, or other-packet edits. No credentials. No GitHub API.
