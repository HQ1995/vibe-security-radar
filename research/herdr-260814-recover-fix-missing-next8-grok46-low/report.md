# Recover fix_object_missing ranks 9-16

REJECT 8. PASS=0. packet_delta=0. Worker PASS is proposal-only; this packet emits none.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.

## Reconstruction

Source packet herdr-260814-nextqueue-v2-grok46-low result SHA256 0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1 replay SHA256 6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed.
Frozen advisory HEAD f2c6ab3202aeafb36fbea6e76d892532acfca1a6 tree 3308b2f6c73929d3854bd12908e996787a8bb0c8.
Recomputed github-reviewed identities 34389. Exclusive filters: withdrawn, canonical91, terminal_verdict (mtime cutoff at source packet), no_repository, no_same_repo_fix, published before 2025-05-01, no first-party repo-advisory URL, then local-clone probe.
fix_object_missing count 38, matching the pinned source bucket. Did not invent rows.

Subtracted canonical94 strict 94, nextqueue queued 20 plus leftover 11, and identities with a current non-routing terminal verdict. Overlap with those sets was empty, so 38 remained.
Deterministic sort is uppercase GHSA ID. Ranks 1-8 are owned by the xhigh sibling and were not frozen here. This worker froze ranks 9-16 only. Disjointness: intersection of ranks 1-8 and 9-16 is empty.

## Frozen ranks 9-16

09. GHSA-48M6-486P-9J8P nimiq/core-rs-albatross REJECT ai_hunk FAIL
10. GHSA-5RG2-XV9J-GV5P nimiq/core-rs-albatross REJECT ai_hunk FAIL
11. GHSA-6973-8887-87FF nimiq/core-rs-albatross REJECT ai_hunk FAIL
12. GHSA-6G2V-66CH-6XMH librenms/librenms REJECT ai_hunk FAIL
13. GHSA-799F-29JM-GR6C nimiq/core-rs-albatross REJECT ai_hunk FAIL
14. GHSA-7C4J-2M43-2MGH nimiq/core-rs-albatross REJECT ai_hunk FAIL
15. GHSA-7WVC-RVP7-W99X go-gitea/gitea REJECT ai_hunk FAIL
16. GHSA-89VP-JRXV-24W8 jupyterlab/jupyterlab REJECT ai_hunk FAIL

Temporary public clones recovered the advisory fix objects. Those objects are routing. Closers are single-parent human commits with no source_matcher hit. Pre-fix 80-commit grep on fix-touched code files found no AI marker. Routing, recovered SHA, same repo, shared SHA, AI-on-fix, carrier trailer transfer, old-bug preservation, sibling fields, and hardening are not proof.
Release artifacts were not hashed; release_gate is UNKNOWN. All seven exact PASS are mandatory, so none is countable. Prefer zero PASS over one false positive.

## Conservation

assigned 8 = reviewed 8 + unreviewed 0. Equation 8=8+0. Holds. Did not pad.
PASS_PROPOSAL 0. countable_pass 0.
Temp clones and pages were deleted after evidence capture.

Stop. No ledger, site, or other-directory edits. No commit or push.
