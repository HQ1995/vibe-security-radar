# Recover fix_object_missing ranks 17-24

REJECT 8. PASS=0. packet_delta=0. Worker PASS is proposal-only; this packet emits none.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.

## Reconstruction

Source packet herdr-260814-nextqueue-v2-grok46-low result SHA256 0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1 replay SHA256 6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed.
Frozen advisory HEAD f2c6ab3202aeafb36fbea6e76d892532acfca1a6 tree 3308b2f6c73929d3854bd12908e996787a8bb0c8.
Recomputed github-reviewed identities 34389. Exclusive filters: withdrawn, canonical91, terminal_verdict (mtime cutoff at source packet), no_repository, no_same_repo_fix, published before 2025-05-01, no first-party repo-advisory URL, then local-clone probe.
fix_object_missing count 38, matching the pinned source bucket. Did not invent rows.

Subtracted canonical94 strict 94, nextqueue queued 20 plus leftover 11, and identities with a current non-routing terminal verdict. Overlap with those sets was empty, so 38 remained.
Deterministic sort is uppercase GHSA ID. Ranks 1-8 and 9-16 are owned by other workers and were not frozen here. This worker froze ranks 17-24 only. Disjointness: intersection of ranks 1-16 and 17-24 is empty. Did not inherit sibling verdicts.

## Frozen ranks 17-24

17. GHSA-96Q5-XM3P-7M84 go-vikunja/vikunja REJECT ai_hunk FAIL
18. GHSA-9GCG-W975-3RJH istio/istio REJECT ai_hunk FAIL
19. GHSA-C3M2-JQMQ-PVP3 goauthentik/authentik REJECT ai_hunk FAIL
20. GHSA-FG23-3346-88F5 langroid/langroid REJECT ai_hunk FAIL
21. GHSA-FGFV-PV97-6CMJ go-vikunja/vikunja REJECT ai_hunk FAIL
22. GHSA-GX64-GJ6P-PC4C jupyterlab/jupyterlab REJECT ai_hunk FAIL
23. GHSA-H5V5-8746-G7MM jupyterlab/jupyterlab REJECT ai_hunk FAIL
24. GHSA-H9CC-W26M-J342 nimiq/core-rs-albatross REJECT ai_hunk FAIL

Temporary public clones recovered the advisory fix objects anonymously with credential helpers disabled. Those objects are routing. Closers are single-parent commits with no source_matcher hit. Pre-fix 80-commit matcher scans on fix-touched code files found no AI marker. Routing, recovered SHA, same repo, shared SHA, AI-on-fix, carrier trailer transfer, old-bug preservation, sibling fields, and hardening are not proof.
Vikunja rows 17 and 21 reference test-only closers, so fix_reversal_gate is FAIL. Release artifacts were not hashed; release_gate is UNKNOWN. All seven exact PASS are mandatory, so none is countable. Prefer zero PASS over one false positive.

## Conservation

assigned 8 = reviewed 8 + unreviewed 0. Equation 8=8+0. Holds. Did not pad.
PASS_PROPOSAL 0. countable_pass 0.
Temp clones and pages were deleted after evidence capture.

Stop. No ledger, site, or other-directory edits. No commit or push.
