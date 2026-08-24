# Recover fix_object_missing ranks 25-32

REJECT 8. PASS=0. packet_delta=0. Worker PASS is proposal-only; this packet emits none.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.

## Reconstruction

Authoritative prior reconstruction herdr-260814-recover-fix-missing-ranks17-24-grok46-low result SHA256 04206ea707bec13f0ec351dc34d95f97b43ec5ce9bf969c71226506f351886e8.
Source packet herdr-260814-nextqueue-v2-grok46-low result SHA256 0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1 replay SHA256 6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed.
Frozen advisory HEAD f2c6ab3202aeafb36fbea6e76d892532acfca1a6 tree 3308b2f6c73929d3854bd12908e996787a8bb0c8.
fix_object_missing count 38, matching the pinned source bucket. Did not invent rows.

Subtracted canonical94 strict 94. Overlap with that set was empty, so 38 remained.
Deterministic sort is uppercase GHSA ID. Ranks 1-8, 9-16, and 17-24 are owned by other workers and were not frozen here. This worker froze ranks 25-32 only. Disjointness: intersection of ranks 1-24 and 25-32 is empty. Did not inherit sibling verdicts.

## Frozen ranks 25-32

25. GHSA-HJ5C-MHH2-G7JQ go-vikunja/vikunja REJECT ai_hunk FAIL
26. GHSA-J99G-7RQW-Q9JG nimiq/core-rs-albatross REJECT ai_hunk FAIL
27. GHSA-MW3Q-R9WH-H2FF nimiq/core-rs-albatross REJECT ai_hunk FAIL
28. GHSA-PF4J-PF3W-95F9 nimiq/core-rs-albatross REJECT ai_hunk FAIL
29. GHSA-PM4M-PH32-GHV5 nodeca/js-yaml REJECT ai_hunk FAIL
30. GHSA-PPPJ-HQ3G-57PJ jupyterlab/jupyterlab REJECT ai_hunk FAIL
31. GHSA-Q49M-57VM-C8CC kata-containers/kata-containers REJECT ai_hunk FAIL topology FAIL
32. GHSA-QRPW-GJVH-X5GM nautobot/nautobot REJECT ai_hunk FAIL

Temporary public clones recovered the advisory fix objects anonymously with credential helpers disabled. Those objects are routing. Closers have no source_matcher hit. Pre-fix 80-commit matcher scans on fix-touched code files found no AI marker. Routing, recovered SHA, same repo, shared SHA, AI-on-fix, carrier trailer transfer, old-bug preservation, sibling fields, and hardening are not proof.
Rank 31 closer 1b9e49eb is a two-parent merge, so topology_gate is FAIL. Release artifacts were not hashed; release_gate is UNKNOWN. All seven exact PASS are mandatory, so none is countable. Prefer zero PASS over one false positive.

## Conservation

assigned 8 = reviewed 8 + unreviewed 0. Equation 8=8+0. Holds. Did not pad.
PASS_PROPOSAL 0. countable_pass 0.
Temp clones were deleted after evidence capture.

Stop. No ledger, site, or other-directory edits. No commit or push.
