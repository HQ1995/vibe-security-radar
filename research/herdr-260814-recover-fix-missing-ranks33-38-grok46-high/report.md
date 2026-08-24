# Recover fix_object_missing ranks 33-38

REJECT 6. PASS=0. packet_delta=0. Worker PASS is proposal-only; this packet emits none.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.

## Reconstruction

Authoritative prior reconstruction herdr-260814-recover-fix-missing-ranks17-24-grok46-low result SHA256 04206ea707bec13f0ec351dc34d95f97b43ec5ce9bf969c71226506f351886e8.
Source packet herdr-260814-nextqueue-v2-grok46-low result SHA256 0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1 replay SHA256 6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed.
Frozen advisory HEAD f2c6ab3202aeafb36fbea6e76d892532acfca1a6 tree 3308b2f6c73929d3854bd12908e996787a8bb0c8.
fix_object_missing count 38, matching the pinned source bucket. Did not invent rows.

Subtracted canonical94 strict 94. Overlap with that set was empty, so 38 remained.
Deterministic sort is uppercase GHSA ID. Ranks 1-8, 9-16, 17-24, and 25-32 are owned by other workers and were not frozen here. This worker froze ranks 33-38 only. Disjointness: intersection of ranks 1-32 and 33-38 is empty. Did not inherit sibling verdicts.

## Frozen ranks 33-38

33. GHSA-R292-9MHP-454M isaacs/node-tar REJECT ai_hunk FAIL
34. GHSA-V3R7-H72X-CJCM nodejs/undici REJECT ai_hunk FAIL
35. GHSA-V479-VF79-MG83 go-vikunja/vikunja REJECT ai_hunk FAIL
36. GHSA-VC34-39Q2-M6Q3 nimiq/core-rs-albatross REJECT ai_hunk FAIL
37. GHSA-VGHX-352F-93JM nimiq/core-rs-albatross REJECT ai_hunk FAIL
38. GHSA-WHVH-WF3X-G77J jupyterlab/jupyterlab REJECT ai_hunk FAIL

Temporary public clones recovered the advisory fix objects anonymously with credential helpers disabled. Those objects are routing. Closers are single-parent commits with no source_matcher hit. Pre-fix 80-commit matcher scans on fix-touched code files found no AI marker. Routing, recovered SHA, same repo, shared SHA, AI-on-fix, carrier trailer transfer, old-bug preservation, sibling fields, and hardening are not proof.
Rank 35 closer 6a0f39b252a8 amends CanDoAPIRoute, unlike test-only sibling Vikunja rows; that does not transfer a PASS. Rank 38 Co-authored-by Anuj Kumar Singh is not a source_matcher identity. First-party git tags were hashed at blob level. No AI contribution exists to contain, so release_gate is FAIL. All seven exact PASS are mandatory, so none is countable. Prefer zero PASS over one false positive.

## Conservation

assigned 6 = reviewed 6 + unreviewed 0. Equation 6=6+0. Holds. Did not pad.
PASS_PROPOSAL 0. countable_pass 0.
Temp clones were deleted after evidence capture.

Stop. No ledger, site, or other-directory edits. No commit or push.
