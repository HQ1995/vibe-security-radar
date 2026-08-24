# Hostile red-team: GHSA-425G-FJHQ-5H92

**KEEP proposal.** Packet delta 0. Current leader-accepted count remains 82.

This is an independent hostile review of the residual-security20 proposal that GHSA-425G is AI incomplete remediation at candidate `a3d7f417`, parent `c9c932af`, fix `6e7f938d`, PyPI openssl-encrypt 1.3.5 / 1.4.0. Worker PASS is proposal only. This packet does not admit the row, does not rebuild canonical82, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0.

## Hostile checks that did not falsify

GitHub associated-pulls for `a3d7f417`, `6ad5d5ca`, and `6e7f938d` are empty. The candidate is not a GitHub squash of mixed human and AI members.

`a3d7f417` has one parent, `c9c932af`. That parent lacks `openssl_encrypt/modules/json_validator.py`. The candidate adds the file as a "secure JSON validator module" with Claude Code and Co-Authored-By: Claude trailers. The new file wraps `jsonschema` in ImportError and, in `validate_against_schema`, prints a warning and returns when `JSONSCHEMA_AVAILABLE` is false.

Leader topology correction: `candidate_set` stays `[a3d7f417...]`. `a3d7f417` is an any-parent ancestor of the closer and is not on the fix first-parent. `carrier_set` is `[bb8915d2673d448b7b89ef484d7fef464f9c6684]`, the AI-marked first-parent landing merge. Duplicate atomic `6ad5d5ca` is that merge's second parent and is lineage evidence only, not a separately counted candidate. Earlier same-blob `f5e9c309` is also not counted. Default blame at the fix parent names `a3d7f417`. First-parent blame names the merge. This is not a human-member transfer. Topology stays PASS.

The GHSA quotes that fail-open return as the affected code. Rolling the validator away restores the older no-schema-validation behavior. Under `AI_INCOMPLETE_REMEDIATION` that broader reopen is not a failure. The counted residual is the incomplete guard, not the pre-validator hole.

PyPI 1.3.5 wheel `c8d7a129...` and sdist `3a8d8c29...` are not yanked. Both carry the fail-open print/return and lack the raise. Wheel METADATA has no `Requires-Dist: jsonschema`. The missing-library branch is the default install, not a dead mandatory-dependency path.

Closer `6e7f938d` rewrites that exact branch to `raise JSONValidationError(...)`. PyPI 1.4.0 wheel `6f819ae6...` and sdist `77a024c1...` are not yanked. `json_validator.py` is byte-identical to `git show 6e7f938d:openssl_encrypt/modules/json_validator.py`. 1.4.0 METADATA requires `jsonschema==4.25.1`.

Identity is github-reviewed GHSA-425g-fjhq-5h92, not withdrawn, no CVE alias, package openssl-encrypt, fixed 1.4.0. The identity is absent from canonical82 strict 82.

## Gates

1. `identity_gate`: PASS. Reviewed first-party GHSA on jahlives/openssl_encrypt. PyPI openssl-encrypt, range introduced 0, fixed 1.4.0.

2. `ai_hunk_gate`: PASS. Atomic `a3d7f417` authors the fail-open hunk with an explicit Claude marker. No unmarked human member.

3. `topology_gate`: PASS. Candidate is an any-parent ancestor of the closer and is not on the fix first-parent. Parent lacks the file. Carrier is AI-marked first-parent landing merge `bb8915d2673d448b7b89ef484d7fef464f9c6684`. Duplicate atomic `6ad5d5ca` is lineage evidence, not a separately counted candidate.

4. `but_for_gate` / `remediation_patch_delta_gate`: PASS. The AI change is an explicit schema-validation security attempt. A released artifact contains that attempt without the later raise. The GHSA names the residual bypass in that boundary. The closer amends the same branch. It is not an untouched sibling.

5. `fix_reversal_gate`: PASS. `6e7f938d` changes the quoted return into a raise. Unknown-version skip and `additionalProperties: true` remain in 1.4.0 and are out of this scope.

6. `release_gate`: PASS. Public PyPI 1.3.5 contains the fail-open and excludes the raise. Public PyPI 1.4.0 contains the raise and matches the closer blob. No git tags; PyPI is the public artifact.

7. `uniqueness_gate`: PASS. Not in canonical82 strict 82.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical82. Publication and more-than-200 stay HOLD.
