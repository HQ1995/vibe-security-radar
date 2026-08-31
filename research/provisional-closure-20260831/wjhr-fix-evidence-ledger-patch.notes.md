# GHSA-WJHR-76VG-2HVC canonical fix evidence

Verdict: keep `21aea2d95b823a15c81a3efe87566de5dcc3befc` as the AI-marked atomic origin, `e36613f3e490da51e37458a53fae36c75686533d` as its patch-equivalent release carrier, and `8256b577190b446e279c81b845d8e27d0ea1fbf5` as the minimum fix on the released path.

The first-party advisory names `77a3837f1f79d486663c9646438e70e8319e1a48` as its patch commit. Local Git establishes why that SHA is not the canonical release edge:

- `77a3837` and `8256b57` have byte-identical full diffs and stable patch-id `8267425b09527c9aed0d1772255eb6610ff020c7`.
- Their parents expose the same pre-fix `garminconnect/client.py` blob `c11438a35f1a73e51417f8829d3f773f8aca1602`; both produce fixed blob `ddda26b27d5079bec3e3c0cf83da0c85d7177902`.
- `77a3837` and its merge `f74174a` are not ancestors of tag `0.3.5`. `8256b57` is an ancestor of `0.3.5`, whose `garminconnect/client.py` is the same fixed blob.
- Therefore `77a3837` is first-party evidence for the atomic patch's origin, while `8256b57` is the object that actually closes the vulnerable release lineage.

The origin side has the same branch-copy topology: `21aea2d` and `e36613f` have byte-identical full diffs and stable patch-id `600e53cf1146df2edc5ee2c8eec0261bd285d2a4`; both produce focal blob `e612db67d43f94161d39de27b23f501749d6839b`. Only `21aea2d` carries the Claude Opus 4.6 trailer, while only `e36613f` is an ancestor of vulnerable tag `0.3.4`. The explicit `candidate_fix_edges` row records this as `origin_kind=branch_copy` without transferring authorship to the carrier.

Primary sources:

- https://github.com/cyberjunky/python-garminconnect/security/advisories/GHSA-wjhr-76vg-2hvc
- https://github.com/cyberjunky/python-garminconnect/commit/21aea2d95b823a15c81a3efe87566de5dcc3befc
- https://github.com/cyberjunky/python-garminconnect/commit/77a3837f1f79d486663c9646438e70e8319e1a48
- https://github.com/cyberjunky/python-garminconnect/commit/8256b577190b446e279c81b845d8e27d0ea1fbf5

Selected evidence hashes use the canonical newline-joined hunk-code rule:

- candidate: `e2fcf191b28313f328dc03131922dad49ae7634b5ec59a965b5a7e205233f8f3`
- fix: `3b1ec80ba10ce55680cce49d60ac326913e65f5ac86b0184efe6395c638f1040`

The patch was prepared against fresh Neon revision 2. It intentionally does not apply the transaction or modify publisher, web, generated evidence, or the recovery export.

Validation passed: one-line `json.loads`, `validate_update` against the fresh live row, exact candidate source-slice and fix-diff matching against Git blobs, selected-hunk SHA-256 recomputation, required-anchor coverage, commit-object checks, and release ancestry checks.
