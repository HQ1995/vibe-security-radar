# Final unknown-9 adjudication

Owner: autoresearch/herdr-260814-final-unknown9-grok46-high/. Proposal only. Assigned ordinals 35, 51, 53, 56, 84, 116, 129, 153, 154. No expansion. No GitHub API. Independent git replay did not complete: Coolify blob extraction failed on GitHub DNS / promisor fetch, and those empty/error dumps were not treated as negative proof.

## Verdict-first

All 9 rows stay UNKNOWN, terminal=false, countable=0. No CONFIRM, no NARROW, no FALSE_POSITIVE. Missing artifacts and missing AI markers were not converted into FAIL/FP.

| Ordinal | Case | Verdict | Open / failed gates | Disagreement with stored labels |
| ---: | --- | --- | --- | --- |
| 35 | GHSA-4MPW-WCJ4-V9PP | UNKNOWN | ai_hunk UNKNOWN; but_for NARROW | None |
| 51 | GHSA-VJP8-WPRM-2JW9 | UNKNOWN | ai_hunk UNKNOWN | None |
| 53 | GHSA-8JQH-598V-RFXC | UNKNOWN | release UNKNOWN; identity/topology NARROW | None |
| 56 | GHSA-8G98-M4J9-QWW5 | UNKNOWN | release UNKNOWN | None |
| 84 | GHSA-VH5J-5FHQ-9XWG | UNKNOWN | release UNKNOWN | None |
| 116 | GHSA-CGJ8-7M5Q-X5GV | UNKNOWN | ai_hunk, topology, but_for, fix_reversal, release UNKNOWN | Stored topology/fix_reversal/release PASS reopened to UNKNOWN after failed replay + unresolved sibling conflict |
| 129 | GHSA-48P8-G2FX-3WWM | UNKNOWN | ai_hunk, topology, but_for UNKNOWN | None |
| 153 | GHSA-MF7V-X7R6-FQ57 | UNKNOWN | fix_reversal FAIL; ai_hunk/topology/but_for/release UNKNOWN | Sibling NARROW not adopted |
| 154 | GHSA-FP43-VJ7G-PG92 | UNKNOWN | fix_reversal FAIL; ai_hunk/but_for/release UNKNOWN | None |

## What closed

Identity closed PASS on 35, 51, 56, 84, 116, 129, 153, 154 from first-party GHSA/CVE objects cited in row evidence. Identity is NARROW on 53 because the global GHSA 404s and the CNA SHA is the fix-PR merge. Uniqueness closed PASS on all nine; shared SHA 57b76343 is a fix in 56 and a candidate in 84 for a different mechanism. ai_hunk closed PASS only where an explicit Jules/Claude marker authors the relevant hunk (53, 56, 84). but_for/fix_reversal/release closed PASS only where row first-party evidence already named parent-vs-candidate hunks and released tags and this review found no unresolved conflict (35 except ai_hunk; 51 except ai_hunk; 129 release/fix_reversal).

## What stayed open

- 35 / 116: Conductor auto-commit with no AI trailer cannot close ai_hunk. A later Claude fix trailer is not origin. 35 but_for stays NARROW because parent already had the mongodump sink. 116 TrustHosts dumps in this directory are fetch errors, so topology/but_for/fix_reversal/release are reopened UNKNOWN rather than kept as stored PASS.
- 51: Staged-fix workflow text and a mismatched PR body are not relevant-hunk AI proof.
- 53 / 56 / 84: No currently fetchable published artifact contains origin without the fix. Packument time keys, a sole later 8.2.4 tag, and missing 8.1.2/8.1.3 tags do not close release. Missing artifacts are not unreleased-FP.
- 129: Merge-from-fork squash Claude trailers do not prove the unrecovered private-fork member authored the ArtifactGC hunk.
- 153 / 154: Multi-sink advisories. Proposed fixes touch different files (Taxonomy.php vs Event.php; SourceMapResourceHandler vs CombinedResource*). fix_reversal FAILs for those pairings. That is not a whole-advisory FALSE_POSITIVE and not a NARROW confirmation of a subset that was not independently replayed.

## Per-gate failures

fix_reversal is the only affirmative FAIL: ordinals 153 and 154, because the named minimum_fix_set does not reverse the candidate residual. All other non-PASS values are UNKNOWN or NARROW. No gate was failed from absent blobs, DNS errors, or missing tags.

## Disagreement with stored labels

The only stored-label disagreement is ordinal 116: stored topology, fix_reversal, and release PASS are reopened to UNKNOWN. A sibling unknown4b NARROW/FAIL packet reported first-parent vs tag-blob mismatch; this review could not replay those objects and therefore neither keeps the stored PASS nor adopts the sibling FAIL/NARROW. Sibling unknown4b NARROW on 153 is also not adopted. Stored UNKNOWN verdicts on all nine rows are otherwise kept.
