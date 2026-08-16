# TP mining Lane A phase 4: broad fix-form recovery (2026-08-16)

## Goal

Re-recover fixes for rows the first pass missed. The fix ALWAYS exists when an
advisory was published; find it in ANY form. Budget: max 10 network calls/row.

## Fix forms (in priority order)

1. Direct commit: any github.com/<owner>/<repo>/commit/<sha> in GHSA, OSV,
   NVD, or the vuldb page.
2. Merge commit: if the referenced sha is a merge commit, it is still the fix;
   verify with the .patch endpoint and record it (form=merge).
3. Release/tag range: advisory/OSV has a fixed version -> find the repo tag
   via `git ls-remote --tags https://github.com/<repo>.git` (no API), pick the tag
   matching the fixed version, then
   "https://github.com/<repo>/compare/<prev-tag>...<fixed-tag>.patch" and
   record form=range with the range string.
4. WordPress SVN: if package is a WP plugin, the fix lives in
   plugins.svn.wordpress.org. Record the changeset/revision URL found in
   patchstack/vuldb/wpscan references (form=svn).
5. Closed-source release: record fixed_version + evidence URL, form=release,
   recovered=true (fix exists, no source diff available).
6. Nothing found anywhere: recovered=false with an honest note.

## Output

.ai-slop/state/laneA/p4/laneA-p4-results-<N>.jsonl — one JSON per input row,
same order:

{"class_id","public_ids","repo","fix_sha":null or "...",
 "fix_range":null or "...", "fix_form":"commit|merge|range|svn|release|none",
 "fixed_version":null or "...", "source":"ghsa|osv|nvd|vuldb|wp|...",
 "note":"<=80 chars"}

Never modify tracked files. Reply with output path and counts per form.

## Acceptance

- class_id set matches input exactly.
- fix_form != none requires an evidence URL or version in note.
