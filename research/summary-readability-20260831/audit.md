# Detail-page summary readability audit

## Technical summary

The `How AI contributed` headline is not uniformly reader-ready. In the current 254-case snapshot, 210 headlines pass a minimal mechanical screen, while 44 need rewriting: 12 are raw research mechanisms cut off at 280 characters, 19 describe the vulnerability without saying what AI did, and 13 are complete but longer than a practical 200-character headline budget.

This is a publishing-path problem, not 44 independent UI bugs. The detail component always prefers `code_evidence.summary`, and all 254 current values pass the permissive `isPublicProse()` filter; consequently, neither the advisory-description fallback nor the generic contribution headline is used. Of those values, 242 come from the curated alias summary map and 12 fall through to `build_missing_code_evidence.py`, which currently assigns `(mechanism or "")[:280]`.

The vLLM example is one of the 12 hard failures. Its public headline contains a PR number, a full SHA, author/trailer metadata, and the unfinished fragment `Later PR memb`; it should instead read: **“Claude-assisted code let requests select DeepStream GPU decoding and control a shared pool, while skipping the normal frame-size limit. An unauthenticated client could force oversized decodes and starve other requests.”**

## What was measured

- Snapshot: `web/src/generated/research-data.json`, generated at `2026-08-31T00:53:34Z`, with `snapshot.case_count = 254`.
- Actual render path: `findingSummary()` takes `code_evidence.summary` first (`web/src/components/canonical-case-evidence.tsx:114-119`) and renders it as the section heading (`web/src/components/canonical-case-evidence.tsx:899-905`).
- Acceptance filter: `isPublicProse()` checks basic length and a short denylist, but does not require a complete sentence, an AI role, an impact, or the absence of commit metadata (`web/src/lib/markdown-utils.ts:28-45`).
- Provenance: each rendered headline was matched against every case ID, alias, and `class_id` in `research/gate-campaign-20260830/summaries-by-alias.json`. Exact matches are “curated overlay”; the remaining values are generated-evidence fallbacks.
- Mechanical headline screen: at most 200 characters, terminal punctuation, no 12–40 character Git SHA, PR number, or audit shorthand such as `BIC`, and an explicit `AI`, `Claude`, `Copilot`, `Cursor`, `Codex`, `Gemini`, or agent/bot authorship term. This screen finds release-copy defects; it does not re-adjudicate causal evidence.

## Findings

| Signal | Cases | Share | Interpretation |
|---|---:|---:|---|
| Curated summary overlay | 242 | 95.3% | The intended public-summary path is already dominant. |
| Raw mechanism fallback | 12 | 4.7% | Every fallback is exactly 280 characters, provenance-first, and cut off mid-sentence. |
| No explicit AI role anywhere | 27 | 10.6% | Eight are raw fallbacks and 19 are curated summaries; the headline does not answer its own section title. |
| AI role absent from first 85 characters | 30 | 11.8% | Attribution arrives late or never; vLLM first mentions Claude at character 250. |
| Longer than 200 characters | 25 | 9.8% | Twelve are broken fallbacks and 13 are overly dense curated headlines. |
| Longer than 160 characters | 110 | 43.3% | The broader corpus is verbose even where it remains usable. |
| Full Git SHA in headline | 10 | 3.9% | Commit identity duplicates the evidence cards and crowds out mechanism/impact. |
| PR number in headline | 3 | 1.2% | Review chronology is exposed before the reader understands the flaw. |
| Fails at least one minimal screen | 44 | 17.3% | Priority rewrite set; the three buckets below are mutually exclusive. |

### Twelve summaries are mechanically truncated research notes

All 12 lack a curated alias-map match. They come from the hard slice at `scripts/build_missing_code_evidence.py:356`, so this is deterministic truncation rather than a CSS display issue. `public_text()` cannot repair text already cut mid-word, and `isPublicProse()` accepts it because it has enough English words.

Affected IDs:

- CVE-2026-79665 / GHSA-Q8HH-M6V5-4F3X
- CVE-2026-78684 / GHSA-HW36-J4Q7-VJXX
- CVE-2026-77068 / GHSA-H5RM-9FHH-5PHJ
- CVE-2026-77083 / GHSA-2664-HR5V-554W
- CVE-2026-76212 / GHSA-JJ45-W38G-GFRJ
- CVE-2026-74894 / GHSA-GVQ9-CMXR-844M
- CVE-2026-74886 / GHSA-C7VW-VFXJ-3MVH
- CVE-2026-74876 / GHSA-723W-CRW6-P9HX
- CVE-2026-10281 / GHSA-Q6QC-XP4Q-RJQ5
- CVE-2026-25253 / GHSA-G8P2-7WF7-98MQ
- CVE-2025-4144 / GHSA-QGP8-V765-QXX9
- CVE-2025-4143 / GHSA-4PC9-X2FX-P7VJ

Representative defects:

- **GHSA-HW36-J4Q7-VJXX:** starts with internal design nouns, then PR/SHA/author/trailer history, and stops at `Later PR memb`; it never reaches the attacker consequence.
- **GHSA-Q8HH-M6V5-4F3X:** begins with a full SHA and “atomic BIC”, distinguishes advisory constituents before explaining that non-admin session tokens skip admin checks, and ends on another SHA.
- **GHSA-H5RM-9FHH-5PHJ:** spends the whole headline on a reconstructed PR member, commit subject, and source path, ending at `That com` before explaining the traversal impact.
- **GHSA-Q6QC-XP4Q-RJQ5:** leads with abbreviated commit/parent proof and ends at `named surfa`; the reader should first learn that Claude-assisted code exposed command routes without authentication.

### Nineteen curated summaries explain the bug but not AI's contribution

These are generally clear vulnerability summaries, but under `How AI contributed` they omit the subject that matters. For example, GHSA-FRVJ-C5QP-XJ4W says “The fix stops decoding at 8 passes” without saying that this was the AI-assisted, incomplete fix.

Affected IDs:

`CVE-2026-77087`, `GHSA-P5RM-JG5C-8C77`, `CVE-2026-59221`, `CVE-2026-72770`, `GHSA-WV26-J37Q-2G7P`, `GHSA-Q6RR-FM2G-G5X8`, `CVE-2026-57126`, `CVE-2026-56837`, `GHSA-2C85-RFCC-G74J`, `CVE-2026-47390`, `GHSA-WXW3-Q3M9-C3JR`, `CVE-2026-44791`, `CVE-2026-44220`, `GHSA-P7MM-R948-4Q3Q`, `CVE-2026-41329`, `CVE-2026-32890`, `GHSA-5WP8-Q9MX-8JX8`, `CVE-2026-32045`, and `GHSA-VH5J-5FHQ-9XWG`.

Suggested rewrite for GHSA-FRVJ-C5QP-XJ4W: **“Claude-assisted path sanitization stopped decoding after eight passes instead of failing closed. A deeply encoded `../` path could survive the check and traverse the upstream terminal server.”**

### Thirteen curated summaries are too dense for a headline

These pass the attribution/content checks but exceed 200 characters: `CVE-2026-74885`, `CVE-2026-55389`, `CVE-2026-56678`, `CVE-2026-32718`, `CVE-2026-50180`, `CVE-2026-57132`, `CVE-2026-9366`, `CVE-2026-44788`, `CVE-2026-40113`, `CVE-2026-41365`, `CVE-2026-34076`, `CVE-2026-27695`, and `CVE-2026-28473`.

For example, CVE-2026-57132 is accurate but 285 characters long and combines fallback behavior, Landlock availability, filesystem scope, network scope, and two impacts in one sentence. A clearer version is: **“AI-written sandbox code silently fell back to a weaker subprocess sandbox when Landlock was unavailable. Sandboxed code could then access files or the network outside the configured limits.”**

### One headline exposes an evidence problem that copyediting cannot solve

CVE-2026-55828 says there is “no auditable source history” to identify the exact faulty AI-written code or its full impact, while the snapshot marks the case `confirmed`. Rephrasing can make that uncertainty sound smoother but cannot close it; either the missing source-to-sink evidence must be supplied or publication must stop presenting the attribution as final.

## Three-sentence reader contract

1. First sentence: name AI or the identified tool, state what it wrote or changed, and name the omitted or weakened security constraint in ordinary technical language.
2. Second sentence: state the attacker prerequisite and concrete consequence; prefer “an unauthenticated user could read…” over CWE labels or abstract phrases such as “named surface”.
3. Use a third sentence only to delimit a mixed-origin branch or an incomplete remediation; keep SHA, PR, author/trailer, parent/atomic/BIC proof, file paths, release archaeology, and fix chronology in the evidence cards below.

Default to one or two complete sentences, aim for 120–180 characters, and reject anything over 200 characters or lacking terminal punctuation. The publisher should require a curated summary for every public case rather than truncating `mechanism`; a small release check for completeness, explicit AI role, length, and provenance-noise tokens covers the recurring failure without adding runtime UI logic.

## Recommended repair order

1. Add curated summaries for the 12 fallback cases and remove the public `mechanism[:280]` behavior.
2. Prefix the AI role into the 19 otherwise usable curated summaries.
3. Tighten the 13 long curated summaries without dropping mechanism or impact.
4. Add one publisher/preflight assertion enforcing the reader contract, then regenerate and inspect the 44 rewritten headlines once.

The remaining 210 headlines are mechanically usable, not certified perfect prose. A later editorial pass can shorten the 85 additional 161–200 character headlines if the site still feels dense, but that is not required to fix the concrete failures above.
