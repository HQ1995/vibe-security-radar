# Independent red-team of GHSA-7GH7 and GHSA-6P9M

**Verdict first: 2 KEEP proposals, 0 NARROW, 0 REJECT, 0 UNKNOWN, 0 BLOCKED.**

This is review only. It is not leader admission, not a canonical-ledger rebuild, and not support for a more-than-200 claim. Publication remains HOLD. `causal_admission` is false. KEEP requires all seven contract gates independently PASS for the exact scope counted.

Hostile input: (1) `GHSA-7GH7-258J-4MPQ` PASS from `autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh`; (2) `GHSA-6P9M-Q3JP-47H4` PASS from `autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium`. For Gogs, the counted edge is the leader correction `candidate=5e6014c421f7e3ab1d541983372377331aa4bf7a`, `minimum_fix=e2fae5d0455d4f92c6382433d21c3a16da077d64`, class `AI_INCOMPLETE_REMEDIATION`. Non-ancestor members are not counted.

Executed transcripts: `notes/actual-executed.txt`, `notes/gogs-executed.txt`, `notes/extra-executed.txt`, `notes/npm-snippets.txt`.

## GHSA-7GH7-258J-4MPQ — KEEP (proposal)

Repository `actualbudget/actual`. Class `AI_DIRECT_ROOT`. Counted candidate `a43b6f5c4714fb08b3fe3e5ce560213b229648c1`. Minimum fix `068185751c03b42e726e3c60b718413d5f96c306`.

**Identity PASS.** Copied first-party object `pages/ghsa-7gh7-258j-4mpq.json` sha256 `0c6321047191c86a93ecb85c31c4bc97cc0ee5c9d1b01b9010a6c9dda12c9fc1`. `github_reviewed: true`, not withdrawn, aliases CVE-2026-46672, affected npm `@actual-app/cli` introduced 0 / fixed 26.6.0. The advisory names `packages/cli/src/output.ts` `escapeCsv` and calls loot-core `csv-stringify` a distinct variant.

**AI-hunk PASS.** Squash subject `[AI] Experimental CLI tool for Actual (#7208)`. Trailer `Co-authored-by: Claude <noreply@anthropic.com>`. One parent `1f821d2849e4303b05b21b87c18852b1b8ca5153`. First-parent adds `packages/cli/src/output.ts` with RFC-only `escapeCsv`.

**Topology PASS.** The counted SHA is the squash itself. PR member `c4de834f` is missing from the clone and is not a tag ancestor requirement once the squash carries its own marker. No authorship transfer.

**But-for PASS.** Parent has no `packages/cli/src/output.ts`. Removing the squash removes the named `@actual-app/cli --format csv` helper. Parent loot-core `csvStringify` is GHSA-XQJM / `@actual-app/web`, out of this affected package. That is not preservation of the scoped CLI bug and not a code move.

**Fix-reversal PASS.** `06818575` (`[AI] Prevent CSV formula injection in exports and CLI output (#7859)`, also Claude-coauthored) adds `FORMULA_TRIGGERS` and `formatCsvCell`. `v26.6.0` `output.ts` blob equals the fix blob `312c5058d722c96930df86d775bd9d62eec4df56`.

**Release PASS.** `v26.5.2` = `5b838293` contains the candidate, does not contain the fix, `escapeCsv` still RFC-only (blame `a43b6f5c`; blob `c2b65d9d`). `v26.6.0` = `3a730c16` contains the fix. npm tarball `@actual-app/cli` 26.5.2 sha256 `b92ef706` contains `function escapeCsv` and no `FORMULA_TRIGGERS`. 26.6.0 sha256 `d414a6cb` contains `FORMULA_TRIGGERS` and `formatCsvCell`. `gitHead` is null; the bundle still carries the serializer.

**Uniqueness PASS.** Not in `countable_first_party_ghsa_ids`. fp211 ordinal 99 is NARROW/HOLD for this same identity, not a second case. Distinct from GHSA-XQJM. Shared fix SHA does not merge the two GHSAs.

**Failed hostile claims.** Later `edc024220` edits `AMOUNT_FIELDS` / `formatCellValue`; it does not rewrite `escapeCsv`. fp211 topology NARROW came from counting the missing member. npm provenance is not empty: the published `dist/cli.js` contains the named helper.

## GHSA-6P9M-Q3JP-47H4 — KEEP (proposal)

Repository `gogs/gogs`. Class `AI_INCOMPLETE_REMEDIATION` under the patch-delta rule. Counted candidate `5e6014c421f7e3ab1d541983372377331aa4bf7a`. Minimum fix `e2fae5d0455d4f92c6382433d21c3a16da077d64`.

**Identity PASS.** Copied first-party object `pages/ghsa-6p9m-q3jp-47h4.json` sha256 `3779a7fbafd644a265a51f213358f3a95c930dfcea9ead775c2d081f522d8ad8`. `github_reviewed: true`, not withdrawn, aliases CVE-2026-52812, Go package `gogs.io/gogs` fixed 0.14.3. References the repository advisory and names the `os.Stat` dedupe shortcut that returns success without hashing.

**AI-hunk PASS.** `5e6014c` subject `lfs: verify content hash and prevent object overwrite (#8166)`. Trailer `Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`. One parent `f5c8030c`. First-parent rewrites `LocalStorage.Upload`: parent was `os.Create` + `io.Copy` with no hash; the AI commit adds temp-file sha256 verification and an `os.Stat` shortcut `io.Copy(io.Discard, rc); return fi.Size()`.

**Topology PASS.** `5e6014c` is an ancestor of `v0.14.2` and `v0.14.3`. Members `85ebf175`, `90f99d5f`, and squash `81ee8836` are not ancestors of those tags or of `5e6014c` (`merge-base --is-ancestor` rc=1). They are not counted. Blob `b53522f1` is shared with the squash; whole-commit patch-ids differ. Blob identity is not authorship transfer.

**But-for / patch-delta PASS.** The AI commit is an explicit security rewrite of the upload boundary. `v0.14.2` contains that rewrite without the later Stat-hash. GHSA-6p9m names the residual Stat bypass of the new-file hash. `e2fae5d` hashes that same Stat shortcut. The residual is not an untouched sibling: parent had no Stat path. Parent overwrite-without-hash is sibling GHSA-gmf8, not this leak. Advisory `introduced: 0` is imprecise versus git; the named shortcut is AI-added. Rollback reopening overwrite is not a patch-delta failure.

**Fix-reversal PASS.** `e2fae5d` (`security: verify content hash on LFS dedupe shortcut (#8333)`, cherry-picked from `f35a767`) first-parent-diffs the Stat block to hash the body and `ErrOIDMismatch`. Mainline `f35a767` lives on `internal/lfsx/storage.go` and is not a `v0.14.3` ancestor. Counted fix is the cherry-pick.

**Release PASS.** `v0.14.2` = `5dcb6c64` contains `5e6014c`, does not contain `e2fae5d`, storage blob `b53522f1`. `v0.14.3` = `3ba8aca9` contains `e2fae5d`, storage blob `b082fbcf`. No later `storage.go` commit between candidate and `v0.14.2`. `v0.14.2` blame of the Stat shortcut is `5e6014c`.

**Uniqueness PASS.** Absent from fp211 public cases, from `countable_first_party_ghsa_ids`, and from the live publication GHSA set. Distinct from overwrite GHSA-gmf8.

**Failed hostile claims.** Worker candidate_set listed non-ancestor members. Leader-corrected edge is the release-line commit with its own marker. `CreateLFSObject` pre-existed; the AI Stat success is what binds a second repo without overwriting victim bytes. Later human origin of the named hunk was not found.

## Claim boundary

- Worker PASS remains a proposal.
- This packet does not edit tracked files, canonical ledgers, or publication data.
- No commit, push, or credential output.
- Strict released lower bound is not rebuilt. A more-than-200 claim is not supported here.
