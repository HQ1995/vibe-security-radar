# Red-team: batch-9 PASS triple

**Status: `REDTEAM_COMPLETE`.** Hostile hypothesis: none of the three source-worker PASS rows is countable until independently proved. Assigned exactly `GHSA-X4HG-HFWF-P9MW`, `GHSA-322X-V876-G883`, and `GHSA-6R28-9PPF-4HJ5` from `autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low/cases.jsonl`. Source verdicts and prose were not trusted.

**KEEP proposal: 2. NARROW: 1. REJECT/UNKNOWN/BLOCKED: 0.**

Worker PASS remains proposal only. Causal admission is false. Publication and more-than-200 remain HOLD. Canonical73 still holds 73 strict released first-party GHSA identities. None of the three assigned IDs are in that set.

Leader contract frozen at SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.

## Attacks

| Case | Attack | Result |
|------|--------|--------|
| X4HG / 322X | `f8ee181b` and `ed0124d3` authored distinct vulnerable mechanisms | Does not stick |
| X4HG / 322X | A human PR member authored the relevant hunk | Does not stick: associated pulls empty; closed numbers are issues, not PRs |
| X4HG / 322X | npm or git `0.0.21` / `0.0.22` fail the claimed candidate/fix split | Does not stick |
| X4HG / 322X | The two GHSAs are duplicated projections | Does not stick |
| 6R28 | `fe11a243` itself creates the Diameter AVP underflow rather than refactoring an old mainline decoder | Does not stick as a mainline refactor (parent has no Diameter files). Sticks as squash-carrier / human-member origin |
| 6R28 | `145859d0` is the exact reversal | Does not stick |
| 6R28 | `v1.6.0` / `v1.6.1` bracket candidate versus fix | Does not stick |
| 6R28 | Copilot authored the AVP underflow hunk | Sticks: Copilot member edits only `layers/ports.go` |

## GHSA-X4HG-HFWF-P9MW — KEEP (all seven gates PASS)

Identity PASS. Frozen advisory-database `GHSA-x4hg-hfwf-p9mw` and GitHub advisory API: `type=reviewed`, `withdrawn_at=null`, `github_reviewed=true`, package npm `@asymmetric-effort/nogginlessdom`, `<= 0.0.21` / first patched `0.0.22`, CWE-1333, repository `asymmetric-effort/NogginLessDom`. Repo advisory REST GET succeeded. Mechanism: `HTMLInputElement.checkValidity()` built `new RegExp` from the user-controlled `pattern` property.

AI hunk PASS. `f8ee181be67344f12aeb30ec39e5ab611c65b826` is single-parent `e314fcf257ff175fa2c5a86d61f5b5f7cbfe8998`. Author and committer Sam Caldwell. Body has `Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`. GitHub associated-pulls is `[]`. Closed `#35` `#36` `#40` `#42` are issues (`pull_request=false`), not PRs. First-parent adds `ValidityState` and `HTMLInputElement.checkValidity`, including `const re = new RegExp(\`^(?:${this.pattern})$\`)`. Parent already has `public pattern = ''` and has no `checkValidity` and no `new RegExp`. On `7cd24135` (0.0.21) blame of that construction is `f8ee181b`.

Topology PASS. No squash-member transfer. Later html-elements commits (`92d9c46`, `dfe8510`, `d84fbc2`) do not steal blame of the RegExp line. Version bump `7cd24135` is Claude-marked and is not origin.

But-for PASS. Removing the `checkValidity` / unguarded `RegExp` construction eliminates the GHSA-named ReDoS. The unused parent `pattern` field is not the sink.

Fix-reversal PASS. `25a3cbac665fae5663f8b71c073b80c3152dbe7b` is single-parent `785e6ac6`. First-parent inserts `hasNestedQuantifiers` and `MAX_PATTERN_LENGTH = 1024` around the same `new RegExp`. Advisory names this commit.

Release PASS. Partial clone has zero tags (`tagOpt=--no-tags`). Independently:

| Artifact | Commit | package.json | contains `f8ee181b` | contains `25a3cbac` |
|----------|--------|--------------|---------------------|---------------------|
| npm 0.0.21 / tag `v0.0.21` | `7cd241350fb7669b006fed46b81436925d1bb55c` | 0.0.21 | yes | no |
| npm 0.0.22 / tag `v0.0.22` | `00dc8ad39071140d1d76c03d93c6e10f19e51138` | 0.0.22 | yes | yes |

npm `gitHead` equals those commits. Annotated tag objects peel to them. Tarball `0.0.21` `build/index.js` has the unguarded pattern `RegExp` and no `hasNestedQuantifiers`. Tarball `0.0.22` has `hasNestedQuantifiers` and `MAX_PATTERN_LENGTH`.

Uniqueness PASS. Absent from canonical73, fp211 public cases, and live `scripts/publication_adjudications.json`. Distinct from `GHSA-322X-V876-G883`. commit-first-af REJECT attached Claude to closer `25a3cbac`, not this origin.

## GHSA-322X-V876-G883 — KEEP (all seven gates PASS)

Identity PASS. Frozen advisory-database `GHSA-322x-v876-g883` and GitHub advisory API: reviewed, not withdrawn, same npm package and `<= 0.0.21` / `0.0.22` range, CWE-22, repo advisory GET succeeded. Mechanism: `matchFileSnapshot` writes caller-controlled `filePath` in update mode.

AI hunk PASS. `ed0124d37f548be12f2ff91b48ce7e33380d0ab4` is single-parent `c9ce5882e06042b9a10f3d8371e8d41c27403283`. Claude Opus 4.6 trailer. Associated-pulls `[]`. Closed `#126` and siblings are issues, not PRs. First-parent adds `export function matchFileSnapshot(actual, filePath)` and `fs.writeFileSync(filePath, ...)`. Parent has `writeSnapshotFile` for named snapshots derived from the caller test file, and has no `matchFileSnapshot`. On 0.0.21 blame of `matchFileSnapshot` is `ed0124d3`.

Topology PASS. No member-to-squash transfer. Later snapshot commits (`6e6e1d3`, `fd632bf`) do not steal that blame.

But-for PASS. Removing `matchFileSnapshot` eliminates the GHSA PoC (`toMatchFileSnapshot('/tmp/...')`). Parent `writeSnapshotFile` is a different API.

Fix-reversal PASS. `785e6ac6e124d1a89b3ccf40bbd75fc8e4cb215d` is single-parent `7cd24135`. First-parent inserts `projectRoot` resolve and rejects paths outside the project directory, then uses `resolved` for all I/O. Advisory names this commit. Later `1a114ca` (GHSA-WJ89 snapshotDir) is a sibling identity.

Release PASS. Same npm / annotated-tag pair as X4HG. Tarball `0.0.21` `matchFileSnapshot` has no `projectRoot`. Tarball `0.0.22` throws `File snapshot path must be within the project directory`. Tag `v0.0.20` peels to `f3ca3806` and already contains `ed0124d3`; npm never published `0.0.20`. Countable vulnerable artifact is published `0.0.21`.

Uniqueness PASS. Distinct first-party identity from X4HG (different SHA, file, CWE, closer). Shared 0.0.21/0.0.22 release pair does not merge cases. Sibling snapshotDir / symlink GHSAs are different identities.

## GHSA-6R28-9PPF-4HJ5 — NARROW (ai_hunk, topology, but-for)

Identity PASS. Frozen advisory-database `GHSA-6r28-9ppf-4hj5` and GitHub advisory API: reviewed, not withdrawn, alias CVE-2026-54345, Go package `github.com/gopacket/gopacket`, `<= 1.6.0` / first patched `1.6.1`, repo advisory GET succeeded. Mechanism: vendor AVP `Length` 8..11 underflows `uint32` `dataLength` and `make([]byte, ~4GiB)`.

AI hunk FAIL. Squash `fe11a243b3365bf877ddd91f9ba37206c25d96df` is single-parent `de82a343cb274a34db691bfe10b1aa1378d07b0d` and carries Copilot because PR #140 member `6de0ba93` (`Update layers/ports.go`) does. Cached PR members:

| Member | Login | Files | Copilot |
|--------|-------|-------|---------|
| `aa3fce6b` | dreadl0ck | diameter layer type | no |
| `64589189` | dreadl0ck | ports mappings | no |
| `a044cc7e` | dreadl0ck | SCTP payload | no |
| `736620f5` | dreadl0ck | `layers/diameter.go` | no |
| `d23e7f51` | dreadl0ck | `layers/diameter_avp_decoders.go` only | no |
| `64382f1b` | dreadl0ck | AVP codes | no |
| `671ee73d` | dreadl0ck | tests | no |
| `6de0ba93` | mosajjal | `layers/ports.go` only | yes |

PR `merge_commit_sha` equals `fe11a243`. Member SHAs are missing from the mainline clone after squash. Mainline blame of `dataLength := avp.Length - uint32(headerSize)` on `v1.6.0` is the carrier. PR branding / squash-carrier transfer is not an atomic AI hunk.

Topology FAIL. Counting the squash as Copilot origin of the underflow transfers authorship from human member `d23e7f51`.

But-for FAIL. Removing Copilot's `ports.go` change leaves `decodeDiameterAVP`. Parent `de82a343` has no Diameter files, so the squash creates the file on mainline; that is carrier introduction of a human-authored decoder, not Copilot origin. PR body claims a port of unmerged `google/gopacket#733` (`merged=false`). That is not a mainline refactor of an already-shipped decoder, and it still does not make Copilot the AVP author.

Fix-reversal PASS. `145859d0eaee1a6f5925ffb93851c976449c3311` is single-parent `95d1ae3e` (`v1.6.0`). First-parent inserts `if avp.Length < uint32(headerSize)` immediately before the subtraction. Advisory names this commit. Associated pulls `[]`.

Release PASS as reconstructed containment, not as AI origin. Lightweight tags: `v1.6.0` peels to `95d1ae3e197eee3a25d24abb7b079a60b578854d` (blob `40b24431`); `v1.6.1` peels to `76119086f5936aacd7088bdf97d565501bb6c4cc` (blob `ce7925e1`, equal to the closer). `fe11a243` is an ancestor of `v1.6.0`; `145859d0` is not. Both are ancestors of `v1.6.1`. First-party release URL `https://github.com/gopacket/gopacket/releases/tag/v1.6.1`.

Uniqueness PASS. Absent from canonical73 and publication adjudications. Prior commit-first-gj REJECT (`SQUASH_CARRIER_COPILOT_ON_NON_MECHANISM_HUNK`) is not a counted KEEP. This row independently closes fix-reversal and release, which that prior row left UNKNOWN.

## Claim boundary

No worker or red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical73 and does not support a more-than-200 claim. Shared tracked files, canonical snapshots, source worker outputs, and the source worker directory were not edited. No commit or push. No credentials printed.
