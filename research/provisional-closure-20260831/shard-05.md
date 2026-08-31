# Provisional closure audit — shard 05

Date: 2026-08-31  
Scope: the seven assigned provisional cases. This report is read-only with
respect to the ledger, publisher, UI, and generated data.

## Decision rule

I replayed the seven gates from `docs/AUDIT-PROTOCOL.md` against the current
ledger/raw records and the full-history local clones. `PASS` below means the
specific gate has direct, replayable evidence. `FAIL` means direct evidence
contradicts the current AI-causal or release claim. `UNKNOWN` means the needed
primary artifact is absent; advisory prose or a package-version commit is not
substituted for that artifact. A row is `READY_TO_BACKFILL` only when all seven
gates pass.

## Verdict summary

Gate order is `identity, ai_hunk, topology, but_for, fix_reversal, release,
uniqueness`.

| Case | Exact gates | Decision | Blocking fact |
|---|---|---|---|
| `CVE-2025-62615` | `PASS, PASS, PASS, FAIL, PASS, PASS, PASS` | `NOT_AI_REVIEW` | The human-created parent lineage already fetched the same user URL with `feedparser.parse(url)`; reverting the Claude rewrite does not remove SSRF. |
| `GHSA-J383-Q79V-268X` | `PASS, PASS, PASS, FAIL, PASS, FAIL, PASS` | `NOT_AI_REVIEW` | The AI commit postdates the advisory's affected `<=3.4.0` line and occurs only in 4.0 tags that already contain the fix. |
| `GHSA-C7RR-QHWX-6Q49` | `PASS, PASS, PASS, PASS, PASS, FAIL, PASS` | `RESEARCH_GAP` | No published vulnerable artifact contains the origin without the fix; the sole surviving release tag contains both. |
| `GHSA-VH5J-5FHQ-9XWG` | `PASS, PASS, PASS, PASS, PASS, UNKNOWN, PASS` | `RESEARCH_GAP` | The named npm 8.1.2/8.1.3 artifacts are unavailable and there are no matching Git tags. |
| `GHSA-8G98-M4J9-QWW5` | `PASS, PASS, PASS, PASS, PASS, UNKNOWN, PASS` | `RESEARCH_GAP` | The named npm 7.0.5–7.0.8 artifacts are unavailable and there are no matching Git tags. The PASS vector is scoped only to the PayPal-webhook mechanism. |
| `GHSA-QGP8-V765-QXX9` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` | None. |
| `GHSA-4PC9-X2FX-P7VJ` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` | None. |

Result: **2 READY_TO_BACKFILL, 2 NOT_AI_REVIEW, 3 RESEARCH_GAP**.

## Case findings

### CVE-2025-62615 — NOT_AI_REVIEW

Current AI edge:

```json
{
  "candidate_set": ["583a9a9eb39673ed633b102e13894199992a4060"],
  "carrier_set": ["57a06f70883ce6be18738c6ae8bb41085c71e266"],
  "minimum_fix_set": ["a6a2f71458928f112c5e74b3bc1a95f9c76f20d5"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "FAIL", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  },
  "decision": "NOT_AI_REVIEW"
}
```

The published CVE / first-party GHSA names an RSS SSRF and is not rejected.
PR member `583a9a9e...` carries `Generated with Claude Code` and a Claude
coauthor trailer; its relevant hunk is preserved by squash carrier
`57a06f70...`, which replaces `feedparser.parse(url)` with an explicit
`urllib.request.urlopen(url)` guarded only by scheme and size checks. Fix
`a6a2f714...` routes the fetch through the SSRF-aware `Requests` wrapper.
Tags `autogpt-platform-beta-v0.6.32` and `v0.6.33` contain the carrier but not
the fix; `v0.6.34` contains the fix.

The failed gate is causal, not documentary. Human commit
`a00df25092ff60d94bcd1d41f18f778a2f27c573` created the RSS block in 2024 and
its new file already fetched the request-controlled URL with
`feedparser.parse(url)`. The Claude change altered the fetch implementation
and became the advisory-named bearer, but removing it restores the earlier
unfiltered network fetch rather than removing SSRF. It therefore cannot be a
seven-gate AI origin.

Primary replay: [first-party GHSA-r55v-q5pc-j57f](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-r55v-q5pc-j57f),
`artifacts/funnel-account-20260817.jsonl` row 1236, and `git show` / tag
ancestry in `.ai-slop/state/repos/significant-gravitas_autogpt`.

Required action: remove the row from AI-causal publication or explicitly
represent it as a non-counting AI rewrite of a pre-existing human-origin
weakness. Do not label the Claude change “direct introduction.”

### GHSA-J383-Q79V-268X — NOT_AI_REVIEW

```json
{
  "candidate_set": ["cf8faed585e14ab57cc390173d1b571aee438390"],
  "carrier_set": [],
  "minimum_fix_set": ["eb398971bfb43c38db3e04528b68ac9a7ce509bc"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "FAIL", "fix_reversal": "PASS",
    "release": "FAIL", "uniqueness": "PASS"
  },
  "decision": "NOT_AI_REVIEW"
}
```

`cf8faed...` is a single-parent commit with an Atlassian Rovo Dev coauthor
trailer. It rewrites `sort_cmp` and weakens the post-callback check to pointer
identity only. `eb398971...` directly repairs that development-tree variant
by snapshotting and comparing both pointer and length.

That closed commit-to-fix edge is not the released advisory origin. The
advisory identifies versions through 3.4.0, while `cf8faed...` was written
after 3.4.0 and is absent from every affected tag. All surviving tags that
contain it (`4.0.0-rc*` and `4.0.0`) also contain `eb398971...`. Tag 3.4.0
instead contains the older, human-written `size < a || size < b` guard; the
human line history includes `752ebe6b7f0ad24f3841602f6b21ec5b808c66c5`
and its later revisions. Reverting `cf8faed...` therefore does not explain or
eliminate the vulnerability published for 3.0–3.4.0.

Primary replay: [GHSA-j383-q79v-268x](https://github.com/advisories/GHSA-j383-q79v-268x),
[mruby issue 6649](https://github.com/mruby/mruby/issues/6649),
`research/orchestrator-260812-posthold-canonical/ledger.jsonl` row 69, and
tag/source history in `.ai-slop/state/repos/mruby_mruby`.

Required action: remove the AI-root attribution. If a non-AI historical
record is desired, first trace the smallest human first-write on the affected
3.x line; that extra trace is not needed to rule out this later AI commit.

### GHSA-C7RR-QHWX-6Q49 — RESEARCH_GAP

```json
{
  "candidate_set": ["ff958e486e1f8de4f7fd43c70ef357b8d6eaf433"],
  "carrier_set": [],
  "minimum_fix_set": ["64f9f86f87c23705fda6faa9947a947bf48b12c2"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "FAIL", "uniqueness": "PASS"
  },
  "decision": "RESEARCH_GAP"
}
```

Claude-marked single-parent commit `ff958e48...` creates `api_server.py` and
the three request-filename-to-`os.path.join("workflows", filename)` paths.
The parent has no file. Human fix `64f9f86f...` replaces the direct join with
a recursive JSON inventory and exact basename selection, reversing the
traversal primitive.

Release containment is directly negative: the only surviving release tag,
`dmca-compliance-2025-08-14`, contains both candidate and fix. No tag or other
recovered published artifact contains the candidate while excluding the fix.
The CVE's cited “Main Commit” `ee254131...` is unrelated PR #37 category-search
work and cannot fill this gate.

Primary replay: [GHSA-c7rr-qhwx-6q49](https://github.com/advisories/GHSA-c7rr-qhwx-6q49),
`research/orchestrator-260813-fp211-audit/final_mechanisms.jsonl`, and Git/tag
history in `.ai-slop/state/repos/zie619_n8n-workflows`.

Required source to close: a first-party published deployment, release,
archive, package, or immutable tag containing `ff958e48...` (or an identical
vulnerable blob) and excluding `64f9f86f...`. Without that source it must not
be promoted; the absence of such an artifact alone is not a CVE withdrawal.

### GHSA-VH5J-5FHQ-9XWG — RESEARCH_GAP

```json
{
  "candidate_set": ["57b7634391959dbbdb39b387ac4dc68157cd58a1"],
  "carrier_set": [],
  "minimum_fix_set": ["fdf67a6fba0deae30912905a79fb5a9e83751a79"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "UNKNOWN", "uniqueness": "PASS"
  },
  "decision": "RESEARCH_GAP"
}
```

Jules-bot commit `57b76343...` is an explicit security attempt that first adds
`token_used_at`, then consumes it with a separate SELECT/check and UPDATE.
That patch delta creates the disclosed concurrent-reuse residual. Human fix
`fdf67a6f...` makes consumption atomic with
`UPDATE ... AND token_used_at IS NULL` and checks whether a row changed.
Later human rewrite `5e5a80b5ffd0b6fccf7bdc2d8793e8b01cb83844`
preserves the residual; it is a lineage witness, not an AI-authorship carrier.

The first-party advisory names vulnerable `<=8.1.2` and fixed `8.1.3`, and an
untagged package-version commit contains the candidate without the fix. That
is insufficient publication proof: the 8.1.2/8.1.3 npm tarballs are
unavailable, there are no 8.1.x Git tags, and the only surviving tag `8.2.4`
already contains the fix.

Primary replay: [first-party GHSA-vh5j-5fhq-9xwg](https://github.com/tailot/taylored/security/advisories/GHSA-vh5j-5fhq-9xwg),
`research/herdr-260814-commitonly-taylored-grok46-medium/report.md`, and Git
history in `.ai-slop/state/repos/tailot_taylored`.

Required source to close: an immutable published 8.1.2 artifact containing
the SELECT-then-UPDATE guard and a published 8.1.3 artifact containing the
atomic consume. Do not infer either from version strings or the later 8.2.4
tag.

### GHSA-8G98-M4J9-QWW5 — RESEARCH_GAP

```json
{
  "candidate_set": ["c139c021f68a09d22c2af88641b61c00f67f2af4"],
  "carrier_set": [],
  "minimum_fix_set": ["57b7634391959dbbdb39b387ac4dc68157cd58a1"],
  "scope_statement": "Only the unverified PayPal-webhook mechanism is attributed and gated here.",
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "UNKNOWN", "uniqueness": "PASS"
  },
  "decision": "RESEARCH_GAP"
}
```

Jules-bot single-parent commit `c139c021...` creates the backend template and
trusts `req.body` at `/paypal/webhook`; its parent has no backend file. Jules
fix `57b76343...` adds PayPal signature verification. That is a direct
candidate-to-fix edge and is distinct from GHSA-VH5J: the shared SHA is the
fix here and the later incomplete-remediation candidate there.

The advisory bundles other flaws. This gate vector is valid only for the
existing row's PayPal-webhook mechanism. It must not support the current
aggregate prose about arbitrary file reads and every bundled issue. If the
publisher insists on an aggregate case, `fix_reversal` is not closed by
`57b76343...`; path containment arrives later in human commit
`5e5a80b5...`, and the aggregate minimum fix set must be rebuilt.

Release remains unproved. The first-party advisory names npm 7.0.5–7.0.7 as
vulnerable and 7.0.8 as fixed, but those tarballs return 404, the registry's
recoverable versions dictionary contains only 8.2.4, and the only Git tag
already contains the fix. Packument timestamps are not artifacts.

Primary replay: [first-party GHSA-8g98-m4j9-qww5](https://github.com/tailot/taylored/security/advisories/GHSA-8g98-m4j9-qww5),
`research/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/report.md`, and Git
history in `.ai-slop/state/repos/tailot_taylored`.

Required sources/fields: recover vulnerable and fixed npm artifacts, and add
the explicit PayPal-only `scope_statement`. Otherwise keep provisional.

### GHSA-QGP8-V765-QXX9 — READY_TO_BACKFILL

```json
{
  "candidate_set": ["b1079e7beb5f4821a0ffc7ae07670c417b66d07d"],
  "carrier_set": [],
  "minimum_fix_set": [
    "d954473f066f0daa3949717fd4d6e805d2ac618b",
    "09a2adb2f197469e5b64e8b89c22b6687cacabc1"
  ],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

The reviewed GHSA aliases published CVE-2025-4144 and is not withdrawn.
Single-parent `b1079e7...` explicitly says Claude Code implemented PKCE and
records the prompt. Its parent has no PKCE identifiers. The commit first
stores an optional challenge and verifies a token request only when the
stored challenge exists, creating the downgrade mismatch. Direct PR #27
commit `d954473...` rejects `code_verifier` when no challenge was stored;
merge `09a2adb...` lands that fix on main.

The candidate is present and the fix absent in v0.0.2 through v0.0.4. The
patched npm 0.0.5 lineage contains `09a2adb...`; the next Git tag v0.0.6 also
contains it. This mechanism is unique from GHSA-4PC9: separate first-write,
invariant, direct fix, and advisory identity.

Primary replay: [GHSA-qgp8-v765-qxx9](https://github.com/advisories/GHSA-qgp8-v765-qxx9),
[fix PR #27](https://github.com/cloudflare/workers-oauth-provider/pull/27),
the current record's `research_status`, and Git/tag history in
`.ai-slop/state/repos/cloudflare_workers-oauth-provider`.

Required backfill: the seven gates above and a non-null causal chain with
`b1079e7...` as the BIC, `d954473...` as the atomic fix, `09a2adb...` as its
main-line merge, v0.0.4 as vulnerable release witness, and npm 0.0.5 / Git
v0.0.6 as fixed witnesses.

### GHSA-4PC9-X2FX-P7VJ — READY_TO_BACKFILL

```json
{
  "candidate_set": ["3b2ae809e9256d292079bb15ea9fe49439a0779c"],
  "carrier_set": [],
  "minimum_fix_set": [
    "66de8d802c1d7c468887906ea1a0769a975ff1e3",
    "4393dd4f96159f261629ce80e9ecaa027d348131"
  ],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

The reviewed GHSA aliases published CVE-2025-4143 and is not withdrawn. Root
commit `3b2ae809...` explicitly says Claude wrote the OAuth provider and
contains the complete prompt. With no parent, its tree is the first public
write: authorization parsing accepts request-controlled `redirect_uri`, and
completion constructs the callback URL and attaches a live code without
checking the registered client's allowlist. Direct PR #26 commit
`66de8d80...` adds client lookup plus exact allowlist validation before code
issuance; merge `4393dd4...` lands the fix on main.

The origin is in v0.0.2 through v0.0.4 while the fix is absent. Patched npm
0.0.5 contains the fix lineage, and v0.0.6 is the next Git tag containing it.
Its redirect-validation edge is independent of the later PKCE downgrade edge.

Primary replay: [GHSA-4pc9-x2fx-p7vj](https://github.com/advisories/GHSA-4pc9-x2fx-p7vj),
[fix PR #26](https://github.com/cloudflare/workers-oauth-provider/pull/26),
the current record's `research_status`, and Git/tag history in
`.ai-slop/state/repos/cloudflare_workers-oauth-provider`.

Required backfill: the seven gates above and a non-null causal chain with
`3b2ae809...` as the root BIC, `66de8d80...` as the atomic fix,
`4393dd4...` as its main-line merge, v0.0.4 as vulnerable release witness,
and npm 0.0.5 / Git v0.0.6 as fixed witnesses.

## Integration boundary

Only the two Cloudflare rows are ready for deterministic gate/chain backfill.
The three release-open rows must remain provisional, and the two causal
negative controls must not remain presented as verified AI introductions.
No ledger, publisher, UI, generated file, commit, or push was changed by this
shard.
