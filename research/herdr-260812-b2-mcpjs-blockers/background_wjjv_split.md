# GHSA-WJJV-3MJ2-39HF mechanism split and lineage audit

Research window: 2026-08-12 12:47–13:00 America/New_York. This is a bounded background finding for the Batch 2 JavaScript/MCP campaign. It does not alter the shared ledger and does not admit a publication row by itself.

## Result first

The advisory is one alias class—**GHSA-WJJV-3MJ2-39HF = CVE-2026-47255**—covering six defensible mechanism groups. It must not be counted as six public vulnerabilities. The allegedly private patch branch is recoverable exactly from the public merge DAG:

```text
10cde1ee (public main / patch base)
  └─ de3a5c45  API account/storage patch, parent 10cde1ee
       └─ 41dd8153  Core relay/MailSender patch, parent de3a5c45
            └─ 1408de54  maintainer hardening, parent 41dd8153
                 └─ second parent of merge 234b811e

234b811e parents: 10cde1ee 1408de54
8cb053f2 parent: 234b811e; tag v0.9.46; npm api 0.9.32/core 0.9.10 gitHead
```

`1408de54^{tree}` and `234b811e^{tree}` are both `6def04846eccc503c13a6178cc7d0ff48c120e75`; their diff is empty. Thus the merge preserved, rather than obscured, three atomic patch commits. The first two atomic patches have Git author `Moltbot <moltbot@workspace.local>`, no GitHub-mapped author, no AI trailer, and an Ope Olatunji committer. The first-party release/advisory attributes the submitted patch to `@benediktkraus`. `Moltbot` is therefore **UNKNOWN model/agent provenance**, not sufficient direct AI attribution.

### Conservative mechanism verdicts

| # | Advisory mechanism | Exact public origin | Atomic closure | Release evidence | Conservative verdict |
|---:|---|---|---|---|---|
| 1 | inactive-agent `hours` validation/binding (CWE-20) | root `cf35e22f` | `de3a5c45` | API 0.9.31 → 0.9.32 | **NARROW** hardening; **REJECT** causal row |
| 2 | storage identifier / query-clause SQL injection (CWE-89) | `876cf485` + `255d3e1c` | partial `de3a5c45`, completed by `1408de54` | API tarballs close | **PASS** lineage, **REJECT** AI-origin row; unreleased partial is **NARROW** only |
| 3 | raw-SQL cross-agent / metadata access (CWE-284) | `255d3e1c` | partial `de3a5c45`, completed by `1408de54` | API tarballs close | **PASS** lineage, **REJECT** AI-origin row; unreleased partial is **NARROW** only |
| 4 | shipped outbound-worker secret/fallback (CWE-798) | root `cf35e22f` | `41dd8153` | source tag closes; worker absent from npm tarballs | **BLOCKED** npm-package containment; **REJECT** AI-origin row |
| 5 | SMTP envelope/header control injection (CWE-20) | root `cf35e22f` | `41dd8153` | source tag closes; worker absent from npm tarballs | **BLOCKED** npm-package containment; **REJECT** AI-origin row |
| 6 | MailSender TLS verification disabled (CWE-319) | root `cf35e22f` | `41dd8153`; narrowed by `6c70c825` | Core 0.9.9 → 0.9.10 → 0.9.13 | **PASS** for remote hosts, **NARROW** after loopback exception; **REJECT** AI-origin row |

Net campaign result: **0 new strict AI-causal rows** and **0 released AI incomplete-remediation rows**. Two unreleased patch gaps are useful negative controls, not publication-grade incomplete-remediation rows. At general vulnerability-accounting level, retain one official alias class, not six IDs.

## Snapshot boundary and hashes

The shared checkout and caches were treated as read-only. Evidence below was frozen between `2026-08-12T12:47:00-04:00` and `2026-08-12T12:59:47-04:00`; later shared changes are outside this report.

| Input | Frozen identity / hash |
|---|---|
| AgenticMail read-only clone | HEAD `4a0e0f6f590aed435c0f8bc962bbdd488aec4016` |
| GitHub Advisory Database read-only clone | HEAD `39d8887723797efc1804585dd06585c9fd751226` |
| reviewed GHSA JSON | SHA-256 `18696a9f374446748af6fcc81a4a1c673ec96b383ac7f5eb497de673d476b5bf` |
| live repository-advisory API response | SHA-256 `9fe12fce85cf000121fe7421d5cc426dad5d5a6d22dacdc65c1b5866fc10726a` |
| prior WJJV UNKNOWN background finding | SHA-256 `60fd0782205ba6bfaba0b4f216f00780ebc5b745472ef3bb827dcf9dce02c65a` |
| prior AgenticMail review packets | SHA-256 `a2a8d4262638ace179ed0b216e48f78a979641c0bd5331db3b7b445147bead42` |
| `api-0.9.31.tgz` | SHA-256 `bedc1876f4fa848b57720e7006ce08845c25ce9d879ff841b7e615c09cc95d28`; npm SHA-1 `9a6216a5c678ba610d273d33175180b769ec36d6` |
| `api-0.9.32.tgz` | SHA-256 `765be78025711b00b913a7d28a044048a3c434b011fcc1a7fcedca5756b22b6a`; npm SHA-1 `ff7191b7f02b83604e421ea299da5a9cf45d0c52` |
| `core-0.9.9.tgz` | SHA-256 `083a8423ad89a7cc8797b2f18e9c9e7bb7f855099477907140167503dae9ed62`; npm SHA-1 `da593d475bbc491d2a34e07f7e5f5a3f1dba289c` |
| `core-0.9.10.tgz` | SHA-256 `e5959e2625d110f2565fd3b7cb8888fcad9d5a3e2dafee5eb5c4d416f02afa70`; npm SHA-1 `4b03ea6143d2fb15bdf3f694514bd9cd09fb478e` |
| `core-0.9.13.tgz` | SHA-256 `5b33015a52cf96f12b1b97f82697f3f854d6ed5874bda489c6dc033b2ac61a1b`; npm SHA-1 `6e62200440779e34b505f973ec9a25338d32b6c8` |

The live first-party [repository advisory](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-wjjv-3mj2-39hf) returned `state=published`, `withdrawn_at=null`, `severity=high`, `published_at=2026-05-18T19:49:35Z`, and identifiers GHSA-WJJV-3MJ2-39HF/CVE-2026-47255. It maps `@agenticmail/api <=0.9.31` to `0.9.32` and `@agenticmail/core <=0.9.9` to `0.9.10`, with CWE-20/89/284/319/798. That identity is first-party evidence for the aggregate, not proof that every submechanism is present in each named npm tarball.

## Exact public topology and blobs

### Origin commits

- [`cf35e22fbfaa99725245505008e9de7a7c71ed02`](https://github.com/agenticmail/agenticmail/commit/cf35e22fbfaa99725245505008e9de7a7c71ed02) is the public root (no parent), authored by Ope Olatunji on 2026-02-15, with no trailers. It creates the inactive-account route family, outbound worker secret/fallback and SMTP construction, and `MailSender` with `rejectUnauthorized: false`. Because it is a root import, earlier private authorship is **BLOCKED**, but public Git does not provide an AI-origin marker.
- [`876cf485e41b239cdbc5b69308f60e4f2c420cea`](https://github.com/agenticmail/agenticmail/commit/876cf485e41b239cdbc5b69308f60e4f2c420cea), parent `99cd2b98565ebc6804e5dc2057e07fbb44ddb229`, is Ope-authored with no trailers. It creates the dynamic storage CRUD surface and its initial raw identifiers.
- [`255d3e1ca306ae720e7df7909a2582d7a7240b65`](https://github.com/agenticmail/agenticmail/commit/255d3e1ca306ae720e7df7909a2582d7a7240b65), parent `876cf485...`, is Ope-authored with no trailers. It adds the full DBMS surface, including raw `where` keys, raw `having`, and guarded raw SQL whose guard checks name shape but not metadata ownership.

Blame at patch base `10cde1ee` maps the exact unsafe lines as follows:

| Mechanism | Pre-fix line provenance |
|---|---|
| inactive hours interpolation | `cf35e22f`, `accounts.ts` lines 207/212 and 222/228 |
| where-key interpolation | `255d3e1c`, `storage.ts` lines 114–156 |
| selected/group/order identifiers | mixed `876cf485`/`255d3e1c`, query lines 817–829 |
| raw `HAVING ${having}` | `255d3e1c`, query line 828 |
| raw-SQL weak table scan | `255d3e1c`, raw SQL lines 1120–1153 |
| public relay secret and fallback | `cf35e22f`, `metadata.json` line 6 and `outbound.js` line 252 |
| SMTP header/envelope construction | `cf35e22f`, `outbound.js` build/MAIL FROM/RCPT TO paths |
| unconditional TLS opt-out | `cf35e22f`, `sender.ts` line 35 |

Relevant object identities preserve exact file-state boundaries:

| Path | origin/pre-fix blob(s) | merged fixed blob |
|---|---|---|
| `packages/api/src/routes/accounts.ts` | root `4de6c151...`; base `30219560...` | `d45b35ee...` |
| `packages/api/src/routes/storage.ts` | `876cf485`: `7810d091...`; `255d3e1c`: `a6a2581f...`; base `f84db393...` | `324b687e...` |
| `packages/core/src/gateway/workers/metadata.json` | `3b6f2a5c...` | `2c72056a...` |
| `packages/core/src/gateway/workers/outbound.js` | `069f7c6a...` | `e9b909b4...` |
| `packages/core/src/mail/sender.ts` | root `d610190e...`; base `14454693...` | `ffc6dffd...` |

### Patch branch and release commits

- [`de3a5c4519f65c76b9f7d9fb5df2bc788e2dcf61`](https://github.com/agenticmail/agenticmail/commit/de3a5c4519f65c76b9f7d9fb5df2bc788e2dcf61), parent `10cde1ee1bef69139ce50a795fd5380e0c626249`: validates/binds account hours; adds storage identifier validation and raw-SQL metadata ownership checks. It changes 4 API files. It leaves raw `HAVING ${having}` and only captures the first table in a comma join.
- [`41dd8153809cabbc9b79aba1b726266af923a1b7`](https://github.com/agenticmail/agenticmail/commit/41dd8153809cabbc9b79aba1b726266af923a1b7), parent `de3a5c45...`: removes the public worker secret and fallback, fails closed if it is absent, validates SMTP header/envelope control characters, and changes MailSender to `options.tlsRejectUnauthorized ?? true`. It changes 5 Core files.
- [`1408de543fa3577d8c2d4fdb289c75fe6faafac7`](https://github.com/agenticmail/agenticmail/commit/1408de543fa3577d8c2d4fdb289c75fe6faafac7), parent `41dd8153...`: maintainer hardening that adds `sanitizeHavingClause` and scans every storage-shaped token so comma-joined victim tables are ownership checked.
- [`234b811e426a0743170f3b10bc43419d64330155`](https://github.com/agenticmail/agenticmail/commit/234b811e426a0743170f3b10bc43419d64330155), parents `10cde1ee...` and `1408de54...`: public merge. Its tree is byte-identical to the second parent.
- [`8cb053f2307dd77b7736ffa0d7df04b0ccc3272d`](https://github.com/agenticmail/agenticmail/commit/8cb053f2307dd77b7736ffa0d7df04b0ccc3272d), parent `234b811e...`: release commit/tag [`v0.9.46`](https://github.com/agenticmail/agenticmail/releases/tag/v0.9.46), bumping API `0.9.31→0.9.32` and Core `0.9.9→0.9.10`. Every origin and atomic patch commit above is its ancestor.
- [`6c70c8254c906f823392d7f5ccee88a5481e7731`](https://github.com/agenticmail/agenticmail/commit/6c70c8254c906f823392d7f5ccee88a5481e7731), parent `75e72238a407ad3312ae82126c8b9848aee235d0`: release/tag `v0.9.49`, Core `0.9.13`, retaining verification for remote hosts but defaulting it off for localhost, `::1`, `127/8`, and `*.localhost`.

## Row-level adjudication

### 1. Inactive-agent hours — NARROW / REJECT

The root public state parses the caller value with `parseInt`, applies `Math.max(..., 1)`, and only then interpolates the resulting JavaScript number into a SQLite datetime modifier. `de3a5c45` replaces this with a positive-safe-integer parser and a bound parameter for both list and cleanup routes.

This is exact same-line hardening and is present in `@agenticmail/api@0.9.32`. However, the pre-fix conversion prevents SQL syntax characters from surviving into the query; this audit did not demonstrate SQL injection or another concrete exploit from this path. The first-party advisory labels it input validation, not a separate SQL-injection mechanism. Preserve as **NARROW hardening**, not a standalone publication component. Its public origin is human/no-marker, so it is also **REJECT** for strict AI causality.

### 2. Storage identifier and clause injection — PASS lineage, REJECT admission

`876cf485` creates the storage tool with caller-controlled identifiers in DDL/DML; `255d3e1c` expands it with raw where keys, selection/conflict/index identifiers and `HAVING ${having}`. Both are direct Ope-authored commits without AI trailers. `de3a5c45` adds the identifier allowlist and safe builders across the surface, but its own diff still contains raw `HAVING ${having}`. `1408de54` explicitly identifies and closes that missed vector before merge.

Release containment is exact: npm API 0.9.31 has gitHead `c7f82ecbc7981d0f8a7ee6245d5757c064a8daf1` and contains `GROUP BY ${groupBy.replace...}` plus `HAVING ${having}` in `dist/index.js`; API 0.9.32 has gitHead `8cb053f2...` and contains `buildGroupBy`, `sanitizeHavingClause`, and the validated account parser. Registry publish times are 2026-05-18 14:39:12Z and 19:47:43Z respectively.

Verdict: **PASS** exact mechanism/fix/released reversal, but **REJECT** as an AI-origin row. The `de3a5c45→1408de54` gap is an exact incomplete remediation, yet it never shipped: both commits were private-branch ancestors folded into `234b811e` before v0.9.46. Even if future first-party evidence established that `Moltbot` was a model, this would remain only **NARROW unreleased incomplete-remediation evidence**, not a released incomplete-remediation row.

### 3. Raw-SQL cross-agent and metadata access — PASS lineage, REJECT admission

`255d3e1c` introduces `/storage/sql` with a regex that admits any `agt_*`/`shared_*` table and explicitly permits `agenticmail_storage_meta`; it does not resolve table ownership. `de3a5c45` adds `verifySqlAccess`, metadata-backed ownership checks, blocks direct metadata-table access, and applies the check to `/storage/explain`. Its anchored extractor sees only the first table after `FROM`/`JOIN`, so `FROM agt_mine, agt_victim` leaves the victim unchecked. `1408de54` adds a backstop for every `agt_*`, `shared_*`, or metadata token.

API 0.9.31 contains the weak scanner; API 0.9.32 contains the exact `Direct SQL access to storage metadata is not allowed` closure. Verdict: **PASS** mechanism/fix/release, **REJECT** strict AI-origin because `255d3e1c` is human/no-marker, and **NARROW** only for the unshipped first-fix gap.

### 4. Hardcoded outbound secret — BLOCKED npm containment / REJECT

The root commit ships `OUTBOUND_SECRET = "outbound_2sabi_secret_key"` in worker metadata and the identical fallback in `outbound.js`. `41dd8153` removes both and returns HTTP 500 when no configured secret exists. Tag `v0.9.45` (`c7f82ecb...`) contains both literals; tag `v0.9.46` (`8cb053f2...`) contains neither. This is a direct source-release reversal.

The advisory maps this mechanism to `@agenticmail/core`, but Core's package manifest publishes only `dist`, README, REFERENCE, and LICENSE; tsup's sole entry is `src/index.ts`. Neither `packages/core/src/gateway/workers/outbound.js` nor `metadata.json` appears in Core 0.9.9/0.9.10 npm tarballs, and the literal is absent from both tarballs. Thus npm proves tag/gitHead provenance but not delivery or containment of this worker source. Verdict: **BLOCKED** for a claim that npm Core 0.9.10 contains the worker fix; **PASS** only for tagged source containment; **REJECT** strict AI origin because the vulnerable source is root human/no-marker.

### 5. SMTP envelope/header injection — BLOCKED npm containment / REJECT

The root worker concatenates caller-controlled `from`, recipients, subject, reply/in-reply/reference values into message headers and `MAIL FROM`/`RCPT TO` commands without control-character validation. `41dd8153` adds `CONTROL_CHARS`, `assertHeaderValue`, and `assertEnvelopeAddress`, applying them before both raw-message and SMTP-command construction.

This is the same source-tag containment boundary as row 4: fixed in the v0.9.46 source tree, but the changed worker is not in the `@agenticmail/core` npm artifact named by the advisory. Verdict: **BLOCKED** npm-package containment, source-tag **PASS**, and **REJECT** strict AI origin. It is a distinct mechanism from the hardcoded secret despite sharing one file and one fix commit; it must not become a second public ID.

### 6. MailSender TLS verification — PASS remote / NARROW / REJECT

The root public file sets `rejectUnauthorized: false`; blame remains on `cf35e22f` through the patch base. `41dd8153` introduces an explicit option and defaults it to true. Unlike the worker files, `MailSender` is bundled: Core 0.9.9's `dist/index.{js,cjs}` contains `rejectUnauthorized: false`; Core 0.9.10 contains `options.tlsRejectUnauthorized ?? true`. Both tarballs have exact gitHeads `c7f82ecb...` and `8cb053f2...` and publish times 14:39:08Z and 19:47:36Z.

Five hours later, `6c70c825`/Core 0.9.13 changes the default to false for loopback hosts while keeping remote verification on and preserving explicit override. The current checked-out source retains that resolver. Therefore the durable claim is narrow: **PASS** released containment for remote SMTP hosts; **NARROW** rather than “certificate verification always defaults on”; **REJECT** strict AI origin because the disabling line originates in root human/no-marker code.

## Duplicate and non-causal controls

- The alias class is exactly `{GHSA-WJJV-3MJ2-39HF, CVE-2026-47255}`. Mechanism splitting must not multiply its public-ID count.
- Storage SQL injection and raw-SQL ownership are separate invariants, but `de3a5c45`/`1408de54` are one patch chain. The maintainer follow-ups are not new advisories.
- Hardcoded secret and SMTP control injection share `outbound.js` and `41dd8153`, but have different attacker input/invariant/effect. Retain both as mechanism controls, with the same npm-containment blocker.
- The prior feature-review packet routed Claude-coauthored `bceedece22678715e117bbc48ba374e5b86403b7` to `8cb053f2`/`6c70c825`. Its own packet says `exact_blame_hit=false`, `blamed_paths=[]`, and overlap only in release/package manifests (`agenticmail/package.json`, `packages/claudecode/package.json`). It does not modify any vulnerable or fixing path and is **REJECT adjacent/package-only routing**.
- Every exact public origin here is `cf35e22f`, `876cf485`, or `255d3e1c`. Ancestry from later Claude-coauthored commits to a release/fix, same-file package overlap, and an AI ratio in a routing artifact do not replace direct blame/delta evidence.
- The two `Moltbot` patch commits are **UNKNOWN AI attribution**, not direct model evidence. The commits have no trailers, no mapped GitHub author, and are unsigned; the advisory attributes the patch to a human GitHub account. No AI-remediation claim is promoted.

## Prior work explicitly excluded

This pass reopened only the previously `UNKNOWN aggregate_unsplit` WJJV row from the frozen prior background report. It did not redo the three already adjudicated AgenticMail negative controls (GHSA-63GR-G7JC-V8RG, GHSA-FQ4X-789W-JG5H, GHSA-HJWC-26PJ-V3PM), the n8n-mcp positive rows, OpenClaw, Coolify, or any accepted/rejected ledger row. No discovery search, build, test suite, exploit run, clone, fetch, tag mutation, or cache write was performed.

## Exact primary-source commands

All Git reads used the required GC/maintenance disables. `$repo` below is the pre-existing read-only AgenticMail clone; no command fetched or wrote objects.

```zsh
cd /home/hanqing/agents/ai-slop
repo=.ai-slop/cache/cve-analyzer/repos/v2_github.com_agenticmail_6f99dfe6a0084582112588e82224a010cafaa5f1b8095765e41aad971196cf49

# Snapshot and local official inputs.
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" rev-parse HEAD
git -c gc.auto=0 -c maintenance.auto=false -C /home/hanqing/.cache/cve-analyzer/advisory-database rev-parse HEAD
sha256sum \
  /home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/05/GHSA-wjjv-3mj2-39hf/GHSA-wjjv-3mj2-39hf.json \
  autoresearch/herdr-260812-mcp-js-ecosystem/background_findings.md \
  autoresearch/orchestrator-260811-atomic150/global-feature-review-packets-v6/agenticmail/packets.jsonl

# Public patch topology, identities, parents, authors, dates and trailers.
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" merge-base 10cde1ee1bef69139ce50a795fd5380e0c626249 1408de543fa3577d8c2d4fdb289c75fe6faafac7
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" log --reverse \
  --format='%H|%P|%aI|%an <%ae>|%s' \
  10cde1ee1bef69139ce50a795fd5380e0c626249..1408de543fa3577d8c2d4fdb289c75fe6faafac7
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" show -s \
  --format='commit=%H%nparents=%P%nauthor=%an <%ae>%nauthor_date=%aI%ncommitter_date=%cI%nsubject=%s%ntrailers=%(trailers:only)' \
  cf35e22fbfaa99725245505008e9de7a7c71ed02 \
  876cf485e41b239cdbc5b69308f60e4f2c420cea \
  255d3e1ca306ae720e7df7909a2582d7a7240b65 \
  de3a5c4519f65c76b9f7d9fb5df2bc788e2dcf61 \
  41dd8153809cabbc9b79aba1b726266af923a1b7 \
  1408de543fa3577d8c2d4fdb289c75fe6faafac7 \
  234b811e426a0743170f3b10bc43419d64330155 \
  8cb053f2307dd77b7736ffa0d7df04b0ccc3272d \
  6c70c8254c906f823392d7f5ccee88a5481e7731
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" rev-parse \
  '1408de543fa3577d8c2d4fdb289c75fe6faafac7^{tree}' \
  '234b811e426a0743170f3b10bc43419d64330155^{tree}'
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" diff --quiet \
  1408de543fa3577d8c2d4fdb289c75fe6faafac7 \
  234b811e426a0743170f3b10bc43419d64330155

# Direct deltas and exact line origins.
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" show --no-ext-diff --unified=8 \
  de3a5c4519f65c76b9f7d9fb5df2bc788e2dcf61 -- \
  packages/api/src/routes/accounts.ts packages/api/src/routes/storage.ts
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" show --no-ext-diff --unified=8 \
  41dd8153809cabbc9b79aba1b726266af923a1b7 -- \
  packages/core/src/gateway/workers/metadata.json \
  packages/core/src/gateway/workers/outbound.js packages/core/src/mail/sender.ts
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" show --no-ext-diff --unified=8 \
  1408de543fa3577d8c2d4fdb289c75fe6faafac7 -- packages/api/src/routes/storage.ts
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" blame -l -L 200,230 \
  10cde1ee1bef69139ce50a795fd5380e0c626249 -- packages/api/src/routes/accounts.ts
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" blame -l -L 110,155 \
  10cde1ee1bef69139ce50a795fd5380e0c626249 -- packages/api/src/routes/storage.ts
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" blame -l -L 810,840 \
  10cde1ee1bef69139ce50a795fd5380e0c626249 -- packages/api/src/routes/storage.ts
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" blame -l -L 1120,1160 \
  10cde1ee1bef69139ce50a795fd5380e0c626249 -- packages/api/src/routes/storage.ts
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" blame -l -L 1,10 \
  10cde1ee1bef69139ce50a795fd5380e0c626249 -- packages/core/src/gateway/workers/metadata.json
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" blame -l -L 238,260 \
  10cde1ee1bef69139ce50a795fd5380e0c626249 -- packages/core/src/gateway/workers/outbound.js
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" blame -l -L 24,42 \
  10cde1ee1bef69139ce50a795fd5380e0c626249 -- packages/core/src/mail/sender.ts

# Release/tag and artifact boundaries.
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" rev-parse \
  'v0.9.45^{}' 'v0.9.46^{}' 'v0.9.49^{}'
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" grep -n \
  'outbound_2sabi_secret_key' v0.9.45 -- \
  packages/core/src/gateway/workers/metadata.json \
  packages/core/src/gateway/workers/outbound.js
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" grep -n -E \
  'resolveTlsRejectUnauthorized|rejectUnauthorized:' HEAD -- packages/core/src/mail/sender.ts

# Live first-party advisory/commit/release sources. No token/header is printed.
gh api repos/agenticmail/agenticmail/security-advisories/GHSA-wjjv-3mj2-39hf
gh api repos/agenticmail/agenticmail/security-advisories/GHSA-wjjv-3mj2-39hf | sha256sum
gh api repos/agenticmail/agenticmail/commits/de3a5c4519f65c76b9f7d9fb5df2bc788e2dcf61
gh api repos/agenticmail/agenticmail/commits/41dd8153809cabbc9b79aba1b726266af923a1b7
gh api repos/agenticmail/agenticmail/releases/tags/v0.9.46

# npm metadata, gitHeads, publish times, integrity and tarball hashes.
curl -fsSL https://registry.npmjs.org/%40agenticmail%2Fapi | jq \
  '{times:{old:.time["0.9.31"],fixed:.time["0.9.32"]},old:.versions["0.9.31"],fixed:.versions["0.9.32"]}'
curl -fsSL https://registry.npmjs.org/%40agenticmail%2Fcore | jq \
  '{times:{old:.time["0.9.9"],fixed:.time["0.9.10"],followup:.time["0.9.13"]},old:.versions["0.9.9"],fixed:.versions["0.9.10"],followup:.versions["0.9.13"]}'
curl -fsSL https://registry.npmjs.org/@agenticmail/api/-/api-0.9.31.tgz | sha256sum
curl -fsSL https://registry.npmjs.org/@agenticmail/api/-/api-0.9.32.tgz | sha256sum
curl -fsSL https://registry.npmjs.org/@agenticmail/core/-/core-0.9.9.tgz | sha256sum
curl -fsSL https://registry.npmjs.org/@agenticmail/core/-/core-0.9.10.tgz | sha256sum
curl -fsSL https://registry.npmjs.org/@agenticmail/core/-/core-0.9.13.tgz | sha256sum
curl -fsSL https://registry.npmjs.org/@agenticmail/core/-/core-0.9.10.tgz | tar -tzf -
```

Primary URLs used directly:

- Advisory API: `https://api.github.com/repos/agenticmail/agenticmail/security-advisories/GHSA-wjjv-3mj2-39hf`
- Advisory page: `https://github.com/agenticmail/agenticmail/security/advisories/GHSA-wjjv-3mj2-39hf`
- Release: `https://github.com/agenticmail/agenticmail/releases/tag/v0.9.46`
- npm registry metadata: `https://registry.npmjs.org/%40agenticmail%2Fapi` and `https://registry.npmjs.org/%40agenticmail%2Fcore`

## Claim boundary

- The public DAG, direct deltas, advisory identity, and API tarball transitions close mechanisms 2 and 3 and the remote-host portion of mechanism 6. They do not supply AI origin for the vulnerable lines.
- The account-hours change is real hardening but not a demonstrated standalone exploitable vulnerability in this audit.
- The worker fixes are present in tagged source, not in the affected/fixed npm Core tarballs. Do not claim npm artifact containment for mechanisms 4 or 5 without a separate first-party deployment artifact.
- `Moltbot` author metadata is not enough to name a model or assert AI agency. Even an eventual positive attribution would leave both partial storage patches unreleased before the human hardening commit.
- `6c70c825` is a compatibility narrowing, not a full TLS regression: remote hosts still verify by default; loopback hosts do not.
- Advisory identity and ancestry are routing/containment evidence. Publication-grade causal attribution requires the exact origin delta and direct attribution; all public origins here are human/no-marker or root-history-blocked. Therefore this shard contributes negative and narrow controls, not a positive AI-causal row.
