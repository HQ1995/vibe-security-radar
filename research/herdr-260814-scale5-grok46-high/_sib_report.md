# Direct-root slice 1 adjudication

## Verdict first

All 25 assigned `dr-slice-1` rows are terminal and non-countable. This packet proposes zero `AI_DIRECT_ROOT` / `AI_NEW_SURFACE_CONTRIBUTOR` admissions. Nine rows are `FALSE_POSITIVE` with class `wrong_edge`. Sixteen rows are `UNKNOWN` because blobless ancestor diffs were not available and missing hunk evidence is not converted into `FAIL`.

- FALSE_POSITIVE / wrong_edge: 9
- UNKNOWN (unclosed hunk comparison): 16
- Countable proposals: 0
- GitHub API used: no; owned directory only; no commits or ledger edits

## Method

Each row was checked against the local first-party GHSA JSON (lowercase advisory path under the worker clones) and against ancestor/fix commit objects in `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`. `git show`/`diff-tree` under `GIT_NO_LAZY_FETCH=1` failed to materialize parent blobs for several ancestors. Per DR-SPEC and CONTRACT, unclosable gates stay `UNKNOWN`. `FALSE_POSITIVE` is used only where overlap files are tests, docs, release metadata, or the assigned AI commit is the named closer with no remaining production hunk. CI/workflow security rows stay UNKNOWN unless the ancestor hunk was compared.

## Per-row

| case_id | verdict | class | I/A/T/B/F/R/U | why |
| --- | --- | --- | --- | --- |
| `GHSA-C2J3-45GR-MQC4` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap includes dist/purify.cjs.js plus CI/README from a 3.4.2 sync. Blobless ancestor diff failed (promisor fetch), so the purify bundle hunk was not compared to the 3.4.12 close |
| `GHSA-JFWG-RXF3-P7R9` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Ancestor is a large v2 rewrite; overlap is Cassandra storage production files. Closer is CQL/N1QL parameterization. Ancestor blob diff failed; cannot prove introducing vs incidenta |
| `GHSA-9Q5R-WFVF-RR7F` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap is production Earley/grammar C++ sources. Ancestor is a JSON serializer/MemorySize refactor; blob diff failed so the CVE hunk vs closer #368 was not compared. |
| `GHSA-FC6G-2GCP-2QRQ` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap is rustfs admin auth/policy/handler sources. Ancestor is a GetMetrics panic guard (Copilot-marked) while closer is aws:SourceIp policy evaluation. Hunk comparison failed. |
| `GHSA-2QVQ-RJWJ-GVW9` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: ancestor is CLI unit-test chore; overlap is spec/expected fixtures only, not template compiler hunks. |
| `GHSA-2W6W-674Q-4C4Q` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: same handlebars CLI test ancestor; overlap is spec/expected fixtures only. |
| `GHSA-3MFM-83XF-C92R` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: same handlebars CLI test ancestor; overlap is spec/expected fixtures only. |
| `GHSA-442J-39WM-28R2` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: same handlebars CLI test ancestor; overlap is spec/expected fixtures only. |
| `GHSA-9CX6-37PM-9JFF` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: same handlebars CLI test ancestor; overlap is spec/expected fixtures only. |
| `GHSA-XHPV-HC6G-R9C6` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: same handlebars CLI test ancestor; overlap is spec/expected fixtures only. |
| `GHSA-XJPJ-3MR7-GCPF` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: same handlebars CLI test ancestor; overlap is spec/expected fixtures only. |
| `GHSA-4GGG-H7PH-26QR` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap includes src/http-server-single-session.ts plus dist/changelog. Ancestor is a CodeQL-alert security pass; blob diff failed so it is not proved as introducing, new surface,  |
| `GHSA-C29Q-5XM7-5P62` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap includes AbstractEmbedService.php / factory (production embed URL surface) plus tests. Feature ancestor adding music services may have rewritten embed parsing; hunk vs clos |
| `GHSA-X44P-GVRJ-PJ2R` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap includes S3EncryptionClient and keyring/pipeline production Java. reEncryptInstructionFile feature may have rewritten crypto metadata handling; blob diff failed. |
| `GHSA-XW7X-H9FJ-P2C7` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: ancestor is release-prep 2.26.0; overlap is CHANGELOG/README/apidiff/examples/version files, not instrumentation sinks. |
| `GHSA-J6V5-G24H-VG4J` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap includes engine.go/options.go plus bytecode persist/tests. Bytecode serialization feature may have rewritten engine security boundary; hunk comparison failed. |
| `GHSA-X3F4-V83F-7WP2` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Same authorizer v2 ancestor as JFWG, but overlap is GraphQL/HTTP auth handlers and URL validator. Closer 6d9bef1 is a different SHA than JFWG. Production overlap without hunk proof |
| `GHSA-PR33-38XX-6R26` | `FALSE_POSITIVE` | `wrong_edge` | U/F/P/F/F/F/U | wrong_edge: ai_ancestor equals the named fix_ref (cookie storage closer), so the AI commit is the reversal rather than an introducing hunk. |
| `GHSA-Q58J-G3F4-H26H` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Assigned AI ancestor is a pull_request_target workflow-injection closer overlapping CI YAML. Blobless ancestor diff was not compared, so this is not converted to FAIL/wrong_edge |
| `GHSA-Q938-GHWV-8GVC` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap includes src/Functions.php plus Stripe tests/changelog. Stripe-pay feature may have rewritten callback/webhook verification; blob diff failed. |
| `GHSA-G754-HX8W-X2G6` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap is production http3 conn/headers/server/stream. Ancestor is qpack v0.6.0 bump that rewrote those files; hunk vs closer 5b2d2129 was not compared. |
| `GHSA-56F2-HVWG-5743` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap is Slack/web media download code. Ancestor is itself a security cap/validate patch, while closer is a later SHA 81c68f58. Could be incomplete rem, sibling path, or unrelate |
| `GHSA-WFP2-V9C7-FH79` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Same openclaw media ancestor/closer pair as 56F2 on a second GHSA identity. Patch-delta and identity uniqueness vs 56F2 not closed from first-party JSON in this pass. |
| `GHSA-H395-GR6Q-CPJC` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Overlap includes src/validation.rs and errors.rs. Crypto-backend decoupling may have rewritten JWT validation; blob diff failed so introducing hunk is unproved. |
| `GHSA-2CF7-HPWF-47H9` | `UNKNOWN` | `UNCLOSED_HUNK_COMPARISON` | U/U/P/U/U/U/U | Subject is docs, but overlap includes src/mcp/handlers-n8n-manager.ts (production). Hunk vs closer c1ca1e73 was not compared; missing evidence is not converted to FAIL. |

## Notes on clustered edges

- Seven handlebars GHSAs share ancestor `80c4516fdad5d8fcb6e24faca51db97bd6cc94c5` (CLI unit tests) and closer `68d8df5a88e0a26fe9e6084c5c6aaebe67b07da2`. Overlap is `spec/expected/*` fixtures only.
- Two authorizer GHSAs share ancestor `30d5459a09b1152c8a2e4689599b53475d53a024` (v2 rewrite) but different closers and overlap sets; both stay UNKNOWN.
- Two openclaw GHSAs share ancestor `4e4ed2ea1793340a9c8d707f3024143ea8f68f4e` (Slack media security cap) and closer `81c68f582d4a9a20d9cca9f367d2da9edc5a65ae`. Incomplete-remediation is not claimed without a closed patch-delta.
- http4k `GHSA-PR33-38XX-6R26` assigns the cookie-storage commit as both `ai_ancestor` and `fix_ref`.

## Evidence paths

- Spec: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md`
- Slice: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-1.jsonl`
- Contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`
- Truth layers: `docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md`
- Advisory clones: `/home/hanqing/.cache/ghsa200-worker-clones/*/advisory-database`
- Commit pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`

## Constraints kept

Owned directory only. No GitHub API, no commits, no ledger/web/scripts edits. English only. Worker PASS is a proposal; this packet emits none. Greater-than-200 remains unsupported.

