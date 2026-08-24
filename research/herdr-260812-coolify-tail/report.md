# Coolify-only unexamined tail

## Result

**COMPLETE for the bounded shard: 11 public components / 12 AI candidate edges were deeply adjudicated; 0 new claim-grade positives survived and all 11 component rows are strong `FAIL` controls.** The remaining unassessed history stays `UNKNOWN`. The newest summary's unnamed “other 12 Coolify items” cannot be mapped to SHAs and is preserved as `BLOCKED` rather than treated as a new count.

## Scope and immutable boundary

- Run interval: `2026-08-12T12:18:00-04:00` through the terminal-artifact time recorded in `result.json`.
- Shared checkout: `/home/hanqing/agents/ai-slop`, branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`. It was intentionally dirty and read only.
- First-party Coolify clone: `/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify`, clean HEAD `098d3d4c253a5a79aa8d166854a1b0a202077259`; heads/tags digest `315a86ad9900551d600e2e21b96a923bc52c5b9983d4ec2af661a8d94f30e373`.
- Local CVEList V5 clone: clean HEAD `8ca64b5ad6b84d3cd5741b023610b8494800f174`.
- Each shared input in `exclusion_manifest.json` is bound independently by relative path, byte size, `mtime_ns`, and SHA-256. This is a stable-read set, not an atomic filesystem snapshot; any later edits by other agents are outside the evidence boundary.
- Writes were confined to `autoresearch/herdr-260812-coolify-tail/`. No cache, clone, existing Coolify witness, ledger, or other shared path was mutated. No build or broad rerun was performed.

## Inputs and hashes

The machine-readable manifest is the complete inventory. Its SHA-256 is `34ec71dda6ab1522ce57d796ce8a612818db9a6ee634718e8f3d354b33b1a8a3`.

| Input | Rows/files | SHA-256 |
|---|---:|---|
| All manifest-bound inputs | 214 | per-file hashes in `exclusion_manifest.json` |
| Latest v41 Coolify adjudication ledger | 22,634 edges | `453a64eb9701fc3e058b35c87f80a3d4c7d066d970c9f6bb5629c632084229a3` |
| Latest v2 Coolify fix-preimage lineage | frozen artifact | `9cb3abbf42e56703030ad045ae3a0a77dd61a1541f819c49b46c7fcc85055787` |
| Frozen Coolify AI commit inventory | 556 commits | `aa873c464200eda94e59e31d10e8a4d4dea47dfd995dab06624e258349fcf8fc` |
| Global v9 Coolify fix roots | 42 rows | `693451af3305f8a7fb0e9cfda9c273dfbdcb2b953d8fb774042b9721884964ba` |
| Global v9 exact-direct candidates | 48 rows | `61f4b6a58988cf1883b3bd545abc96cc05e5f69f5863173a339b7acbd824a320` |
| Global v9 feature-review packets | 31 packets | `4b5f4f7d2afb6ccc0eb06346e9a349cac3b33e74b0decfb16dc6d265e7cd706f` |
| Strict 200 v3 terminal ledger | 200 components | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| Eleven frozen first-party CNA objects used for selected rows | 11 | aggregate `7d933708d5e65e1aee8684905c59267b863eb4866648da310dd579cce12c9680` |
| Bounded beta.474 deleted-line owner screen | 10 fixes | `7484c15ab1841d88d3a6b42c53f9f299abe5e9fc057b00157682bf42f0f94a05` |

The 214 inputs comprise 9 current docs, 18 Coolify-relevant autoresearch Markdown files, 88 Coolify workflow/case files, 79 tests, 15 current v9 Coolify candidate artifacts, four canonical state artifacts, and the strict-200-v3 ledger.

## Exclusion manifest

The manifest was built before candidate promotion and deliberately separates hard exclusions from diagnostic mentions:

| Exclusion class | Count | Rule |
|---|---:|---|
| Terminal candidate/fix edges | 201 | Existing `PASS`, alias, or rejected terminal pair; do not re-adjudicate the same edge. |
| SHAs in terminal edges | 299 | Scheduling exclusion only when the exact terminal edge/component matches. |
| Terminal mechanism/component groups | 168 | Component-level deduplication. |
| Current accepted/adjudicated Coolify components | 9 | CVE-2026-32718, 34049, 34050, 34149, 34167 (commit-only), 34198, 34599, 42148, and 42204. |
| Nonterminal v41 edges | 22,441 | Still eligible; remain `UNKNOWN` unless reviewed row by row. |
| Full SHAs merely mentioned | 1,891 | Diagnostic seen-set, **not** automatic exclusion. |
| Public IDs merely mentioned | 498 | Diagnostic seen-set, **not** automatic exclusion. |

This corrects two stale intermediate labels: the later `RESEARCH-NEEDS-REVIEW-CLOSURE` and strict-200-v3 artifacts make CVE-2026-34050 (`acff543e... -> 0fed5532...`) and CVE-2026-34149 (`473c3227... -> 99043600...`) existing `PASS` exclusions. The newest explicit Coolify closures CVE-2026-34198, CVE-2026-42204, and commit-only CVE-2026-34167 were also excluded. Existing volume (`d2064dd4... -> 410a9a61...`) and resource-scope (`e36622fd... -> a478ac66...`) terminal components were not recounted.

The 88 source/case files cover 78 named Coolify mechanisms/workflows and 10 case/control manifests; all 79 matching tests were included as contract evidence, not independent causal rows. Exact paths, hashes, extracted SHAs, terminal edges, and all 168 mechanism names are in `exclusion_manifest.json`.

## Selected 11-row adjudication

All twelve candidate commits have direct commit-level Claude attribution in the frozen 556-row inventory, and every candidate is an ancestor of its repair. Those facts establish AI association and topology only. Each verdict below uses the candidate's direct parent, candidate delta, exact public repair delta/member, first-party advisory identity, first-containing tags, and component deduplication.

| # | First-party component | Candidate / repair | Direct parent and same-mechanism assessment | Release boundary | Verdict |
|---:|---|---|---|---|---|
| 1 | CVE-2026-34153 / GHSA-46hp-7m8g-7622 | `20b428891673... -> 3fdce06b654f...` | Candidate only replaces Docker image digest parsing. Parent and candidate do not add the `mount_path -> LocalFileVolume.fs_path -> shell` path; repair validates/escapes file-storage paths. Same controller, different field and sink. | beta.435 -> beta.471 | `FAIL_WRONG_FIELD_SHARED_CONTROLLER` |
| 2 | CVE-2026-42147 / GHSA-pwm4-w33c-wjf3 | `5e90fc6b8f12... -> 297e9c41e199...` | Strong same-field control: candidate trims S3 endpoint/credentials, but its parent already accepts and uses attacker-controlled endpoints. Repair adds `SafeWebhookUrl` and IPv6-loopback normalization. Removing the candidate leaves SSRF reachable. | beta.455 -> beta.474 | `FAIL_NONCAUSAL_NORMALIZATION` |
| 3 | CVE-2026-42201 / GHSA-f35h-g2c2-q36v | `3d1b9f53a0ae... -> 03313e54cc79...` | Candidate validates Docker **network names**. Repair validates database identifiers/passwords interpolated into Compose commands. Shared helper file, different inputs and mechanism. | beta.471 -> beta.474 | `FAIL_DIFFERENT_FIELD_SHARED_HELPER` |
| 4 | CVE-2026-34599 / GHSA-q9j6-xcvx-px63 | `a0884b758f4d... -> 48ba4ece3c1b...`; unrelated control `b33962bf8202...` | Candidate changes an early return so service logs auto-load, while its parent already exposes mutable `$container` and client-callable `getLogs()` shell interpolation; deleting it leaves the sink reachable. The second candidate changes only an import in `User.php`. | beta.453 / beta.461 -> beta.471 | `FAIL_NON_NECESSARY_LIFECYCLE`; existing `bbb2aa9a...` PASS owns the component |
| 5 | CVE-2026-34152 / GHSA-5qp8-9gg7-4c86 | `d59c75c2b23d... -> 6f163ddf0299...` | Candidate adds Compose build-ARG handling. Parent already has distinct pre/post-deployment heredoc transport; repair normalizes CR/LF only in those commands. | beta.453 -> beta.471 | `FAIL_DIFFERENT_COMMAND_PATH` |
| 6 | CVE-2026-34057 / GHSA-6r3g-w7x8-54fj | `cc96403cbe50... -> d486bf09ab2d...` | Candidate adds password-confirmation arguments/returns to existing restore methods. Parent already has hydratable server/container properties and the command path; repair locks/scopes/validates them. | beta.465 -> beta.471 | `FAIL_MODAL_FLOW_PRESERVATION`; consistent with the later closure's FAIL for prior candidates |
| 7 | CVE-2026-59734 / GHSA-4fhp-xqqp-w7vv | `837391c31b18... -> 0ffcee7a4dcd...` | Candidate changes Docker build-cache ARG/SOURCE_COMMIT behavior, not `generate_healthcheck_commands()` or its method/host/path values. Repair validates/escapes that distinct function. | beta.450 -> beta.469 | `FAIL_DIFFERENT_FUNCTION_IN_LARGE_JOB` |
| 8 | CVE-2026-42204 / GHSA-chg4-63hm-xv9x | `bf503861fcb6... -> 817128c5affa...` | Strong temporal control: candidate renders build args in a preview getter in beta.453. The permissive shell rule is introduced later by already-counted `c9922c30...` in beta.471; repair tokenizes that rule. | beta.453; affected interval starts beta.471; fixed beta.474 | `FAIL_PREVIEW_ONLY_TEMPORAL_CONTROL`; existing component owns the count |
| 9 | CVE-2026-42172 / GHSA-c83f-5ph7-x8xv | `729c891542df... -> 90ddbb357231...` | Candidate adds a placeholder Webhook notification channel; it does not create, persist, authenticate, or expire Sanctum tokens. Repair adds expiry and warning jobs/UI. | beta.435 -> beta.474 | `FAIL_DIFFERENT_SECURITY_DOMAIN` |
| 10 | CVE-2026-42153 / GHSA-gvc4-f276-r88p | `cbba7f0a672e... -> 64753b413640...` | Candidate adds collapsible log UI. Repair converts PostgreSQL and sibling healthchecks to CMD exec-form. No healthcheck input, command construction, or execution delta exists in the candidate. | beta.453 -> beta.474 | `FAIL_LOG_UI_DIFFERENT_SINK` |
| 11 | CVE-2026-34034 / GHSA-rpr8-p7jc-x844 | `511415770a43... -> 096d4369e59b...` | Candidate adds an image-retention field/cast/UI and never touches `sentinel_token`; repair validates/escapes that token at shell sinks. Same model, unrelated field. | beta.453 -> beta.466 | `FAIL_UNRELATED_MODEL_FIELD`; no change to existing V2 FAIL component verdict |

### Exact lineage ledger

`candidate (direct parent) -> exact repair member (direct parent)`:

```text
1  20b428891673e6e266e18c5fa55a039f9f69b71e (6d3c996ef374a8827eaf0e14318570344522420c) -> 3fdce06b654fa3b7b4be59c0faaab6b4546c78de (47668121a4031a9bd1466fa4a46292894670275c)
2  5e90fc6b8f12d51543a0520ed6e3ad42374be016 (e0b2424b7645bf67562924917b64a4e18cec233b) -> 297e9c41e19958f6237919794c28c3fb1d4cda32 (57ea0764b8f0a491fd1d30bedc5cbe281744b36c)
3  3d1b9f53a0aec74468be75675bcaaaed0fd41d46 (e39678aea584be533f89052d4e2939f2d8834449) -> 03313e54cc790f3a6df6cb4fa9274c27437083e7 (2264a2ef76f15cdc8b8cdf9f7f1bcd8e984a9280)
4a a0884b758f4d0947d7563abb1b4551ea1410a719 (21429a26b1df09bbf07dd89e26e721a8cdf19ac7) -> 48ba4ece3c1b43cb4b9627438c0ff4e4251e3511 (e39678aea584be533f89052d4e2939f2d8834449); release carrier f267a28cb2badc7e712c4592af4d79d090fe5063
4b b33962bf8202c4067bb9d91de4b6d725134dfaa5 (8d212bc11062620ed4d66fd9a41f098fe6fd9d04) -> same repair member
5  d59c75c2b23d95f2cf798d76efa4f31b6e99f611 (a56fde7f124f3da172388611911c3d16cb435f0f) -> 6f163ddf02991fb8fd8bc17fdcecddc318b813c6 (944a038349216f00b390e905c121355adc8b23c1); carrier ad95d65aca064f49b38f73f88d61f842737d5463
6  cc96403cbe50f3538ceeec88feaabe445ad5094f (9a4b4280be5ad6e238cea4ffc267d64c8cd5289a) -> d486bf09ab2da8ad78fa721a079f066c76ce08d2 (0fed553207383f384b93cba24d28122065fa67d5)
7  837391c31b18dcf30ec22b32d248d545fb7723bf (4e896cca05a3a8d89344645316518253a19b31b8) -> 0ffcee7a4dcd24f92b5fab8c9c7be140b9532733 (38df6867183df6b4b7b6ee531a336812a1085a6c)
8  bf503861fcb68aec1074a2b391456404fc1068cd (d59c75c2b23d95f2cf798d76efa4f31b6e99f611) -> 817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1 (1cf6c7d0aef8e0edb800ae43f44ded102397cb13); carrier e1aac50b745cf499e710b7e35cd2a9d6a1538dd9
9  729c891542df36eae5d957190fa570a6a87ca4a0 (22153c419d4a07e96336ae34a6457b477f60f19e) -> 90ddbb357231ca3808f277eb87a63c8f650417e6 (bff6d853708f3d7c861279586f107739036e67da); carrier b1a78df58efe3ac38679d18c888b5817c7f01216
10 cbba7f0a672eb982e2455c0582c90e0714cdecf9 (9e0fa03434d3662d1b55dde264e09361e01082fe) -> 64753b41364010f5e8d539194a567feea1d1d520 (245c6a18c8779c0434451e5bc9da801348cc5a24); carrier b74f54302b1a857c22c55fe1210d700859b0b3df
11 511415770a43389391802a9d5f7e284624e9b738 (0cc59739015732baa25593860164c90eae0d0bef) -> 096d4369e59b3db7ace2db3ca42588c41b9b6019 (6fbb5e626a82c576ae7a1a08b4e1d16aee2e82ed)
```

Rows 2, 4, and 8 are the strongest negative controls: same attacker-controlled field but noncausal normalization; same vulnerable method but non-necessary lifecycle behavior; and a nearby preview change that predates the actual regression. They show why ancestry, file overlap, release overlap, or an AI trailer cannot replace a same-mechanism reversal.

## Corroborating beta.474 preimage screen

`preimage_candidates.json` examined exact deleted-line owners for ten additional beta.474 security members. Only 3/10 fixes had any AI-owned deleted line (five observations total): webhook null-secret handling, volume validation, and S3 SSRF. Row-level inspection resolved those observations to an advisory-scope mismatch, already-terminal volume components, unchanged legacy-binding validation, or the already-rejected webhook-vs-S3 component mismatch. This screen is diagnostic and contributes no new positive.

## Exact commands and sources

```zsh
# Snapshot and complete exclusion manifest.
git -C /home/hanqing/agents/ai-slop rev-parse HEAD
git -C /home/hanqing/agents/ai-slop status --short --branch
python3 autoresearch/herdr-260812-coolify-tail/build_exclusion_manifest.py \
  --root /home/hanqing/agents/ai-slop \
  --output /home/hanqing/agents/ai-slop/autoresearch/herdr-260812-coolify-tail/exclusion_manifest.json \
  --snapshot-at 2026-08-12T12:18:00-04:00

# Bounded exact deleted-line screen; no clone mutation.
python3 autoresearch/herdr-260812-coolify-tail/inspect_fix_preimages.py \
  --repository /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify \
  --ai-scan /home/hanqing/agents/ai-slop/.ai-slop/state/cohort-v1/ai-commit-scan-coolify-20260801-v4/commits.jsonl \
  --output /home/hanqing/agents/ai-slop/autoresearch/herdr-260812-coolify-tail/preimage_candidates.json

# Candidate topology, direct parents, repair members, and release containment.
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify merge-base --is-ancestor <candidate> <fix>
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify rev-parse '<candidate>^' '<fix>^'
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify diff '<candidate>^' <candidate> -- <advisory-paths>
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify diff '<fix>^' <fix> -- <advisory-paths>
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify tag --contains <sha> 'v4.0.0-beta.*' | sort -V | head -1

# Frozen first-party CNA identity, affected ranges, advisory URL, and exact fix references.
jq '{id:.cveMetadata.cveId,state:.cveMetadata.state,title:.containers.cna.title,
     affected:.containers.cna.affected,references:.containers.cna.references}' \
  /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/{34xxx,42xxx,59xxx}/CVE-*.json

# A live first-party advisory listing was used only to bound the beta.474 selector;
# it was not persisted and is not claim-bearing evidence.
gh api 'repos/coollabsio/coolify/security-advisories?per_page=100'
```

The primary identities are the eleven local published CNA objects and their `https://github.com/coollabsio/coolify/security/advisories/GHSA-...` references. Individual CNA paths and SHA-256 values are preserved in `subresearch.md`; the aggregate is recorded above.

## Negative, unknown, and blocked results

- `FAIL`: 11/11 selected public components (12 candidate edges); each failure is based on direct parent/candidate/fix deltas, not a model vote.
- New claim-grade `PASS`: 0.
- `UNKNOWN`: the unassessed portion of 556 AI commits x 42 fix roots and the 22,441 nonterminal v41 edges. No absence claim is made.
- `BLOCKED`: the phrase “other 12 Coolify items” in the newest summary has no row-to-SHA mapping. Prefix and full-SHA exclusion scans found no selected exact candidate pair named there, but semantic collision with an unnamed prose group cannot be disproved.
- No test/build result is presented as security proof. Candidate discovery, source recovery, blame, same-file matching, ancestry, and released tags are routing or containment evidence; only an exact parent delta plus same-mechanism repair could support a positive.

## Claim boundary

This shard found **no new publication-grade Coolify AI-origin or AI-contributor security component**. That is a result about these 11 deeply reviewed rows, not evidence that the broader Coolify history contains none. Existing positives, aliases, negatives, unresolved rows, and incomplete-remediation components remain unchanged. Publication use should refresh first-party advisory refs/tags and reuse the exact lineage ledger above; nothing in this run edits an existing witness or ledger.
