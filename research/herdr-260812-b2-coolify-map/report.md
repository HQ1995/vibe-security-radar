# Batch 2 — Coolify “other 12” mapping closure

## Result

**COMPLETE.** The newest summary phrase `Coolify 其余本轮 12 项` maps exactly to the twelve `FAIL` public-CVE rows enumerated by the immediately preceding original Coolify audit. It does not mean twelve unknown commits or twelve independent components.

- Exact mapping: **12 public rows / 11 semantic mechanisms**.
- Status normalization: **PASS 0 / REJECT 12 / NARROW annotations 3 / BLOCKED 0 / UNKNOWN 0** within the mapped set.
- Batch 1 collision: **6 public rows / 6 mechanisms**; **4 exact terminal-primary edges**, or **5 exact edges** when every candidate in the frozen diagnostic route set is included.
- Previously unnamed remainder: **6 public rows / 5 mechanisms**.
- Bounded follow-up: only the requested top three non-colliding rows were re-adjudicated. No `556 x 42` population rescan was performed.

The Batch 1 blocker is therefore closed. No Batch 1 verdict changes and no new claim-grade positive is created.

## Scope and exclusions

This run read the dirty shared checkout, completed archived audit records, the existing read-only Coolify clone, local CVEList objects, and Batch 1 artifacts. It wrote only under `autoresearch/herdr-260812-b2-coolify-map/`.

Already adjudicated rows were excluded from new deep review. In particular, the six Batch 1 collision rows below were collision-checked but not re-litigated, and the original audit's two named positives (`CVE-2026-42204`, `CVE-2026-34167`) are not part of “the other 12.” After the mapping closed, only `CVE-2026-42200`, `CVE-2025-64419`, and `CVE-2026-34058` received bounded new adjudication. The remaining unmapped Coolify history stays `UNKNOWN`.

The default service tier remained active; `/fast` was not enabled. No network request, credential access, clone, cache mutation, build, test suite, broad Git maintenance, or corpus rerun occurred. All Git reads used `-c gc.auto=0 -c maintenance.auto=false`.

## Snapshot boundary and frozen sources

Snapshot boundary: `2026-08-12T13:02:26-04:00`.

- Shared checkout: branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`, intentionally dirty and read-only.
- Coolify clone: HEAD `098d3d4c253a5a79aa8d166854a1b0a202077259`, clean porcelain status; ref-set digest `70b9dd5e1b67d0343f4d698b2edbd1329392d18cf6c54d19dd34f07857e15633`.
- The parent/root rollout was actively append-only. Its whole-file hash is intentionally not a claim anchor. The two completed records that establish receive-before-write chronology are frozen by physical line, byte length, timestamp, and SHA-256.

| Claim-bearing input | Bytes | SHA-256 / record digest |
|---|---:|---|
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | 27,171 | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| Byte-identical pre-existing snapshot `autoresearch/herdr-260812-unknown-recovery/snapshot/new-components-main.md` | 27,171 | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| Batch 1 `report.md` | 16,585 | `54e318d0fa08f3e6065e19816973b6efaad184028747339e2edd727f6a327a14` |
| Batch 1 `result.json` | 1,771 | `99c1fbcd644d27edc8b02f50416e4cbded96d9001624e265641ca8573abc1630` |
| Batch 1 `exclusion_manifest.json` | 251,161 | `34ec71dda6ab1522ce57d796ce8a612818db9a6ee634718e8f3d354b33b1a8a3` |
| Original completed Coolify audit transcript | 4,855,847 | `f1b6529500695eb0fcfeac8c55a0585bb8127e288288c478958b28fdb24e20c6` |
| Nested half-audit transcript | 2,908,278 | `d6a7317ffacabebbc3dcd47e3ac91c0c9f129938a8000ed5849cd9c82c4d7331` |
| Existing diagnostic route table `/tmp/ai_slop_nonbaseline_direct.tsv` | 71,613 | `ec7591362358b6c69e383d7a4c2c2d21638de7dbacc0567f7ca2aca813251eb2` |
| Parent receive record, physical line 37166 | 4,019 | `0a92a890d79962084725953891cf9c0e9fde62c9dc7ce0398958d8eb2ff4e665` |
| Parent summary-patch record, physical line 37252 | 20,396 | `d790d5ec76818a5386fbb2b3affd6f344da1f15498844a4762b4db57ea777928` |
| Original audit combined terminal record, physical line 397 | 3,885 | `4a09e1271ecf6de635a97398a2e24311b93f80b856929ac30842072392d4ac15` |

The complete machine-readable snapshot, including hashes for all twelve `PUBLISHED` CVEList objects, is in `source_manifest.json`.

## Why the mapping is exact

The proof is direct chronology, not keyword similarity:

1. At `2026-08-12T12:47:16.646Z`, physical JSONL line 37166 of `/home/hanqing/.codex/sessions/2026/08/11/rollout-2026-08-11T00-38-47-019fef1d-aef4-78f2-975b-d178d9bb36cf.jsonl` receives the original audit's terminal answer: `14 个 CVE 中 PASS 2 / FAIL 12 / NR 0`. It names the two PASS rows, then enumerates the twelve FAIL rows and their SHA/mechanism reasons.
2. At `2026-08-12T12:52:43.231Z`, physical line 37252 of that same parent rollout applies the main-summary patch containing `Coolify 其余本轮 12 项` and `详见本轮只读审计结论`.
3. The resulting summary's physical line 214 contains the same phrase. The earlier audit's twelve-row FAIL complement is therefore the phrase's source set.

Batch 1 correctly preserved `BLOCKED` from repository documents alone because the summary omitted the archived transcript path. Batch 2 recovers that missing source link without guessing.

## Exact row-to-SHA/mechanism mapping

The table uses `candidate (direct parent) -> atomic repair member (direct parent)`. A carrier is labeled separately and never substituted for its security member. Route-table membership and ancestry remain diagnostic; each `REJECT` reason compares fields, trust boundary, and sink.

| # | Public row | AI candidate(s) and direct baseline | Atomic repair / carrier | Mechanism and verdict | Batch 1 collision |
|---:|---|---|---|---|---|
| 1 | `CVE-2026-34153` / `GHSA-46hp-7m8g-7622` | `20b428891673e6e266e18c5fa55a039f9f69b71e` (`6d3c996ef374a8827eaf0e14318570344522420c`); `473c32270d72252ee6753afc35c3ea4360d169e0` (`733c20fc9d4af7c109c711315e63bbd21623e62f`) | member `3fdce06b654fa3b7b4be59c0faaab6b4546c78de` (`47668121a4031a9bd1466fa4a46292894670275c`) | Candidate changes image-digest parsing or backup API behavior; repair confines/escapes `LocalFileVolume.fs_path`. Different field/sink: `REJECT`. | ID + mechanism + exact `20b42889… -> 3fdce06b…` |
| 2 | `CVE-2026-42200` / `GHSA-mv4c-9x67-rrmv` | `99043600ee881fd8581185e7590604d9882382cd` (`1bd957073b107ceab92f8181c5f0f97b2457c282`); `cb1f571eb4b36da153d559246534f75683117299` (`988c08f2d1b22ea8bfe4ceece23041d27cce3e8c`) | member `a05d4e3a4b024719cda512244549fb5c949180c3` (`b1a78df58efe3ac38679d18c888b5817c7f01216`); carrier `1cf6c7d0aef8e0edb800ae43f44ded102397cb13` | Mongo names / general Compose paths differ from PostgreSQL init-filename traversal and escaped write target: `REJECT`, topology `NARROW`. | none |
| 3 | `CVE-2025-64419` / `GHSA-234r-xrrg-m8f3` | `f8e3bb54a3cb48da842351cc75490c8a20134807` (`69ab53ce1e9b96bbea4d36b3b4b826cbe3b26b3b`) | routed `f86ccfaa9af572a5487da8ea46b0a125a4854cf6` (`274c37e33380e1003707d7b930ec9d6bf5b0a980`); earlier same-mechanism security commit `cb1f571eb4b36da153d559246534f75683117299` | Routed pair adds custom Compose env/flag injection; advisory describes unsanitized YAML service/volume parameters. Wrong edge: `REJECT`; advisory-reference/release interpretation `NARROW`. | none |
| 4 | `CVE-2026-42147` / `GHSA-pwm4-w33c-wjf3` | primary `564cd8368bb8b4485b3981060dace37645b20f52` (`e39678aea584be533f89052d4e2939f2d8834449`); frozen route set also `5e90fc6b8f12d51543a0520ed6e3ad42374be016`, `875351188fbdcbb8b4405fe30274eaff9c657824`, `f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd` | member `297e9c41e19958f6237919794c28c3fb1d4cda32` (`57ea0764b8f0a491fd1d30bedc5cbe281744b36c`) | Notification URL validation, trimming, restore changes, and migration do not establish the S3 endpoint SSRF boundary in form plus `testConnection()`: `REJECT`. | ID + mechanism; exact edge only under full route set via `5e90fc6b… -> 297e9c41…` |
| 5 | `CVE-2026-34034` / `GHSA-rpr8-p7jc-x844` | `9675d74360c9057fe78682dccc263580b870904e` (`2c04336d7a12f5c8c8299fc4c6e2e2543712e5a6`); `a8aa4524751d1530031f6134d49474d254bbab72` (`8be1a9b5de3aa287cebf705ed7bd39400d4f7291`) | member `096d4369e59b3db7ace2db3ca42588c41b9b6019` (`6fbb5e626a82c576ae7a1a08b4e1d16aee2e82ed`) | UI relocation / metrics refactor preserve the vulnerable Sentinel-token path; repair validates and escapes the token: `REJECT`. | ID + mechanism only; Batch 1 used candidate `511415770a43389391802a9d5f7e284624e9b738` |
| 6 | `CVE-2026-42143` / `GHSA-6pmw-6m96-4v4m` | `3fdce06b654fa3b7b4be59c0faaab6b4546c78de` (`47668121a4031a9bd1466fa4a46292894670275c`) | member `d2064dd4998694cda2eabd00149f7c4d1e94c699` (`d77e4c864fdf3a9f0f22c04775a4573011beb0ed`) | Candidate repairs `LocalFileVolume.fs_path`; member repairs `LocalPersistentVolume.name` at `docker volume rm`. Different model/input/sink: `REJECT`. | none |
| 7 | `CVE-2026-34168` / `GHSA-mh8x-fppq-cp77` | same `3fdce06b654fa3b7b4be59c0faaab6b4546c78de` and baseline | same `d2064dd4998694cda2eabd00149f7c4d1e94c699` and baseline | Same root cause and exact edge as row 6: `REJECT`; component-deduplicate with row 6. | none |
| 8 | `CVE-2026-42201` / `GHSA-f35h-g2c2-q36v` | `3d1b9f53a0aec74468be75675bcaaaed0fd41d46` (`e39678aea584be533f89052d4e2939f2d8834449`) | member `03313e54cc790f3a6df6cb4fa9274c27437083e7` (`2264a2ef76f15cdc8b8cdf9f7f1bcd8e984a9280`); follow-up `40a9881ef2381f3f4db2dc004dd11b8a0dd3a6a2`; carrier `bff6d853708f3d7c861279586f107739036e67da` | Candidate validates Docker network names; repair validates distinct database credentials interpolated into Compose commands: `REJECT`. | ID + mechanism + exact member-normalized edge |
| 9 | `CVE-2026-34152` / `GHSA-5qp8-9gg7-4c86` | `a2e5b2d67d8cc05fd60a2d97e098ccc401562a25` (`d2a1b965987eb3d74847a22b3a3e8fc8104852b1`); `d59c75c2b23d95f2cf798d76efa4f31b6e99f611` (`a56fde7f124f3da172388611911c3d16cb435f0f`); `f8e3bb54a3cb48da842351cc75490c8a20134807` | member `6f163ddf02991fb8fd8bc17fdcecddc318b813c6` (`944a038349216f00b390e905c121355adc8b23c1`); carrier `ad95d65aca064f49b38f73f88d61f842737d5463` | Status/build-ARG/env-file changes do not constrain CR/LF in pre/post-command heredoc transport: `REJECT`. | ID + mechanism + exact `d59c75c2… -> 6f163ddf…` |
| 10 | `CVE-2026-34057` / `GHSA-6r3g-w7x8-54fj` | `cc96403cbe50f3538ceeec88feaabe445ad5094f` (`9a4b4280be5ad6e238cea4ffc267d64c8cd5289a`) | member `d486bf09ab2da8ad78fa721a079f066c76ce08d2` (`0fed553207383f384b93cba24d28122065fa67d5`) | Candidate changes confirmation/modal behavior while the mutable container/server sink already exists; repair locks, scopes, and validates it: `REJECT`. | ID + mechanism + exact edge |
| 11 | `CVE-2026-34038` / `GHSA-qqrq-r9h4-x6wp` | `8714d9bd0332a29275750f2f58fab043df2d677a` (`981fc127b5054c19ae3d71897e49d08f53cc6154`); `f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd` (`bb9ddd089a8c3b660a9d142998cc59f05cdd442f`) | member `23f9156c7306b221101f1ebbe4d3c6b5e2522acd` (`f896d47b99acad04cf10dc94ba2865bf7b68dfca`) | Front-end normalization / Livewire migration do not impose the repair's API/runtime path, target, container, and command validation: `REJECT`. | none |
| 12 | `CVE-2026-34058` / `GHSA-rh5x-qx77-fq9v` | `5d73b76a44198dfbc8533010a348a1703793094d` (`6593b2a553425050b69dcfc6a72508abd2f6e93b`) | member `ae31111813b0b5cbf3e148dd0b6975c046947110` (`e2ba44d0c39571fb5f81e512b5454dd88aca9591`); carrier `944a038349216f00b390e905c121355adc8b23c1` | Candidate is Traefik cache/UI work; member validates and quotes unmanaged container IDs at shell sinks: `REJECT`, topology `NARROW`. | none |

`mapping.json` preserves the same mapping as structured data, including the 21 frozen route-table candidate edges and normalized carrier/member identities.

## Collision check against Batch 1

Batch 1 selected 11 public components / 12 candidate edges. Collision definitions and results are frozen separately to avoid silently moving the denominator:

| Unit | Count | Exact members |
|---|---:|---|
| Public-ID rows | 6 / 12 | `CVE-2026-34153`, `CVE-2026-42147`, `CVE-2026-34034`, `CVE-2026-42201`, `CVE-2026-34152`, `CVE-2026-34057` |
| Semantic mechanisms | 6 / 11 | the same six mechanisms |
| Exact member-normalized edges, terminal-primary candidate | 4 | `20b42889…->3fdce06b…`, `3d1b9f53…->03313e54…`, `d59c75c2…->6f163ddf…`, `cc96403c…->d486bf09…` |
| Exact member-normalized edges, all 21 frozen route candidates | 5 | the four above plus `5e90fc6b…->297e9c41…` |
| Component-only collision | 1 | `CVE-2026-34034`: original `9675d743…/a8aa4524…->096d4369…`; Batch 1 `51141577…->096d4369…` |

The non-colliding remainder is six public rows / five mechanisms: `CVE-2026-42200`, `CVE-2025-64419`, `CVE-2026-42143`, `CVE-2026-34168`, `CVE-2026-34038`, and `CVE-2026-34058`. Rows `42143` and `34168` are one mechanism.

## Bounded top-three adjudication

### 1. CVE-2026-42200 — `REJECT`, carrier/member `NARROW`

- CNA identity: `PUBLISHED`, affected `< 4.0.0-beta.474`, first-party `GHSA-mv4c-9x67-rrmv`, PR `9681`, carrier `1cf6c7d0…`.
- `99043600…` validates Mongo backup database/collection names; first containing tag `v4.0.0-beta.471`.
- `cb1f571e…` validates Docker Compose service/volume paths; first tag `v4.0.0-beta.436`.
- Atomic repair `a05d4e3a…` applies filename confinement/validation and shell escaping to PostgreSQL init scripts; parent `b1a78df5…`; first tag `v4.0.0-beta.474`.
- `1cf6c7d0…` is the two-parent carrier containing `a05d4e3a…`, also first tagged beta.474.

The candidates and repair concern distinct database/input mechanisms. The row is a strong wrong-input plus carrier/member negative control, not a same-mechanism incomplete repair.

### 2. CVE-2025-64419 — `REJECT`, advisory mapping `NARROW`

- CNA identity: `PUBLISHED`, affected `< 4.0.0-beta.445`, first-party `GHSA-234r-xrrg-m8f3`, reference `f86ccfaa…`.
- Candidate `f8e3bb54…` injects environment variables into custom Compose build commands; parent `69ab53ce…`; first tag beta.445.
- Routed `f86ccfaa…` auto-injects `-f` and `--env-file` flags into custom Compose commands; parent `274c37e3…`; first tag beta.445.
- Neither delta implements the CNA-described sanitization of parameters read from attacker-controlled `docker-compose.yaml`.
- Earlier `cb1f571e…`, first tag beta.436, explicitly adds pre-save validation for Compose service names and volume source/target values.

The routed candidate/fix pair is the wrong mechanism and remains `REJECT`. The discrepancy between the CNA's described mechanism/version reference and the earlier same-mechanism security delta is retained as `NARROW`; this report does not rewrite the CNA or claim that its affected range is false.

### 3. CVE-2026-34058 — `REJECT`, carrier/member `NARROW`

- CNA identity: `PUBLISHED`, affected `< 4.0.0-beta.471`, first-party `GHSA-rh5x-qx77-fq9v`, PR `9172`, carrier `944a0383…`.
- Candidate `5d73b76a…`, parent `6593b2a5…`, centralizes Traefik version caching/UI; first tag beta.445.
- Atomic repair `ae311118…`, parent `e2ba44d0…`, validates the Livewire container ID and applies `escapeshellarg` at unmanaged-container command sinks; first tag beta.471.
- `944a0383…` is the two-parent carrier containing `ae311118…`, first tag beta.471.

Shared `Server.php` context is not causal lineage. This is a different-mechanism plus carrier-masking control.

## Negative, blocked, and unknown controls

- `REJECT`: all 12 mapped public rows. Wrong field, wrong input, different sink, refactor preservation, or carrier masking remains visible row by row.
- `NARROW`: three annotations, not positive verdicts—two carrier-to-member corrections (`42200`, `34058`) and one first-party advisory/commit-mechanism mapping discrepancy (`2025-64419`).
- `BLOCKED`: zero in this mapped set; the sole Batch 1 phrase blocker is resolved.
- `UNKNOWN`: zero among the twelve mapped rows. The broader unexamined Coolify history remains `UNKNOWN` because it was deliberately not rescanned.
- `PASS`: zero new rows. The two PASS rows from the source audit were explicitly named before “other 12,” are already adjudicated, and were excluded.

## Exact commands and sources

Representative replay commands used for the bounded closure:

```zsh
cd /home/hanqing/agents/ai-slop

# Locate the source phrase and freeze stable documents.
rg -n --fixed-strings 'Coolify 其余本轮 12 项' \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  /home/hanqing/.codex/sessions/2026/08/11/rollout-2026-08-11T00-38-47-019fef1d-aef4-78f2-975b-d178d9bb36cf.jsonl
sha256sum docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  autoresearch/herdr-260812-coolify-tail/report.md \
  autoresearch/herdr-260812-coolify-tail/result.json \
  autoresearch/herdr-260812-coolify-tail/exclusion_manifest.json

# Freeze exact completed records inside the still-growing parent container.
sed -n '37166p' /home/hanqing/.codex/sessions/2026/08/11/rollout-2026-08-11T00-38-47-019fef1d-aef4-78f2-975b-d178d9bb36cf.jsonl | sha256sum
sed -n '37252p' /home/hanqing/.codex/sessions/2026/08/11/rollout-2026-08-11T00-38-47-019fef1d-aef4-78f2-975b-d178d9bb36cf.jsonl | sha256sum
sed -n '397p' /home/hanqing/.codex/sessions/2026/08/12/rollout-2026-08-12T08-39-02-019ff5fb-b671-7aa2-acd8-a1989f04f568.jsonl | sha256sum

# Enumerate exactly the 21 diagnostic candidate routes for the twelve rows.
rg 'CVE-2026-(34153|42200|42147|34034|42143|34168|42201|34152|34057|34038|34058)|CVE-2025-64419' \
  /tmp/ai_slop_nonbaseline_direct.tsv

# Resolve first-party candidate/member/carrier topology without maintenance.
repo=/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" \
  show -s --format='%H|%P|%ad|%s' --date=iso-strict <sha>
git -c gc.auto=0 -c maintenance.auto=false -c versionsort.suffix=-beta -C "$repo" \
  tag --contains <sha> --sort=version:refname
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" status --porcelain=v1
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" show-ref | sha256sum

# Verify first-party CNA identity and released containment locally.
jq -c '{id:.cveMetadata.cveId,state:.cveMetadata.state,affected:.containers.cna.affected,references:.containers.cna.references}' \
  /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/42xxx/CVE-2026-42200.json \
  /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2025/64xxx/CVE-2025-64419.json \
  /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/34xxx/CVE-2026-34058.json
```

Primary sources are the hashed summary, exact archived audit records, local first-party Coolify Git objects/tags, and local first-party CNA CVEList objects. Batch 1 artifacts provide the collision denominator. The route TSV is diagnostic only.

## Claim boundary

Publication-safe claim: the archived source chain proves that the summary phrase denotes exactly the enumerated twelve rejected public rows; they deduplicate to eleven mechanisms, and six rows/six mechanisms collide with Batch 1.

This is **not** a new security-causality positive. Routing, blame, ancestry, subjects, tests, archived agent prose, and source recovery do not by themselves prove causality. The three newly inspected rows remain negative after candidate-parent/repair-member/mechanism/release comparison. The other nine retain their original direct-delta `REJECT` adjudications. No statement is made about unexamined Coolify history, and the unresolved breadth remains `UNKNOWN`.
