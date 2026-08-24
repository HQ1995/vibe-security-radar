# Batch 2 Coolify phrase recovery

## Result

**COMPLETE: the phrase `Coolify 其余本轮 12 项` is recoverable.** It denotes the twelve literal `FAIL` CVE rows in the terminal message of the original read-only Coolify incomplete-remediation audit, not twelve unnamed commits and not twelve independent mechanism components. The source audit handled 14 CVEs as `PASS 2 / FAIL 12 / NR 0`; the two PASS rows were CVE-2026-42204 and CVE-2026-34167, so the complement is the exact twelve-row mapping below.

Normalized to the campaign vocabulary, all twelve rows remain `REJECT`; CVE-2025-64419 also carries a `NARROW` release/reference caveat. No row is promoted by ancestry, routing, source recovery, or this mapping exercise.

## Snapshot boundary and provenance

- Snapshot time: `2026-08-12T12:55:27-04:00`.
- Shared checkout: `/home/hanqing/agents/ai-slop`, branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`; dirty and read only.
- Read-only first-party Coolify clone: `/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify`, HEAD `098d3d4c253a5a79aa8d166854a1b0a202077259`; `status --porcelain=v1` was empty.
- No full `556 x 42` population scan, build, test suite, or network call was performed.

The exact source chain is chronological and direct:

1. Original Coolify audit subagent transcript
   `/home/hanqing/.codex/sessions/2026/08/12/rollout-2026-08-12T08-39-02-019ff5fb-b671-7aa2-acd8-a1989f04f568.jsonl`
   ends with the literal result `14 个 CVE 中 PASS 2 / FAIL 12 / NR 0` and names all twelve FAIL CVEs. Its nested half-audit transcript
   `/home/hanqing/.codex/sessions/2026/08/12/rollout-2026-08-12T08-39-37-019ff5fc-41ae-79b2-8790-e4f00d339347.jsonl`
   supplies the expanded candidate/parent/member/carrier distinctions for seven of them.
2. The parent/root rollout
   `/home/hanqing/.codex/sessions/2026/08/11/rollout-2026-08-11T00-38-47-019fef1d-aef4-78f2-975b-d178d9bb36cf.jsonl`
   receives that exact terminal message at JSONL line 37166 (`2026-08-12T12:47:16.646Z`). At line 37252 (`2026-08-12T12:52:43.231Z`) it creates the summary document containing `Coolify 其余本轮 12 项`. Thus the number 12 is demonstrably the FAIL count from that audit, not a later inference.
3. The resulting summary is
   `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md`, line 214. It says `详见本轮只读审计结论` but omits the transcript path, which is why Batch 1 correctly preserved the mapping as `BLOCKED` using repository-held documents alone.

### Frozen input hashes

| Input | Bytes | SHA-256 |
|---|---:|---|
| Main summary document | 27,171 | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| Batch 1 report | 16,585 | `54e318d0fa08f3e6065e19816973b6efaad184028747339e2edd727f6a327a14` |
| Original Coolify audit transcript | 4,855,847 | `f1b6529500695eb0fcfeac8c55a0585bb8127e288288c478958b28fdb24e20c6` |
| Nested half-audit transcript | 2,908,278 | `d6a7317ffacabebbc3dcd47e3ac91c0c9f129938a8000ed5849cd9c82c4d7331` |
| Parent/root rollout containing receive then patch, snapshot observation only | 327,640,347 | `8e1ca0f3ef54beb9a398f70c72bf4a265485e6b4dae9a4d1bdc95da42dce3738` |
| Frozen diagnostic route table `/tmp/ai_slop_nonbaseline_direct.tsv` | 71,613 | `ec7591362358b6c69e383d7a4c2c2d21638de7dbacc0567f7ca2aca813251eb2` |

The parent/root rollout continued appending after this observation, so its whole-file digest is not a stable claim anchor. The completed receive record at physical line 37166 is frozen as `0a92a890d79962084725953891cf9c0e9fde62c9dc7ce0398958d8eb2ff4e665`; the later patch record at line 37252 is frozen as `d790d5ec76818a5386fbb2b3affd6f344da1f15498844a4762b4db57ea777928`. The `/tmp` table is also volatile and therefore not the sole proof: its relevant rows and the final twelve-row decision are embedded in the hashed completed audit transcript. All CVE objects below were locally frozen `PUBLISHED` CVEList records; their individual hashes appear under Sources.

## Exact twelve-row mapping

`candidate (direct parent) -> exact repair member (direct parent)` is used below. A merge carrier is explicitly labeled and is never substituted for its security member. Candidate lists include the candidates explicitly named by the terminal audit; extra route-table candidates are shown only where needed to explain the Batch 1 collision.

| # | Public row | Audit candidate(s) and baseline | Exact member / carrier | Mechanism comparison | Status | Batch 1 collision |
|---:|---|---|---|---|---|---|
| 1 | CVE-2026-34153 / GHSA-46hp-7m8g-7622 | `20b428891673e6e266e18c5fa55a039f9f69b71e` (`6d3c996ef374a8827eaf0e14318570344522420c`); `473c32270d72252ee6753afc35c3ea4360d169e0` (`733c20fc9d4af7c109c711315e63bbd21623e62f`) | `3fdce06b654fa3b7b4be59c0faaab6b4546c78de` (`47668121a4031a9bd1466fa4a46292894670275c`) | Candidates change Docker image-digest parsing and backup API behavior; member confines/escapes `LocalFileVolume.fs_path`. Wrong field and sink. | `REJECT` | ID + component + exact edge `20b42889... -> 3fdce06b...` |
| 2 | CVE-2026-42200 / GHSA-mv4c-9x67-rrmv | `99043600ee881fd8581185e7590604d9882382cd` (`1bd957073b107ceab92f8181c5f0f97b2457c282`); `cb1f571eb4b36da153d559246534f75683117299` (`988c08f2d1b22ea8bfe4ceece23041d27cce3e8c`) | true member `a05d4e3a4b024719cda512244549fb5c949180c3` (`b1a78df58efe3ac38679d18c888b5817c7f01216`); routed carrier/root `1cf6c7d0aef8e0edb800ae43f44ded102397cb13` | Mongo collection-name validation and generic Compose pre-save validation do not create the PostgreSQL init-script filename traversal/arbitrary-write mechanism. Carrier/member correction required. | `REJECT` | none |
| 3 | CVE-2025-64419 / GHSA-234r-xrrg-m8f3 | `f8e3bb54a3cb48da842351cc75490c8a20134807` (`69ab53ce1e9b96bbea4d36b3b4b826cbe3b26b3b`) | routed `f86ccfaa9af572a5487da8ea46b0a125a4854cf6` (`274c37e33380e1003707d7b930ec9d6bf5b0a980`); audit identifies earlier security repair `cb1f571eb4b36da153d559246534f75683117299` | Candidate and routed commit inject env/`-f`/`--env-file` behavior into custom Compose commands; advisory is volume-source injection. Wrong edge. The audit also records a CNA beta.445/reference mapping discrepancy. | `REJECT`; release mapping `NARROW` | none |
| 4 | CVE-2026-42147 / GHSA-pwm4-w33c-wjf3 | terminal row: `564cd8368bb8b4485b3981060dace37645b20f52` (`e39678aea584be533f89052d4e2939f2d8834449`); diagnostic route set also contains `5e90fc6b8f12d51543a0520ed6e3ad42374be016` (`e0b2424b7645bf67562924917b64a4e18cec233b`), `875351188fbdcbb8b4405fe30274eaff9c657824`, and `f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd` | `297e9c41e19958f6237919794c28c3fb1d4cda32` (`57ea0764b8f0a491fd1d30bedc5cbe281744b36c`) | Terminal candidate guards notification webhook URLs; advisory/member guards the S3 endpoint and `testConnection()` SSRF. Different field/request sink. | `REJECT` | ID + component; candidate-set exact edge via Batch 1's `5e90fc6b... -> 297e9c41...` |
| 5 | CVE-2026-34034 / GHSA-rpr8-p7jc-x844 | `9675d74360c9057fe78682dccc263580b870904e` (`2c04336d7a12f5c8c8299fc4c6e2e2543712e5a6`); `a8aa4524751d1530031f6134d49474d254bbab72` (`8be1a9b5de3aa287cebf705ed7bd39400d4f7291`) | `096d4369e59b3db7ace2db3ca42588c41b9b6019` (`6fbb5e626a82c576ae7a1a08b4e1d16aee2e82ed`) | Sidebar/UI and metrics refactors preserve the pre-existing Sentinel-token shell path; member adds token validation/escaping. | `REJECT` (`refactor_preservation`) | ID + component only; Batch 1 used different candidate `511415770a43389391802a9d5f7e284624e9b738` |
| 6 | CVE-2026-42143 / GHSA-6pmw-6m96-4v4m | `3fdce06b654fa3b7b4be59c0faaab6b4546c78de` (`47668121a4031a9bd1466fa4a46292894670275c`) | `d2064dd4998694cda2eabd00149f7c4d1e94c699` (`d77e4c864fdf3a9f0f22c04775a4573011beb0ed`) | Candidate fixes `LocalFileVolume.fs_path`; repair validates/quotes `LocalPersistentVolume.name` at `docker volume rm`. Different model, field, and sink. | `REJECT` | none |
| 7 | CVE-2026-34168 / GHSA-mh8x-fppq-cp77 | same `3fdce06b654fa3b7b4be59c0faaab6b4546c78de` | same `d2064dd4998694cda2eabd00149f7c4d1e94c699` | Same persistent-volume-name root cause and exact edge as row 6. It is a second public row, not a second mechanism component. | `REJECT`; component-dedup with row 6 | none |
| 8 | CVE-2026-42201 / GHSA-f35h-g2c2-q36v | `3d1b9f53a0aec74468be75675bcaaaed0fd41d46` (`e39678aea584be533f89052d4e2939f2d8834449`); `e20327b9c4e4a36d01e49e170fcb7cb8f5d0f283` (`a3d9ca5c5ccd231df5d04e88397e9274ec1f8133`) | member `03313e54cc790f3a6df6cb4fa9274c27437083e7` (`2264a2ef76f15cdc8b8cdf9f7f1bcd8e984a9280`); follow-up `40a9881ef2381f3f4db2dc004dd11b8a0dd3a6a2`; carrier `bff6d853708f3d7c861279586f107739036e67da` | Candidates guard Docker network names and view authorization; member guards database credentials interpolated into Compose commands. Different input/mechanism. | `REJECT` | ID + component + exact member-normalized edge `3d1b9f53... -> 03313e54...` |
| 9 | CVE-2026-34152 / GHSA-5qp8-9gg7-4c86 | `a2e5b2d67d8cc05fd60a2d97e098ccc401562a25` (`d2a1b965987eb3d74847a22b3a3e8fc8104852b1`); `d59c75c2b23d95f2cf798d76efa4f31b6e99f611` (`a56fde7f124f3da172388611911c3d16cb435f0f`); `f8e3bb54a3cb48da842351cc75490c8a20134807` | member `6f163ddf02991fb8fd8bc17fdcecddc318b813c6` (`944a038349216f00b390e905c121355adc8b23c1`); carrier `ad95d65aca064f49b38f73f88d61f842737d5463` | Deployment status, build-arg regex, and env-file injection do not address CR/LF in pre/post-command heredoc transport. | `REJECT` | ID + component + exact member-normalized edge `d59c75c2... -> 6f163ddf...` |
| 10 | CVE-2026-34057 / GHSA-6r3g-w7x8-54fj | primary `cc96403cbe50f3538ceeec88feaabe445ad5094f` (`9a4b4280be5ad6e238cea4ffc267d64c8cd5289a`); rejected adjacent routes `94560ea6c7a841840638e7c73a4b5d6da2afe713`, `a9f42b94401bbd7cbb233b2f0c60fe7276ac3845`, `dca6d9f7aab40fb9e6ea24dcc3a85bea02cc33a6` | `d486bf09ab2da8ad78fa721a079f066c76ce08d2` (`0fed553207383f384b93cba24d28122065fa67d5`) | Password/modal behavior plus cleanup/reconnect routes do not lock client-controlled server/container state; member adds locking, team scope, and container validation. | `REJECT` | ID + component + exact edge `cc96403c... -> d486bf09...` |
| 11 | CVE-2026-34038 / GHSA-qqrq-r9h4-x6wp | `8714d9bd0332a29275750f2f58fab043df2d677a` (`981fc127b5054c19ae3d71897e49d08f53cc6154`); `f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd` (`bb9ddd089a8c3b660a9d142998cc59f05cdd442f`) | `23f9156c7306b221101f1ebbe4d3c6b5e2522acd` (`f896d47b99acad04cf10dc94ba2865bf7b68dfca`) | Front-end path normalization and Livewire binding migration do not reject shell metacharacters; member adds API/runtime path, target, container, and command validation. | `REJECT` | none |
| 12 | CVE-2026-34058 / GHSA-rh5x-qx77-fq9v | `5d73b76a44198dfbc8533010a348a1703793094d` (`6593b2a553425050b69dcfc6a72508abd2f6e93b`) | exact member `ae31111813b0b5cbf3e148dd0b6975c046947110` (`e2ba44d0c39571fb5f81e512b5454dd88aca9591`); carrier `944a038349216f00b390e905c121355adc8b23c1` | Candidate is Traefik version-cache/UI work. Member validates container ID and quotes it at the unmanaged-container shell sink. Routing to the carrier obscured the true member. | `REJECT` | none |

## Collision check against Batch 1

Batch 1 reviewed 11 public components / 12 candidate edges. Collision counts depend on whether an "edge" means the terminal summary's displayed primary candidate or every candidate in its frozen diagnostic candidate set, so both exact definitions are reported:

| Collision unit | Count | Members |
|---|---:|---|
| Public-ID rows | **6 / 12** | CVE-2026-34153, 42147, 34034, 42201, 34152, 34057 |
| Semantic components | **6 / 11** | the same six; rows 42143/34168 collapse to one non-colliding component |
| Exact member-normalized edges, terminal-primary definition | **4** | `20b42889->3fdce06b`, `3d1b9f53->03313e54`, `d59c75c2->6f163ddf`, `cc96403c->d486bf09` |
| Exact member-normalized edges, full frozen candidate-set definition | **5** | the four above plus `5e90fc6b->297e9c41` for CVE-2026-42147 |
| Component-only collision with different candidate edge | **1** | CVE-2026-34034: old `9675d743/a8aa4524 -> 096d4369`; Batch 1 `51141577 -> 096d4369` |

Therefore the previously unnamed, non-colliding remainder is **6 public rows / 5 semantic components**: CVE-2026-42200, CVE-2025-64419, CVE-2026-42143, CVE-2026-34168, CVE-2026-34038, and CVE-2026-34058. No Batch 1 verdict changes.

## Bounded top-three adjudication of previously unnamed rows

Only three rows were examined after the mapping closed, as requested.

1. **CVE-2026-42200 — `REJECT_WRONG_INPUT_AND_CARRIER_MEMBER`.** The two routed AI candidates modify Mongo collection-name handling and generic Compose parsing. The published mechanism is a PostgreSQL init-script filename traversal leading to arbitrary write/root RCE. Local first-party Git resolves the actual member to `a05d4e3a...` with parent `b1a78df...`; `1cf6c7d0...` is a broad routed carrier/root. This is a useful carrier/member negative control, not an incomplete same-mechanism repair.
2. **CVE-2025-64419 — `REJECT_WRONG_EDGE`, with release mapping `NARROW`.** `f8e3bb54... -> f86ccfaa...` concerns custom Docker Compose env and flag injection, while the advisory describes volume-source command injection. The original audit identifies earlier Claude repair `cb1f571e...` as the security-relevant code, so the routed pair is rejected. Its recorded CNA beta.445/reference mismatch is retained as `NARROW`; it is not silently resolved into a release-grade claim here.
3. **CVE-2026-34058 — `REJECT_DIFFERENT_MECHANISM_AND_CARRIER_MASKING`.** `5d73b76a...` is a Traefik versions-cache/UI refactor. The actual security member is `ae311118...`, which validates/escapes unmanaged container IDs; `944a0383...` is its merge carrier. Same model/file routing is not a causal edge.

## Sources and CVE object hashes

All twelve local CNA objects were `PUBLISHED` and linked a first-party `coollabsio/coolify` repo advisory at the snapshot boundary:

```text
4fe3992c82324d777fd6dc8d6784e30d67c6b8ff5bbf42802477078095b927b1  cves/2026/34xxx/CVE-2026-34153.json
effe04e52beefca1c8a9271952ac6335633a7f36c549329236f9e2c1aee4c06b  cves/2026/42xxx/CVE-2026-42200.json
791600cafbf324cbe2633362e1a002e5c8c01c5c8bc150675b2be31afa8f3b42  cves/2025/64xxx/CVE-2025-64419.json
ce2b917fbd7747e8a0a1144a3a1aae6ff45a416a88563ca8fec53b39e781db33  cves/2026/42xxx/CVE-2026-42147.json
b6b1f71b158b0293ea7ac7be0769a18e403fffe08ce9e872f237637bc4a7ffbd  cves/2026/34xxx/CVE-2026-34034.json
6000f9c9b20e81cbae726346bc7ff11bde0cdb9ffed5279bd8a794e5d354db9a  cves/2026/42xxx/CVE-2026-42143.json
7dd2c256cf37c6bd26ddbf87799ef6e6d08e24ee92a2965729737d7b52d4beae  cves/2026/34xxx/CVE-2026-34168.json
a69fea62174951c6cd7cc5a17d8043ede57a9a365a70636338233ef5de38ed2b  cves/2026/42xxx/CVE-2026-42201.json
dbddd5900e3576e74f3605bfbaeb5150e62b72de9b6ff495696112813ec5fb4c  cves/2026/34xxx/CVE-2026-34152.json
f5500b7a5b53efa56494bb1e5f0480488c88404cc3cf6006e43a4cc20ea61e71  cves/2026/34xxx/CVE-2026-34057.json
254ace338ef9a35d37cd430d2d5bb2e801bf3ef106090fe79b93e748a290cf56  cves/2026/34xxx/CVE-2026-34038.json
efb6f4c2aee715f38d110e156983cf797cc15f273c65eb30a8cb800ce40d1a61  cves/2026/34xxx/CVE-2026-34058.json
```

The `cves/...` paths are relative to `/home/hanqing/.cache/cve-analyzer/cvelistV5/`.

## Exact commands

```zsh
cd /home/hanqing/agents/ai-slop

# Find the phrase and its originating archived audit.
rg -n -i 'Coolify.*12|12.*Coolify|\u5176\u4f59\u672c\u8f6e' docs autoresearch .ai-slop/state/cohort-v1
rg -l --fixed-strings 'coolify_incomplete_remediation_audit' \
  /home/hanqing/.codex/sessions/2026/08/{11,12}
rg -n --fixed-strings '只读审计结论：14 个 CVE 中' \
  /home/hanqing/.codex/sessions/2026/08/11/rollout-2026-08-11T00-38-47-019fef1d-aef4-78f2-975b-d178d9bb36cf.jsonl
rg -n -o --fixed-strings 'Coolify 其余本轮 12 项' \
  /home/hanqing/.codex/sessions/2026/08/11/rollout-2026-08-11T00-38-47-019fef1d-aef4-78f2-975b-d178d9bb36cf.jsonl

# Freeze source documents/transcripts.
stat -c '%n|%s|%y' <each-input>
sha256sum <each-input>

# Expand abbreviated SHAs and preserve parent/member/carrier topology without maintenance.
repo=/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" rev-parse <sha-prefix>
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" \
  show -s --format='%H|%P|%s' <sha>
git -c gc.auto=0 -c maintenance.auto=false -C "$repo" status --porcelain=v1

# Frozen diagnostic routes only; not causal proof.
rg -n 'CVE-2026-(34153|42200|42147|34034|42143|34168|42201|34152|34057|34038|34058)|CVE-2025-64419' \
  /tmp/ai_slop_nonbaseline_direct.tsv

# First-party identity and frozen object hashing; no API call.
sha256sum /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/{2025/64xxx/CVE-2025-64419.json,2026/{34xxx,42xxx}/CVE-2026-*.json}
```

## Claim boundary

- **Recovered fact:** the phrase maps exactly to twelve public CVE rows because the archived terminal audit says `PASS 2 / FAIL 12` and enumerates the twelve FAIL rows before the parent writes the phrase.
- **Not a new causal result:** archived model/agent prose, route-table overlap, ancestry, and commit subjects are diagnostic. The retained `REJECT` decisions are supported by the original audit's parent/candidate/member inspection; this run only rechecked bounded topology and the three previously unnamed rows above.
- **Deduplication:** twelve public rows equal eleven mechanisms because CVE-2026-42143 and CVE-2026-34168 share one persistent-volume-name root cause. Six public rows/six components collide with Batch 1; five exact edges collide under the full frozen candidate-set definition.
- **Unknown remains unknown:** no inference is made about the unexamined Coolify history. The broad 556-commit by 42-fix-root population was not rescanned.
