# Round8 independent double-confirm — 2026-08-26

Independent re-audit of the 202 cases in
`artifacts/round8-double-confirm-packet-20260826.md`, judged per
`docs/AUDIT-PROTOCOL.md`: vulnerability first, AI second; BIC = smallest
first-writer of the vulnerable lines (move / rename / refactor / revert /
squash aggregate is not a BIC); AI role judged only from signals on that
BIC.

This is not a rubber-stamp of round8 records. Ledger was not rewritten.

## Structural packet claims (re-run)

- 202/202 `records-wNNN.jsonl` have the 18-key shape, `class_id` matches
  `cases-202.jsonl`, and `scripts/audit_record_gates.py` prints `ok`.
- 202/202 ledger rows carry `round8_research` byte-identical to the
  worker record; `status` / `round8_verdict` match; row count 24,124.
- Pre-land backup: those 202 rows were all `PARTIALLY_ANALYZED`.

## Verdict changes (load-bearing)

Round8 claimed 3 `AI_ROOT_CAUSE` + 2 `AI_CODE_FLAWED` + 2 `BLOCKED` +
195 `NOT_AI`. Independent review **overturns both `AI_CODE_FLAWED`
rows** and **two additional `NOT_AI` → `BLOCKED`**. The three
Claude-Code MCP unpatched TPs and the original two `BLOCKED` rows stand.

| Worker | Round8 | Independent | Why |
|---|---|---|---|
| w076 anubissbe/projecthub-mcp | AI_ROOT_CAUSE | **confirm AI_ROOT_CAUSE** | Parent stored webhook URLs but did not fetch them. BIC `31dd902d…` first wrote `fetch(webhook.url)` (test + notify helpers) with `Generated with Claude Code` + `Co-Authored-By: Claude`. Still present at HEAD → unpatched. |
| w080 hulupeep/mcp-ui-probe | AI_ROOT_CAUSE | **confirm AI_ROOT_CAUSE** | `src/journey/JourneyStorage.ts` added in `ada347ec…` only; `path.join(baseDir, ${journeyId}.yml)` with no sanitization; file absent at parent; Claude Code trailer on BIC; no later commits on the file → unpatched. |
| w166 astralisone/rive-mcp-server-core | AI_ROOT_CAUSE | **confirm AI_ROOT_CAUSE** | `importRiveFile.ts` created in `db1d0cc4…` (= HEAD); feeds `libraryId` into unsanitized `saveLibrary` path join; Claude Code trailer on BIC; no later change to the sink → unpatched. |
| w020 budibase/budibase | AI_CODE_FLAWED | **overturn NOT_AI** | BIC `84ae2210…` first wrote the incomplete flag-only `validateGlobalRoleUpdate` allowlist (assign() already forwarded `appBuilder`/`role` since 2023). Raw commit: Peter Clement, **no trailer, no Generated-with**. The only AI story is PR #18771 branch `codex/fix-public-role-global-grants`. Protocol judges AI from signals **on the BIC**, not delivery-branch naming. Reject branch-name inference → NOT_AI. |
| w195 dynatrace-oss/dynatrace-mcp | AI_CODE_FLAWED | **overturn NOT_AI** | Unauthenticated HTTP handler was first written in `6cca70b23c…` (Christian Kreuzberger, **no AI marker**). `00b7649a…` is the GitHub squash of PR #107 (carrier, not BIC). Copilot's only content change in the PR (`d2e79dd7…`) is `let body: unknown = undefined` → `let body: unknown`. Fix-side Claude trailer correctly demoted. |
| w087 anthropics/claude-code | BLOCKED | **confirm BLOCKED** | Public repo has no `CoworkVMService` source (docs/changelog/examples only). No obtainable BIC for the Windows Desktop SYSTEM service. |
| w189 guardrails-ai/guardrails | BLOCKED | **confirm BLOCKED** | Tags `v0.10.0` → `v0.10.2`; `+version =` enumeration over `pyproject.toml` never contains `0.10.1`. No in-repo introducer. |
| w156 langchain-ai/helm | NOT_AI | **overturn BLOCKED** | Studio `baseUrl` sink lives in closed `langsmith-frontend`, not this helm clone. Round8 BIC `be02862…` is a helm commit, not the SPA first-writer. Chart retag `6b9c7ef…` (`langsmith-0.12.33`) only bumps image tags. No public BIC → cannot judge AI. |
| w186 openstack/ironic-python-agent | NOT_AI | **overturn BLOCKED** | CVE-2026-42997 / OSSA-2026-010 is Ironic conductor `molds.py` credential forwarding. Assigned clone is IPA; no `molds.py`, no matching tags. GHSA listed the ramdisk agent with Ironic version ranges. Round8 BIC `15e20fe…` is on `openstack/ironic`, not this clone. No in-repo BIC → cannot judge AI. |
| w147 mayan-edms/mayan-edms | NOT_AI | **overturn EVIDENCE_GAP** | 4.10.1 XSS is `window.location = hash` after URI.js. Round8 BIC `9f8c7cb9…` is a 1572-file one-parent squash that reopened a sink `b78089cc` had closed with `.pathname`. series/3.5 members are not in this clone; squash is not BIC; AI unjudged. |
| w152 geonode/geonode | Round8 BIC `70296bf4…` (#6627 squash). Independent first-writer of TinyMCE `|safe` is member `45bb0dce…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w018 django/django | Round8 BIC `929684d6…` (2015 Content-Length check). Independent first-writer of unbounded ASGI `read_body` is `a415ce70…`. | NOT_AI stands; round8 BIC is dormant under WSGI LimitedStream. |
| w032 electron/electron | Round8 BIC `0090616f…` (#20307 squash). Independent first-writer of the Promise `ConvertToV8` path is member `5c4c9d56…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w011 apache/airflow | Round8 BIC `5c52bbf3…` (2022 CopyFrom copy). Independent first-writer of unsanitized `COPY INTO` interpolations is `17af3bee…`. | NOT_AI stands; round8 BIC is a later copy of S3ToSnowflake. |
| w104 django/django | Round8 BIC `8fd94405…` (URL-only cache.set). Independent first-writer of GET-200 `learn_cache_key` is `d65526d6…`. | NOT_AI stands; round8 BIC is an earlier different cache key. |
| w054 electron/electron | Round8 BIC `1a47cc3a…` (claimed #36606 member). Independent records squash `6bd9ee69…` — members absent in this clone. | NOT_AI stands; same first-write, different recorded SHA. |
| w121 dotnet/runtime | Round8 BIC `80f633db…` (clrjit path property). Independent first-writer of empty `app_root` CWD fallback is `78b303df…`. | NOT_AI stands; round8 BIC is a later carrier. |
| w065 apache/airflow | Round8 BIC `d295e708…` (log/UI `DEFAULT_SENSITIVE_FIELDS`). Independent first-writer of GET extra `redact()` is `d010b0dd…`. | NOT_AI stands; round8 BIC is the allowlist origin, not the GET serializer. |
| w169 apache/airflow | NOT_AI | **policy-open** (worker `AI_ROOT_CAUSE`) | BIC SHA matches `525dc133…`. Commit object: guan404ming, empty trailers. Round8 correctly saw no on-commit marker and demoted Claude on the fix. Independent worker treats PR #61398 body “Was generative AI tooling used to co-author this PR? Yes — Claude Code with Opus 4.5” as the Airflow-required authorship channel. Protocol still says AI is judged from signals **on the BIC**. Same class of question as w020 (off-commit signal). **Not a catalog TP until that call is made.** |

Independent AI-anchored set after this review: **exactly the 3 unpatched MCP cases (w076, w080, w166)**. No `AI_CODE_FLAWED` remains. **w169 is not in that set** until the PR-body-disclosure call below.

## Record defects that do not flip the verdict

| Worker | Issue | Independent call |
|---|---|---|
| w065 apache/airflow | Recorded `introducer_parent` `ab57e954…` is **not an object** in the clone. Actual parent of BIC `d295e708…` is `86ad6281…`. `secrets_masker.py` (and `DEFAULT_SENSITIVE_FIELDS`) absent there. No AI on BIC. | NOT_AI stands; parent SHA is wrong. |
| w015 pennersr/django-allauth | Round8 BIC `a7ab2d85…` (2023-10-12) is a later helper/extract. Independent smallest first-writer is earlier `eb96b359…` (2023-09-17, same human maintainer), which first assigned untrusted SAML RelayState to `login.state['next']`. | NOT_AI stands; round8 BIC is a carrier. |
| w078 agentscope-ai/agentscope | Round8 BIC `296cd0ef…` ("Initial commit") is too coarse. Independent first-writer of unvalidated `requests.get` is PR #304 member `69bfddf1…` (HONGYI001), no AI marker. | NOT_AI stands; squash should have been decomposed. |
| w088 agentscope-ai/agentscope | Round8 recorded GitHub squash `7a619621…` as BIC with `squash_decomposed=false`. Independent first-writer is `f3a7867d…` (`urlretrieve` of attacker URL), no AI marker. | NOT_AI stands; squash should have been decomposed. |
| w129 vllm-project/vllm | Round8 recorded squash `da78caec…` (PR #6183) as BIC with `squash_decomposed=false`. Independent first-writer of remote `pickle.loads` is `81e47ed9…` (youkaichao), no AI marker. | NOT_AI stands; squash should have been decomposed. |
| w155 mlflow/mlflow | Round8 BIC `3a58f74a…` is PR #8186 squash. Independent first-writer of the truncated dataset digest is `c108c85b…` (dbczumar, 2023-03-11, “Pandas works :D”), no AI marker. | NOT_AI stands; squash should have been decomposed. |
| w064 apache/airflow | Round8 BIC `fe5a2ea7…` is a squash. Independent first-writer is `98d07ca3…` (Amogh Desai, 2025-02-10), no AI marker. | NOT_AI stands; squash should have been decomposed. |
| w030 dgtlmoon/changedetection.io | Round8 BIC `f707c914…` is PR #1866 squash (`squash_decomposed=false`). Independent first-writer of unhardened `XMLParser(strip_cdata=False)` is member `0e332da4…` (dgtlmoon, 2023-10-17), no AI marker. | NOT_AI stands; squash should have been decomposed. |
| w027 modelcontextprotocol/python-sdk | Round8 BIC `86bb54cb…` is #861 (DNS-rebinding protection added, default off). Independent first-writer of unguarded FastMCP HTTP is earlier `557e90d2…` (Integrate FastMCP, David Soria Parra, 2024-12-09), no AI marker. | NOT_AI stands; round8 BIC is incomplete-remediation, not first write. |
| w034 langflow-ai/langflow | Round8 recorded squash `5e2f4b8f…` (#1766) as `introducer_sha` despite `squash_decomposed=true`. Independent first-writer that dropped the UUID `user_id` filter is member `f401e573…` (ogabrielluiz), no AI marker. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w035 gradio-app/gradio | Round8 BIC `287fe678…` (v4 squash). Independent first-writer of `hash_bytes(data.tobytes())` audio cache key is PR #4256 member `9c1c6e64…`. | NOT_AI stands; recorded SHA is a later extract/squash. |
| w004 apache/airflow | Round8 recorded squash `d58da15d…` as BIC. Independent first-writer of `JWTRefreshMiddleware` (`secure = bool(ssl_cert)`) is member `22cba854…`, no AI marker. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w009 apache/airflow | Round8 BIC `23e2c952…`. Independent first-writer of the unguarded Samba `os.path.join` is PR member `ee8785b5…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w059 humansignal/label-studio | Round8 BIC `6ec1e79e…` (1.0.0 squash). Independent first-writer of `HttpResponse(json.dumps(...))` is nested PR member `1ab91a1a…` (Max Tkachenko, 2020-01-09). | NOT_AI stands; recorded SHA is a later port/squash. |
| w005 vllm-project/vllm | Round8 BIC `10141809…`. Independent first-writer of image `tobytes()` hashing is squash-decomposed `faa9b841…`. | NOT_AI stands; squash should have been decomposed. |
| w003 vllm-project/vllm | Round8 BIC `214efc2c…` (PR #10400 squash). Independent first-writer of the assert-as-allowlist is member `a90c408e…` (Max de Bayser, 2024-11-19). Claude trailer is on the fix, demoted. | NOT_AI stands; squash should have been decomposed. |
| w012 vllm-project/vllm | Round8 BIC `4bf82d4b…`. Independent first-writer is `d55cfbda…`. | NOT_AI stands; squash should have been decomposed. |
| w025 vllm-project/vllm | Round8 BIC `e6e42e4b…`. Independent first-writer of unvalidated embedding tensors is PR #6613 member `365c2450…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w026 apache/airflow | Round8 BIC `e2f26537…` (PR #42834 squash). Independent first-writer of `redact(..., max_depth=1)` is member `7e3a1efe…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w033 apache/airflow | Round8 BIC `91ae1733…` (PR #57441 squash). Independent first-writer of body `entity.dag_id` override is member `3e4a56f7…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w043 smithy-lang/smithy-rs | Round8 BIC `45ae7684…`. Independent first-writer of default `serve()` with no timeouts is nested PR member `23aa48a7…`. | NOT_AI stands; recorded SHA is a later carrier/squash. |
| w045 pyasn1/pyasn1 | Round8 BIC `d17e0e17…` (RELATIVE-OID squash). Independent first-writer of the unbounded OID continuation loop is root `0df024a9…` (2005); RELATIVE-OID copied it. | NOT_AI stands; round8 BIC is a later copy, not first write. |
| w047 remix-run/react-router | Round8 BIC `034c0efd…` (leading `//` detector). Independent first-writer of the incomplete CVE-2025-68470 `resolvePath` sanitizer is PR #14529 member `c6a6e5d5…`. | NOT_AI stands; round8 BIC is a parallel `//` check, not this residual. |
| w051 cel-expr/cel-go | Round8 BIC `d561d0a3…` (PR #1009 squash). Independent first-writer of json-tag comma-split without `json:"-"` skip is member `f0b814d6…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w069 stoatchat/stoatchat | Round8 BIC `6b41db98…` (later incomplete IP filter). Independent first-writer of exploitable `/proxy` fetch is `21335b32…`. | NOT_AI stands; round8 BIC is incomplete-remediation, not first write. |
| w075 huggingface/diffusers | Round8 BIC `cee1cd6e…` (PR #5472 squash). Independent first-writer of TOCTOU check-then-load is member `5063e3b8…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w102 langchain-ai/langgraph | Round8 BIC `025b634d…` (PR #3608 squash). Independent first-writer of unsanitized SQLite filter SQL is member `b9fae069…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w128 awslabs/mcp | Round8 BIC `481f56a3…` (PR #1213 squash). Independent first-writer of fail-open policy init is member `9a7a0f60…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w167 stacklok/toolhive | Round8 BIC `826205b5…` (PR #423 squash). Independent first-writer of incomplete private-CIDR table is member `f400124c…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w056 apache/airflow | Round8 BIC `b3a384ee…` (PR #44322 squash). Independent first-writer of leaked `statement`/`orig_error` is member `38af7c11…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w042 apache/airflow | Round8 BIC `3fac5c35…` (PR #29968 squash, “Creating SMTP provider”). Independent first-writer of `SmtpHook.starttls()` with no SSL context is member `b62b7823…` (Hussein Awala, 2023-03-08). Fix-side Claude trailer demoted. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w106 langchain-ai/langgraph | Round8 BIC `5c3ac5d1…` (PR #1948 squash). Independent first-writer of unsegmented `LIKE '<path>%'` (dropped ltree) is member `3b5e629b…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w096 pydantic/pydantic-ai | Round8 BIC `53964f0e…` (PR #5228 squash). Independent first-writer of pre-sanitization `last_index` dangling-tool-call strip is member `6dd1e80c…`. Claude on later v2 fix #6169 demoted. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w074 vllm-project/vllm | Round8 BIC `bf668b5b…` (later `not in self.api_tokens` refactor). Independent first-writer of non-constant-time bearer compare is PR #1106 member `94b51f17…` (`!= "Bearer " + token`). | NOT_AI stands; round8 BIC is a later carrier, not first write. |
| w107 langflow-ai/langflow | Round8 BIC `d3d06be8…` (PR #8271 squash). Independent first-writer of leftmost X-Forwarded-For `get_client_ip` is member `b61d557d…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w068 apache/airflow | Round8 BIC `51fea3e7…` (PR #44126 squash). Independent first-writer of unguarded SFTP `retrieve_directory` join is member `c751c77c…`. Fix-side Claude trailer demoted. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w118 uutils/coreutils | Round8 BIC `a16630fd…` (PR #6621 squash). Independent first-writer of incomplete `path_is_current_or_parent_directory` (misses `./`) is member `733cca26…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w133 pdm-project/pdm | Round8 BIC `d52c79cb…` (PR #1893 squash). Independent first-writer of project `.pdm-plugins` `addsitedir` is member `d6805d92…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w089 vllm-project/vllm | Round8 BIC `360bd67c…` (PR #5191 squash). Independent first-writer of GGUF `int k` + `torch::empty` dequantize kernel is member `89602705…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w142 tryghost/ghost | Round8 BIC `07d60410…` (got v11 `options.lookup` control, still working). Independent first-writer of the dead hook after got v13 is PR #27073 member `be3ef915…`. | NOT_AI stands; round8 BIC is the earlier working control, not this CVE. |
| w091 apache/airflow | Round8 BIC `1c9a6609…` (later MS Graph `proxies` log). Independent first-writer of a proxy-named Connection extra after the denylist is PR #17399 member `aaef66c0…` (`extra__salesforce__proxies`). | NOT_AI stands; round8 BIC is a later carrier, not first write. |
| w150 langflow-ai/langflow | Round8 BIC `8dab3423…`. Independent first-writer of plaintext `Folder.auth_settings` JSON is PR #9095 member `80a95121…`. Squash `9e242024…` is not BIC. | NOT_AI stands; recorded SHA is not the first-writer. |
| w120 apache/airflow | Round8 BIC `4ffb0a6f…` (PR #47432 squash). Independent first-writer of `_token` cookie with omitted `Path` is member `34e5a22f…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w097 vllm-project/vllm | Round8 BIC `e6de9784…` (PR #10216 squash). Independent first-writer of `pickle.loads` in `StatelessProcessGroup.recv_obj` is member `175f2cd5…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w157 projectcapsule/capsule | Round8 BIC `a6b830b1…` (PR #1844 squash). Independent first-writer of webhook typo `namespace/finalize` is member `2327f9c8…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w154 openc3/cosmos | Round8 BIC `a34e61ae…` (2024 incomplete `sanitize_params`). Independent first-writer of `LocalMode.open_local_file` concat is `4ac32f56…` (Ryan Melton, 2022). | NOT_AI stands; round8 BIC is incomplete-remediation, not first write. |
| w158 sqlfluff/sqlfluff | Round8 BIC `106cac1c…` (PR #5230 matching rewrite). Independent first-writer of self-referential `Bracketed(ArithmeticExpression)` is `a36712c4…` (2019). | NOT_AI stands; round8 BIC is a later refactor, not first write. |
| w184 psf/black | Round8 BIC `ed770ba4…` (PR #4176 squash). Independent first-writer of unsanitized magics in the cache filename is member `9cab4c22…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w175 rancher/fleet | Round8 BIC `0bcea06f…` (2023 `createCfg` lookup regression). Independent first-writer of tenant-triggered cluster-admin secret reads is `5bd0498d…` (2021 `valuesFrom`). | NOT_AI stands; round8 BIC is a later second hole, not first write. |
| w177 mervinpraison/praisonai | Round8 BIC `f0076393…` (incomplete `gethostbyname` gate). Independent first-writer of `web_crawl` fetch-after-check SSRF is `58f09a2e…`. | NOT_AI stands; round8 BIC is incomplete-remediation, not first write. |
| w137 apache/airflow | Round8 BIC `4bff1215…` (PR #42049 squash). Independent first-writer of Edge Internal API RPC copy is member `5016386c…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w187 uutils/coreutils | Round8 BIC `d3a2db41…` (PR #7796 squash). Independent first-writer of default `groups=` rgid reuse is member `faced00a…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w194 solana-foundation/anchor | Round8 BIC `7360dbba…` (PR #3878 squash). Independent first-writer of `is_unit_type` / `Pubkey::default()` skip is member `76a91303…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w178 unclecode/crawl4ai | Round8 BIC `392c9239…` (move `handle_crawl_request` into `api.py`). Independent first-writer of Docker `browser_config` proxy plumbing is `ce4f04da…`. | NOT_AI stands; round8 BIC is a later move, not first write. |
| w110 vllm-project/vllm | Round8 BIC `4ef00b5c…` (PR #20349 squash). Independent first-writer of `AutoModel.from_config(..., trust_remote_code=True)` is member `56db3353…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w125 apache/airflow | Round8 BIC `90051561…` (`serialize_object` rewrite). Independent first-writer of truncation `redact(str(...))` is PR #38094 member `97b48266…`. | NOT_AI stands; round8 BIC is a later refactor, not first write. |
| w200 dgtlmoon/changedetection.io | Round8 BIC `cb62404b…` (2025 incomplete `re.sub` filter). Independent first-writer of unsanitized `/static/<group>/` is root `ec3f3480…` (2021). | NOT_AI stands; round8 BIC is incomplete-remediation, not first write. |
| w149 vllm-project/vllm | Round8 BIC `a1a2aaad…`. Independent first-writer of unpinned GGUF `hf_hub_download` is PR #20793 member `1c9bd8ea…`. Squash `11599b0e…` is not BIC. | NOT_AI stands; recorded SHA is not the first-writer. |
| w112 vllm-project/vllm | Round8 BIC `4594fc3b…` (PR #21396 squash). Independent first-writer of Qwen3-Coder `eval()` is member `f48f6da2…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w153 apache/airflow | Round8 BIC `cd8d564e…` (PR #46770 squash). Independent first-writer of unfiltered `/ui/asset_dependencies` loop is member `6c75ded8…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w123 vllm-project/vllm | Round8 BIC `66d617e3…` (PR #7238 squash). Independent first-writer of named `tokenize` override is member `03b690b3…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w162 apache/airflow | Round8 BIC `d8a3ad24…` (PR #52581 squash). Independent first-writer of `lstrip("/log/")` JWT check is member `bee14220…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w134 vllm-project/vllm | Round8 BIC `00c3d68e…` (PR #7446 squash). Independent first-writer of `librosa.load(..., sr=None)` is member `dc425622…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w138 vllm-project/vllm | Round8 BIC `8ebf271b…` (PR #32746 squash). Independent first-writer of urllib3 `parse_url` + leftover raw aiohttp fetch is member `2cc525b2…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w163 vllm-project/vllm | Round8 BIC `5d199ac8…` (later unbounded PyAV video extract). Independent first-writer of STT unbounded `librosa.load` of uploads is PR #12909 member `e4aee908…`. | NOT_AI stands; round8 BIC is a later decoder swap, not first write. |
| w170 apache/airflow | Round8 BIC `ab037cb0…` (PR #49475 squash). Independent first-writer of `TASK_INSTANCE` on `externalLogUrl` is member `e7a999ed…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w174 vllm-project/vllm | Round8 BIC `057daef7…` (PR #116 OpenAI frontend). Independent first-writer of unbounded `n: int = 1` is `3c2b47fc…` (DecodingParams, 2023). | NOT_AI stands; round8 BIC is later HTTP exposure, not first write. |
| w191 vllm-project/vllm | Round8 BIC `56669c1f…` (PR #29037 squash). Independent first-writer of the M-RoPE `prompt_token_ids` type-narrowing assert is member `b2cc9f09…`. Parent `22e44ad5…` is present. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w000 sparklemotion/sqlite3-ruby | Round8 BIC `06ee4ac6…` (2017 aggregators-nil refactor). Independent first-writer of `sqlite3_close_v2` (UAF window) is `da908657…` (2024, PR #557). | NOT_AI stands; round8 BIC is pre-UAF close pattern, not first write. |
| w024 mmaitre314/picklescan | Round8 BIC `373720f5…` (move exclusive PyTorch dispatch into `scan_bytes`). Independent first-writer of exclusive `.bin`/`.pt` routing is `f98f9bd8…`. | NOT_AI stands; round8 BIC is a later move, not first write. |
| w151 shopify/ejson2env | Round8 BIC `0af3ac08…` (subtree-export squash). Independent first-writer of `export KEY=VALUE` is ejson `9568f513…`. | NOT_AI stands; recorded SHA is the export squash. |
| w201 sigstore/rekor | Round8 BIC `5fb05e15…` (PR #337 squash). Independent first-writer of unbounded Alpine gzip `io.Copy` is member `75d7a2e2…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w111 github.com/statamic/cms | Round8 BIC `0620092fa…` (PR #4257 squash). Independent first-writer of Antlers `reduceVar` method dispatch is member `7c67d3bf…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w117 github.com/zalando/skipper | Round8 BIC `d11b8862…` (PR #1848 squash). Independent first-writer of unauthenticated `/routes` is member `6d10e472…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w055 pennersr/django-allauth | Round8 BIC `6890d1d6…` (pennersr rewrite of Okta provider). Independent first-writer of `extract_uid` via `preferred_username` is johri21 `8d410aee…`. | NOT_AI stands; round8 BIC is a later rewrite, not first write. |
| w116 chainguard-dev/melange | Round8 BIC `60b364ce…`. Independent first-writer of native APK install without datahash is apko `8cf8e127…` (PR #426). | NOT_AI stands; round8 BIC is not the native-install first write. |
| w017 project-monai/monai | Round8 BIC `afedafd2…` (#571 squash). Independent first-writer of unsanitized `extractall` is member `c0dfc5e0…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w140 Project-MONAI/MONAI | Round8 BIC `775715d1…` (#56 member). Independent used squash landing `d5e610f48…` because inner SHAs are absent in this clone. | NOT_AI stands either way (DLMED human). |
| w161 streamlit/streamlit | Round8 BIC `f5d05a11…` (#5504 squash; decomposed `99bdaa0c…`). Independent first-writer of P-mode `np.array` hash is member `880a108d…`. | NOT_AI stands; `99bdaa0c` is a later tobytes refactor. |
| w083 twisted/twisted | Round8 BIC `e11cd82…` (2011 visited-set loop check). Independent first-writer of unguarded `Name.decode` is `5fd59e69…` (2001 first add of `protocols/dns.py`). | NOT_AI stands; round8 BIC is incomplete loop-prevention, not first write. |
| w165 rucio/rucio | Round8 BIC `f2c83203…` (operator expansion). Independent first-writer of Oracle `json_exists` `.format()` is `6b403623…`. | NOT_AI stands; round8 BIC is a later expansion of the same sink. |
| w103 vllm-project/vllm | Round8 BIC `721fa3df…` (PR #10 squash). Independent first-writer of unbounded `uvicorn.run` is member `d262ac92…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w172 mlflow/mlflow | Round8 BIC `cbd5f504…` (PR #17945 squash). Independent first-writer of unauthenticated FastAPI job routes is member `715e72fc…`. | NOT_AI stands; recorded SHA is the squash aggregate. |
| w084 tryghost/ghost | Round8 BIC `aca4626c…`. Independent first-writer of the XSS sink is PR member `b8531108…`. | NOT_AI stands; squash should have been decomposed. |
| w149 vllm-project/vllm | Squash siblings carry `gemini-code-assist[bot]`. Pickaxe: flawed GGUF `hf_hub_download(...)` without revision is in human `1c9bd8ea…`; Kimi-K2.5 line in human `c9d5ff04…`. Primary BIC `a1a2aaad…` human-only co-authors. | NOT_AI stands. |

## Bulk independent scans (all 202)

Strict AI-marker regex on the claimed BIC (Claude/Copilot/Codex/Cursor/Gemini/Generated-with; generic `[bot]` excluded):

- 189/195 `NOT_AI` BICs have **no** strict AI marker.
- The only `AI_*` claimed BIC without a strict on-commit marker is **w020** (overturned above).
- `w195`'s recorded squash has Copilot; after decomposition the first-writer does not (overturned above).

Parent pointer `git rev-parse introducer_sha^` vs recorded `introducer_parent`: **185 match**. Exceptions: w065 (wrong SHA, above); two BLOCKED (no SHA); six bundles with null `clone_dir` whose objects still resolve in the obvious clone (`haxtheweb_*`, `apache_airflow`) and then match.

58 squash records: the only squash whose **first decomposed writer lacks AI while the recorded BIC has AI** is **w195**.

82 `NOT_AI` BICs are dated **≤2022** (pre-coding-agent era) and independently have no AI marker → NOT_AI for AI-role.

## Clean-context LLM re-audits (in flight + landed)

One-case clean contexts (bundle + `AUDIT-PROTOCOL` only; round8 records hidden) for unpatched / leader-takeover / early post-2023 rows.

Landed so far (194). **Confirm NOT_AI** (191): w000, w001, w002, w003, w004, w005, w006, w007, w008, w009, w010, w011, w012, w013, w014, w015, w016, w017, w018, w019, w021, w022, w023, w024, w025, w026, w027, w028, w029, w030, w031, w032, w033, w034, w035, w036, w037, w038, w039, w040, w041, w042, w043, w044, w045, w046, w047, w048, w049, w050, w051, w052, w053, w054, w055, w056, w057, w058, w059, w060, w061, w062, w063, w064, w065, w066, w067, w068, w069, w070, w071, w072, w073, w074, w075, w077, w078, w079, w081, w082, w083, w084, w085, w086, w088, w089, w090, w091, w092, w093, w094, w095, w096, w097, w098, w099, w100, w101, w102, w103, w104, w105, w106, w107, w108, w109, w110, w111, w112, w113, w114, w115, w116, w117, w118, w119, w120, w121, w122, w123, w124, w125, w126, w127, w128, w129, w130, w131, w132, w133, w134, w135, w136, w137, w138, w139, w140, w141, w142, w143, w144, w145, w146, w148, w149, w150, w151, w152, w153, w154, w155, w157, w158, w159, w160, w161, w162, w163, w164, w165, w167, w168, w170, w171, w172, w173, w174, w175, w176, w177, w178, w179, w180, w181, w182, w183, w184, w185, w187, w188, w190, w191, w192, w193, w194, w196, w197, w198, w199, w200, w201. Also landed **overturn BLOCKED**: w156, w186. Also landed **overturn EVIDENCE_GAP**: w147. Also landed **policy-open** (not catalog TP): w169.

SHA mismatches (carrier/squash/incomplete-fix recorded as BIC): w000, w003, w011, w017, w018, w032, w054, w065, w083, w104, w121, w140, w152, w161, w165, w004, w005, w009, w012, w015, w024, w025, w026, w027, w030, w033, w034, w035, w042, w043, w045, w047, w051, w055, w056, w059, w064, w068, w069, w073, w074, w075, w078, w084, w088, w089, w091, w096, w097, w102, w103, w106, w107, w110, w111, w112, w116, w117, w118, w120, w123, w125, w128, w129, w133, w134, w137, w138, w142, w149, w150, w151, w153, w154, w155, w157, w158, w162, w163, w167, w170, w172, w174, w175, w177, w178, w184, w187, w191, w194, w200, w201 — see record defects. Others match round8 `introducer_sha`.

All 2023+ clean-context re-audits are landed. Remaining work is **77 provisional** ≤2022 rows (year-heuristic on the *claimed* BIC only — not yet protocol first-writer re-trace). Those cannot hide a catalog TP unless a **different** first-writer than the recorded BIC carries an AI marker; the bulk BIC scan found none on the recorded SHAs.

## Policy calls the packet asked for

1. **w020 `codex/*` branch** — rejected as a BIC signal. NOT_AI.
2. **w195 squash vs Copilot amendment** — squash is not BIC; Copilot did not write the unauthenticated handler. NOT_AI.
3. **w189 / w087 / w156 BLOCKED** — confirmed or newly overturned; closed verdicts cannot land without a 40-hex introducer.
4. **Fix-side AI markers** (73/202 records mention them) — correctly demoted wherever sampled (w195 fix Claude; w035/w168 later Claude on non-BIC).
5. **w169 PR-body Claude disclosure** — open. BIC `525dc133…` has no trailer. Independent worker treats Airflow’s required PR checkbox as co-authorship of that first-writer. Do not catalog as TP until this is decided.

## Suggested ledger correction (not applied)

Follow the round7-correction pattern (`scripts/apply_round7_correction_20260826.py` style: backup, rewrite lane record, patch ledger keys):

1. Flip w020 and w195 `status` / `round8_verdict` to `NOT_AI`; rewrite `ai_marker` / `reasoning` to match BIC-only signals. Flip w156 to `BLOCKED` (no public Studio BIC; helm SHA is not introducer).
2. For w195, set `introducer_sha` to `6cca70b23c068cd862ec0420d126387eed0436d6` (keep squash SHAs in `decomposed_shas`).
3. Optional hygiene: fix w065 `introducer_sha=d010b0dd…` / `introducer_parent`; set w003 `introducer_sha=a90c408e…`; set w004 `introducer_sha=22cba854…`; set w005 `introducer_sha=faa9b841…`; set w009 `introducer_sha=ee8785b5…`; set w012 `introducer_sha=d55cfbda…`; set w015 `introducer_sha=eb96b359…`; set w025 `introducer_sha=365c2450…`; set w026 `introducer_sha=7e3a1efe…`; set w027 `introducer_sha=557e90d2…`; set w030 `squash_decomposed=true` / `introducer_sha=0e332da4…`; set w033 `introducer_sha=3e4a56f7…`; set w034 `introducer_sha=f401e573…`; set w035 `introducer_sha=9c1c6e64…`; set w043 `introducer_sha=23aa48a7…`; set w045 `introducer_sha=0df024a9…`; set w047 `introducer_sha=c6a6e5d5…`; set w051 `introducer_sha=f0b814d6…`; set w056 `introducer_sha=38af7c11…`; set w064 `introducer_sha=98d07ca3…`; set w069 `introducer_sha=21335b32…`; set w073 `introducer_sha=699ec1cb…`; set w075 `introducer_sha=5063e3b8…`; set w078 `squash_decomposed=true` / `introducer_sha=69bfddf1…`; set w084 `introducer_sha=b8531108…`; set w088 `squash_decomposed=true` / `introducer_sha=f3a7867d…`; set w102 `introducer_sha=b9fae069…`; set w128 `introducer_sha=9a7a0f60…`; set w129 `squash_decomposed=true` / `introducer_sha=81e47ed9…`; set w155 `introducer_sha=c108c85b…`; set w167 `introducer_sha=f400124c…`; set w042 `squash_decomposed=true` / `introducer_sha=b62b7823…`; set w106 `introducer_sha=3b5e629b…`; set w096 `introducer_sha=6dd1e80c…`; set w074 `introducer_sha=94b51f17…`; set w107 `introducer_sha=b61d557d…`; set w068 `introducer_sha=c751c77c…`; set w118 `introducer_sha=733cca26…`; set w133 `introducer_sha=d6805d92…`; set w089 `introducer_sha=89602705…`; set w142 `introducer_sha=be3ef915…`; set w091 `introducer_sha=aaef66c0…`; set w150 `introducer_sha=80a95121…`; set w120 `introducer_sha=34e5a22f…`; set w097 `introducer_sha=175f2cd5…`; set w157 `introducer_sha=2327f9c8…`; set w154 `introducer_sha=4ac32f56…`; set w158 `introducer_sha=a36712c4…`; set w184 `introducer_sha=9cab4c22…`; set w103 `introducer_sha=d262ac92…`; set w172 `introducer_sha=715e72fc…`; set w175 `introducer_sha=5bd0498d…`; set w177 `introducer_sha=58f09a2e…`; set w137 `introducer_sha=5016386c…`; set w187 `introducer_sha=faced00a…`; set w194 `introducer_sha=76a91303…`; set w178 `introducer_sha=ce4f04da…`; set w110 `introducer_sha=56db3353…`; set w125 `introducer_sha=97b48266…`; set w200 `introducer_sha=ec3f3480…`; set w149 `introducer_sha=1c9bd8ea…`; set w112 `introducer_sha=f48f6da2…`; set w153 `introducer_sha=6c75ded8…`; set w123 `introducer_sha=03b690b3…`; set w162 `introducer_sha=bee14220…`; set w134 `introducer_sha=dc425622…`; set w138 `introducer_sha=2cc525b2…`; set w163 `introducer_sha=e4aee908…`; set w170 `introducer_sha=e7a999ed…`; set w174 `introducer_sha=3c2b47fc…`; set w191 `introducer_sha=b2cc9f09af…`; set w000 `introducer_sha=da908657…`; set w024 `introducer_sha=f98f9bd8…`; set w151 `introducer_sha=9568f513…`; set w201 `introducer_sha=75d7a2e2…`; set w111 `introducer_sha=7c67d3bf…`; set w117 `introducer_sha=6d10e472…`; set w055 `introducer_sha=8d410aee…`; set w116 `introducer_sha=8cf8e127…`; set w017 `introducer_sha=c0dfc5e0…`; set w140 `introducer_sha=d5e610f48…` (or keep round8 member `775715d1…` if PR objects are fetched); set w161 `introducer_sha=880a108d…`; set w083 `introducer_sha=5fd59e69…`; set w165 `introducer_sha=6b403623…`; set w152 `introducer_sha=45bb0dce…`; set w018 `introducer_sha=a415ce70…`; set w032 `introducer_sha=5c4c9d56…`; set w011 `introducer_sha=17af3bee…`; set w104 `introducer_sha=d65526d6…`; set w054 `introducer_sha=6bd9ee69…`; set w121 `introducer_sha=78b303df…`.

Do not publish ALIAS-* ; do not use introducer date as `published_at`. After a TP-status flip, re-run `scripts/publish_tp_ledger.py` so the catalog drops the two false `AI_CODE_FLAWED` rows.

## Checkpoint — 2026-08-26 evening (do not lose)

Snapshot so a long run cannot forget the load-bearing calls. Ledger still
untouched.

**Files (committed artifacts):**

- `artifacts/round8-independent-double-confirm-20260826.md` — this report
- `artifacts/round8-independent-verdicts-20260826.json` — per-case tracker
- `artifacts/round8-independent-review-index-20260826.json`
- `artifacts/round8-independent-ai-marker-scan-20260826.json`
- `artifacts/round8-independent-parent-ai-scan-20260826.json`
- `artifacts/round8-independent-bic-years-20260826.json`
- Clean-context JSON (gitignored): `.ai-slop/state/research-queue/round8/independent-wNNN.json`

**Counts at this snapshot:** tracker `done=202` / `provisional=0` / `pending=0`
(202 total). Protocol BIC complete for all 202. Clean-context JSON landed: **191** confirm `NOT_AI`, plus w020/w195 overturn NOT_AI, w156/w186
BLOCKED, w147 EVIDENCE_GAP, and w169 policy-open.

**Load-bearing verdicts (do not rubber-stamp round8):**

| Worker | Independent | Note |
|---|---|---|
| w076, w080, w166 | confirm `AI_ROOT_CAUSE` | Unpatched Claude Code MCP TPs |
| w020, w195 | **overturn → `NOT_AI`** | Branch-name / squash-Copilot are not BIC signals |
| w087, w189 | confirm `BLOCKED` | No obtainable 40-hex introducer |
| w156 | **overturn → `BLOCKED`** | Studio SPA not in helm; no public BIC |
| w186 | **overturn → `BLOCKED`** | GHSA mapped Ironic molds onto IPA; no in-repo BIC |
| w147 | **overturn → `EVIDENCE_GAP`** | 1572-file squash reopened XSS; series/3.5 members absent |

Catalog implication after a later ledger correction: public `AI_CODE_FLAWED`
drops to 0; AI-anchored set is the three MCP TPs.

**Next after this lane:** recall clone-404 / empty-repo clusters from the
~28.6k leftover (`in_window_zero_pct_leftover`) and the in-window
reviewed-no-repo set — GitHub transfers, renames, truncated slugs, org-page
false slugs. Do not write the ledger until those recoveries are listed.

## Independent headline (current evidence)

| Verdict | Round8 | Independent (this review) |
|---|---|---|
| AI_ROOT_CAUSE | 3 | **3** (w076, w080, w166) — confirmed |
| AI_CODE_FLAWED | 2 | **0** — both overturned |
| BLOCKED | 2 | **4** — w087/w189 confirmed; w156/w186 overturned from NOT_AI |
| EVIDENCE_GAP | 0 | **1** — w147 (undecomposed squash) |
| NOT_AI | 195 | **194** after two AI_CODE_FLAWED overturns, two NOT_AI→BLOCKED, and w147 EVIDENCE_GAP |
