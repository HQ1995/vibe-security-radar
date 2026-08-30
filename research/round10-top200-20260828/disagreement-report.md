# Round 10 independent re-review — disagreement report

Independent Grok re-review of the 200 cases in `research/round10-top200-20260828/` versus the glm-5.3-flash primary campaign (`primary/wNNN.json`). Reviewers were assigned the same case bundles and `docs/AUDIT-PROTOCOL.md` and were forbidden from reading `primary/`, `report.md`, or other workers' outputs.

Ledger was not written. These are research findings only.

## Scope

- Cases in the campaign: **200**
- Independent reviews compared: **44**
- Missing independent reviews: `w004, w005, w006, w007, w008, w009, w015, w016, w017, w018, w019, w022, w023, w025, w026, w027, w028, w029, w031, w032, w033, w034, w035, w036, w037, w038, w039, w041, w042, w043, w044, w045, w046, w047, w048, w049, w050, w051, w052, w053, w054, w055, w056, w057, w058, w059, w061, w062, w063, w064, w065, w066, w067, w068, w069, w070, w071, w072, w073, w074, w075, w076, w077, w078, w079, w082, w083, w084, w085, w086, w087, w088, w089, w095, w096, w097, w098, w099, w100, w101, w102, w103, w104, w105, w106, w107, w108, w109, w110, w111, w112, w113, w114, w115, w116, w117, w118, w119, w125, w126, w127, w128, w129, w130, w131, w132, w133, w134, w135, w136, w137, w138, w139, w144, w145, w146, w147, w148, w149, w154, w155, w156, w157, w158, w159, w162, w163, w164, w165, w166, w167, w168, w169, w170, w171, w172, w173, w174, w175, w176, w177, w178, w179, w183, w184, w185, w186, w187, w188, w189, w194, w195, w196, w197, w198, w199`
- Invalid independent reviews: **none**
- glm-5.3-flash verdicts: `{"AI_ROOT_CAUSE": 5, "BLOCKED": 1, "NOT_AI": 38}`
- Independent Grok verdicts: `{"AI_ROOT_CAUSE": 5, "FALSE_POSITIVE": 1, "NOT_AI": 38}`

## Headline

- Full core agreement (verdict + BIC + parent + parent-absence + fix + repo + AI-marker state): **6 / 44**
- Any disagreement topic (needs adjudication): **38**
- **Verdict disagreements (this report's primary set): 2**
- Same verdict, different BIC/fix/marker/parent: **36** (listed in an appendix; they are disagreements, but not verdict flips)

### Verdict-pair matrix (glm-5.3-flash → Grok)

| glm-5.3-flash | independent Grok | n |
|---|---|---|
| `BLOCKED` | `NOT_AI` | 1 |
| `NOT_AI` | `FALSE_POSITIVE` | 1 |

### Disagreement topics (all compared cases)

| topic | n |
|---|---|
| parent-absence flag | 29 |
| BIC SHA | 16 |
| BIC parent | 15 |
| fix SHA | 6 |
| AI-marker presence | 3 |
| verdict | 2 |

## Verdict disagreements

Every case below has a different `verdict` between glm-5.3-flash (`primary/`) and independent Grok (`review/`). Evidence quotes are clipped; full records remain in those JSON files.

### 1. `w121` — GHSA-gx77-xgc2-4888 — `ray-project/ray`

- class_id: `alias-11a634b1375c88bebfe978b1`
- advisory_ids: `CVE-2025-34351, GHSA-gx77-xgc2-4888`
- glm-5.3-flash verdict: **NOT_AI**
- independent Grok verdict: **FALSE_POSITIVE**
- disagreement topics: verdict, BIC SHA, BIC parent
- glm BIC: `ce73705ee7043afe6cbafaf67ec20b961f002689`
- grok BIC: `b197fa84a6088e9bdd4e3f829097eef44ed4ed21`
- glm parent: `4130e4dc601504d0cd1c2428a84bb268b6110265`
- grok parent: `77a96d9df09fe4a0731c04448b79b36c129840d3`
- glm fix: `—`
- grok fix: `—`

**glm-5.3-flash AI marker.**

absent — the exact BIC commit object names human author and committer "sampan <sampan@anyscale.com>" and contains only "Signed-off-by: sampan <sampan@anyscale.com>"; it has no Co-Authored-By, Generated-with, bot author, or other AI marker.

**independent Grok AI marker.**

absent; claimed first-write author Sampan S Nayak <sampansnayak2@gmail.com>, committer GitHub <noreply@github.com>; trailers are Signed-off-by: sampan <sampan@anyscale.com> and Co-authored-by: sampan <sampan@anyscale.com> (same human), no Generated-with/Copilot/ChatGPT/Claude/Cursor/bot-author markers.

**glm-5.3-flash bug semantics.**

Ray's token-authentication feature is fail-open by default: the configuration default is "disabled", GetAuthenticationMode() returns DISABLED unless an enabling value is supplied, and the dashboard HTTP authentication middleware immediately calls the requested handler when token auth is disabled. Consequently, a network-reachable default Ray dashboard/Jobs API accepts unauthenticated requests, including POST /api/jobs/, allowing an attacker to submit attacker-controlled jobs and execute arbitrary code on the cluster.

**independent Grok bug semantics.**

The advisory claimed that Ray 2.52.0 ships token authentication for dashboard/Jobs/RPC interfaces disabled unless RAY_AUTH_MODE=token is set, so a network attacker can submit jobs and execute code on an exposed cluster. In-tree this is RAY_CONFIG AUTH_MODE/auth_mode defaulting to "disabled" and GetAuthenticationMode() returning AuthenticationMode::DISABLED unless the string is "token". Vendor docs treat this as a documented, opt-in defense-in-depth control for a trusted-network product model, not a missing authentication step that Ray promised by default.

**glm-5.3-flash flaw origin.**

The insecure feature default first appears in reconstructable PR #58046 member ce73705ee7043afe6cbafaf67ec20b961f002689, which added RAY_CONFIG(std::string, auth_mode, "disabled") in src/ray/common/ray_config_def.h and created src/ray/rpc/authentication/authentication_mode.cc with a fallback to AuthenticationMode::DISABLED. The four-member PR was squash-landed as b197fa84a6088e9bdd4e3f829097eef44ed4ed21 and later authentication integration retained that default through the ray-2.52.0 release.

**independent Grok flaw origin.**

Token-auth scaffolding was first added in b197fa84a6088e9bdd4e3f829097eef44ed4ed21 ([Core] Add authentication token logic, PR #58046), which introduced RAY_CONFIG(std::string, auth_mode, "disabled") and GetAuthenticationMode() falling through to DISABLED. d496ea87808706333703be6ff25ecc9472330fd5 only renamed the env/config key to AUTH_MODE. Later non-master branches briefly flipped the default to token and back; public tags ray-2.52.0 through ray-2.57.0 and HEAD still default to disabled. CVE.org later REJECTED CVE-2025-34351 (2025-12-02/09) as not a valid vulnerability under the vendor security model and as conflicting with CVE-2023-48022. GitHub GHSA-gx77-xgc2-4888 remains listed, but CVE.org rejection is authoritative per protocol.

**glm-5.3-flash reasoning.**

The vulnerability is the default decision, not a later move or the 2.52.0 release/cherry-pick commit. The first member of PR #58046 explicitly chose disabled as the authentication-mode default and made every non-token value resolve to DISABLED. Later work wired token checking into the dashboard and other services, but the shipped middleware remains a no-op under that default, so the pre-existing Jobs API execution surface stays unauthenticated. The PR was squash-landed, so b197fa84a6088e9bdd4e3f829097eef44ed4ed21 is only the mainline aggregate; the published four-member patch reconstructs ce73705ee7043afe6cbafaf67ec20b961f002689 as the smallest commit that wrote the vulnerable lines, and identical blob IDs prove those lines are the ones carried into the squash. Its direct parent lacks both the config line and the authentication source tree. The aggregate is present from ray-2.52.0 onward, consistent with the vendor's feature boundary, while first-party sources identify no patched release and the default remains disabled through ray-2.58.0 in the assigned history. Finally, the exact ce73705e commit object contains no AI authorship marker; PR-page material and later commits are inel…

**independent Grok reasoning.**

Protocol requires CVE.org over GitHub withdrawn_at. CVE-2025-34351 is rejected: the CNA determined the insecure-default claim is not a valid vulnerability given Ray/Anyscale trusted-network security model and duplicates CVE-2023-48022. Therefore the assigned advisory cluster is FALSE_POSITIVE, not NOT_AI. The claimed mechanism (opt-in token auth with default disabled) is real code and was first written in b197fa84, but that is a documented product default, not a judged vulnerability after CNA rejection. No patched version exists because the vendor did not treat this as a defect to flip on the release line. AI markers on the claimed first-write are absent; that is moot once the advisory is rejected.

**remaining_gap.**

- glm: Unpatched: first-party advisories list no patched version, the vendor says default-on authentication is future work, and the assigned history through ray-2.58.0 still defaults AUTH_MODE to "disabled"; therefore no fix_sha or direct_fix_sha exists to report.
- grok: —

### 2. `w122` — GHSA-hjfh-v9xj-7f93 — `gnuboard/gnuboard5`

- class_id: `alias-1c2ab093e620402e9249589f`
- advisory_ids: `CVE-2024-37656, GHSA-hjfh-v9xj-7f93`
- glm-5.3-flash verdict: **BLOCKED**
- independent Grok verdict: **NOT_AI**
- disagreement topics: verdict, BIC SHA, BIC parent, parent-absence flag
- glm BIC: `—`
- grok BIC: `41d21074b5fcf579633c255f3b499434b2d4d46b`
- glm parent: `—`
- grok parent: `04c3efa279d60f646bf3b430750ab5a98fcc6eef`
- glm fix: `e03e01d41098f6a42788e53cb8bd5894ce47cd15`
- grok fix: `e03e01d41098f6a42788e53cb8bd5894ce47cd15`

**glm-5.3-flash AI marker.**

not assessable: no qualifying BIC commit object is reachable; under the BIC-only attribution rule, no AI attribution was inferred from the bulk-import, port, attempted-fix, or final-fix commit objects

**independent Grok AI marker.**

absent; BIC author/committer gnuboard <kagla@naver.com> 2013-09-13; cat-file -p shows subject "그누보드5" with no Co-Authored-By, Generated-with, Copilot, ChatGPT, Claude, Cursor, Gemini, Aider, or bot-author trailers.

**glm-5.3-flash bug semantics.**

In affected gnuboard5, an unauthenticated request to bbs/logout.php can supply a leading-backslash url such as `\google.com`. The handler treats it as having no scheme or host, and its later checks reject `//`, NUL/backslash combinations, or slash-then-backslash forms but not a leading backslash. It then assigns the original attacker-controlled value to `$link`; the affected `goto_url()` emits `Location: \google.com`. User agents normalize the backslash as a slash/network-path reference and navigate off-site, enabling a logout-linked phishing/open-redirect attack.

**independent Grok bug semantics.**

bbs/logout.php takes attacker-controlled GET parameter url and, after logout, passes it to goto_url() as the Location target. Host/scheme checks (parse_url plus later // and https?:// guards) do not treat a leading backslash as an external host, so a URL such as logout.php?url=\\google.com survives validation. Browsers then interpret the backslash redirect as off-site navigation (CWE-601). The incomplete Feb 2024 regex only blocked NUL-backslash and slash-then-backslash, not a single leading backslash.

**glm-5.3-flash flaw origin.**

The causal flaw is a validation/consumption mismatch in `bbs/logout.php`: `parse_url()` is used as a scheme/host gate (since 2024 after `urldecode(str_replace('\\', '', $url))`), while the uncanonicalized `$url` is passed to the redirect sink. The same vulnerable scheme/host validation plus raw `$link = $url` mechanism is already present in the oldest reachable legacy snapshot, `a4b2e70e4d68d7cadad58f170b47aef36ae4fbe5`, and was later bulk-ported into gnuboard5 by `41d21074b5fcf579633c255f3b499434b2d4d46b`. Both are large initial/import aggregates rather than the member commit that originally authored the mechanism, so the smallest qualifying BIC lies before the repository's reachable source history.

**independent Grok flaw origin.**

The first public write of bbs/logout.php already assigned $link=$url after only parse_url scheme/host checks, then called goto_url($link). Immediate parent 04c3efa279d60f646bf3b430750ab5a98fcc6eef is README-only, so 41d21074b5fcf579633c255f3b499434b2d4d46b is the smallest surviving first-write. Later Open Redirect patches (8755c8ece, 5ab91fa0a, 15f203779, 8d912e351) tightened protocol-relative and parse_url cases but left the backslash host bypass. Direct fix e03e01d41098f6a42788e53cb8bd5894ce47cd15 (issue #318) adds safe_filter_url_host() stripping backslashes inside goto_url/alert/confirm, first released in v5.5.17. CVE-2024-37656 remains published, not rejected.

**glm-5.3-flash reasoning.**

The first-party issue fixes the mechanism and affected release: a leading backslash bypasses `bbs/logout.php`'s host/scheme checks, and the affected redirect sink emits the unchecked value. Source comparison proves v5.5.16 has that path and v5.5.17 contains the centralized direct fix `e03e01d41098f6a42788e53cb8bd5894ce47cd15`; the fix's direct parent still emits the raw URL. Causal history also proves the January and February 2024 changes were only incomplete hardening, not introducers, because the same parse-url gate plus raw redirect assignment exists in the oldest reachable 2012 legacy snapshot and later gnuboard5 import. The oldest occurrence is a 899-file initial import whose parent has no source tree beyond a README, and the gnuboard5 occurrences are similarly huge port/release aggregates. The protocol excludes imports/moves/squash aggregates as BICs, and no member commit that originally wrote the vulnerable lines can be reconstructed from reachable refs. Therefore a closed AI/NOT_AI judgment would falsely attribute imported code to an importer; the correct result is BLOCKED at the public-history boundary. With no qualifying BIC object, BIC-only AI inspection is not possible.

**independent Grok reasoning.**

The vulnerability is CWE-601 open redirect from trusting logout.php url after incomplete host checks. The smallest first-write of that sink is the 2013 import of logout.php, not later incomplete remediations. Parent-tree verification shows the file absent immediately before 41d21074b. The #318 fix strips backslashes in the shared goto_url path and lands in v5.5.17. AI judgment is BIC-only: 2013 human import, no AI markers. Therefore NOT_AI. Not FALSE_POSITIVE: CVE-2024-37656 remains published and the PoC matches the code.

**remaining_gap.**

- glm: The exact pre-import member commit and its direct parent that originally authored `bbs/logout.php`'s scheme/host-only validation together with raw `$link = $url` are absent from the reachable repository history. That source commit object is required to establish the smallest BIC and perform BIC-only AI attribution; the available history begins with the non-decomposable 899-file import `a4b2e70e4d…
- grok: —

## Appendix — same verdict, other disagreements

These cases share a verdict but disagree on BIC SHA, parent, parent-absence, fix SHA, repo, and/or AI-marker presence. They are included because the goal asked for every disagreement with glm-5.3-flash, not only verdict flips.

| worker | case | repo | verdict | topics | glm BIC | grok BIC | glm fix | grok fix |
|---|---|---|---|---|---|---|---|---|
| `w000` | GHSA-xgx5-9hx8-gf84 | `jahlives/openssl_encrypt` | AI_ROOT_CAUSE | parent-absence flag | `50bec5d3656d` | `50bec5d3656d` | `993cd13d581a` | `993cd13d581a` |
| `w001` | GHSA-pj8r-rv9w-cfg8 | `jahlives/openssl_encrypt` | NOT_AI | parent-absence flag | `fdc475f1ea7b` | `fdc475f1ea7b` | `1c122790d6d9` | `1c122790d6d9` |
| `w002` | GHSA-9557-234j-7rv9 | `gitpython-developers/gitpython` | NOT_AI | BIC SHA, BIC parent, parent-absence flag | `b825dc74773f` | `3fd37230e76a` | `4b4e47fc1224` | `4b4e47fc1224` |
| `w003` | GHSA-fv4x-pgrr-xh57 | `n8n-io/n8n` | NOT_AI | parent-absence flag, fix SHA | `f81e76aca958` | `f81e76aca958` | `c4488a956f3d` | `3e4fb19caf73` |
| `w010` | GHSA-cwxf-925x-2ccm | `n8n-io/n8n` | NOT_AI | BIC SHA, BIC parent, parent-absence flag | `e23bfdfb3ded` | `d9a5defe88a9` | `2222fe3a6c88` | `2222fe3a6c88` |
| `w011` | GHSA-298h-jpq4-m665 | `gitpython-developers/gitpython` | NOT_AI | BIC SHA, BIC parent | `00c5497f1901` | `33ebe7acec14` | `d9ddb55bdc66` | `d9ddb55bdc66` |
| `w012` | GHSA-wv46-xpj8-pw53 | `gitpython-developers/gitpython` | AI_ROOT_CAUSE | BIC SHA, BIC parent, parent-absence flag, AI-marker presence | `e8d0fbf774d1` | `701ce32fe5ba` | `96a888f4d782` | `96a888f4d782` |
| `w013` | GHSA-c472-7fxr-552c | `jahlives/openssl_encrypt` | AI_ROOT_CAUSE | parent-absence flag | `4c7ae852c784` | `4c7ae852c784` | `57e618d32eab` | `57e618d32eab` |
| `w014` | GHSA-6cm2-456v-hrq7 | `gitpython-developers/gitpython` | NOT_AI | parent-absence flag | `b372e2636634` | `b372e2636634` | `1d51b891d7f2` | `1d51b891d7f2` |
| `w020` | GHSA-5vwr-vwx4-9hc3 | `scriban/scriban` | NOT_AI | AI-marker presence | `46054810b50b` | `46054810b50b` | `dde661d36bb6` | `dde661d36bb6` |
| `w021` | GHSA-7j6f-2mq2-g5vq | `lin-snow/ech0` | NOT_AI | parent-absence flag, AI-marker presence | `fcbe5084a4f0` | `fcbe5084a4f0` | `6df567301072` | `6df567301072` |
| `w030` | GHSA-9x7q-v2pf-x72v | `budibase/budibase` | NOT_AI | BIC SHA, BIC parent | `5787dd3f93d6` | `ba9f7724b342` | `1fecb3fc3497` | `1fecb3fc3497` |
| `w040` | GHSA-5v96-p23j-5mwq | `roskus/prospero-flow-crm` | AI_ROOT_CAUSE | fix SHA | `a9c4845f24e9` | `a9c4845f24e9` | `3ab1b254782e` | `5fd1fe862bbd` |
| `w060` | GHSA-45m3-398w-m2m9 | `olivetin/olivetin` | NOT_AI | parent-absence flag | `6a7187fb5b6a` | `6a7187fb5b6a` | `f044d90d5525` | `f044d90d5525` |
| `w080` | GHSA-xm8c-hvjf-c5q9 | `raineorshine/npm-check-updates` | NOT_AI | parent-absence flag | `43bac8b12f6c` | `43bac8b12f6c` | `b554b84848fc` | `b554b84848fc` |
| `w081` | GHSA-r8rp-5f55-5j9x | `krayin/laravel-crm` | NOT_AI | BIC SHA, BIC parent, fix SHA | `fc536cbc35cb` | `ca3e1b352928` | `97953fd3200b` | `—` |
| `w092` | GHSA-rf5q-vwxw-gmrf | `mtrudel/bandit` | NOT_AI | BIC SHA, BIC parent, fix SHA | `190ada4e3f30` | `e73e379ab598` | `32a89b351d09` | `ae3520dfdbfa` |
| `w094` | GHSA-frh3-6pv6-rc8j | `mtrudel/bandit` | NOT_AI | BIC SHA, BIC parent | `c17de3f3ea24` | `da4027cff7d2` | `8156921a51e6` | `8156921a51e6` |
| `w123` | GHSA-239c-9qhp-4xc9 | `gnuboard/gnuboard5` | NOT_AI | BIC SHA, BIC parent | `a4b2e70e4d68` | `41d21074b5fc` | `e03e01d41098` | `e03e01d41098` |
| `w140` | GHSA-qvfj-hqjq-cmgm | `aeon-toolkit/aeon` | NOT_AI | parent-absence flag | `849946a6862c` | `849946a6862c` | `751918052c0c` | `751918052c0c` |
| `w141` | GHSA-pfvm-w89x-94jw | `sipsorcery-org/sipsorcery` | AI_ROOT_CAUSE | BIC SHA, BIC parent, parent-absence flag | `dd767827e600` | `6edd60f593a4` | `ccb0b5a845ef` | `ccb0b5a845ef` |
| `w142` | GHSA-jwjp-4649-v8jp | `sipsorcery-org/sipsorcery` | NOT_AI | parent-absence flag | `e8f32451ede6` | `e8f32451ede6` | `a2466550bb2a` | `a2466550bb2a` |
| `w143` | GHSA-785c-v4m5-q4wg | `appwrite/templates` | NOT_AI | parent-absence flag | `7840536b8878` | `7840536b8878` | `—` | `—` |
| `w150` | GHSA-6p2w-vm5p-8648 | `chatgptnextweb/nextchat` | NOT_AI | parent-absence flag | `038fa3b30179` | `038fa3b30179` | `—` | `—` |
| `w151` | GHSA-8fjq-3x3v-5fgg | `dundee/gdu` | NOT_AI | parent-absence flag, fix SHA | `30356670ad7f` | `30356670ad7f` | `5d76fab735f1` | `f1d803d81518` |
| `w152` | GHSA-42r3-x6vx-x49x | `crmne/ruby_llm` | NOT_AI | parent-absence flag | `cd0ca3e859d7` | `cd0ca3e859d7` | `9d75b033d7d0` | `9d75b033d7d0` |
| `w153` | GHSA-4c22-7xx9-4rpv | `lazyagi/lazyllm` | NOT_AI | parent-absence flag | `1289fd08aa19` | `1289fd08aa19` | `—` | `—` |
| `w160` | GHSA-xqqh-3w52-q8p7 | `sparklemotion/nokogiri` | NOT_AI | parent-absence flag | `5f0b432a1a9b` | `5f0b432a1a9b` | `5b77f3d1c48c` | `5b77f3d1c48c` |
| `w161` | GHSA-2qqv-3jgq-vpm9 | `siyuan-note/siyuan` | NOT_AI | BIC SHA, BIC parent, parent-absence flag | `ba2193403da7` | `a24f509fc894` | `2d8b98395a91` | `2d8b98395a91` |
| `w180` | GHSA-r232-48q8-3598 | `asyncfuncai/deepwiki-open` | NOT_AI | parent-absence flag | `36d7fa915ecb` | `36d7fa915ecb` | `—` | `—` |
| `w181` | GHSA-74m6-m3xx-3vmj | `keras-team/keras` | NOT_AI | BIC SHA, BIC parent, parent-absence flag | `a762b418bfc1` | `a3ba0b92a259` | `4933ea4a5b3f` | `4933ea4a5b3f` |
| `w182` | GHSA-rcw8-9qrw-27m2 | `nltk/nltk` | NOT_AI | BIC SHA, BIC parent, parent-absence flag | `cc344440f6e0` | `2eabeab4114c` | `bc007200d123` | `bc007200d123` |
| `w190` | GHSA-xgmr-hcvf-x3qc | `owen2345/camaleon-cms` | NOT_AI | parent-absence flag | `7dd48f479225` | `7dd48f479225` | `092de84dc706` | `092de84dc706` |
| `w191` | GHSA-h4w6-wx8r-p68v | `ruby/webrick` | NOT_AI | parent-absence flag | `037e8523a55f` | `037e8523a55f` | `25b0e9206bf5` | `25b0e9206bf5` |
| `w192` | GHSA-mqp7-cg7m-4hhq | `renovatebot/renovate` | NOT_AI | BIC SHA, parent-absence flag, fix SHA | `969d455a3c9b` | `969f2c5f8fff` | `b3f7846c1609` | `f430552de4a0` |
| `w193` | GHSA-m98p-5698-x2wc | `thorsten/phpmyfaq` | NOT_AI | parent-absence flag | `06df60e77611` | `06df60e77611` | `7a82e3ff5917` | `7a82e3ff5917` |

### A1. `w000` — GHSA-xgx5-9hx8-gf84 — `jahlives/openssl_encrypt`

- shared verdict: **AI_ROOT_CAUSE**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `50bec5d3656d62b8dbbb0ce082fd67b8436677fd` / `cdc9c7d814915a9a2c568987b7bcc14f3b7cf533` / `993cd13d581a15821cb170df14627af1f1c1b1c3`
- grok BIC / parent / fix: `50bec5d3656d62b8dbbb0ce082fd67b8436677fd` / `cdc9c7d814915a9a2c568987b7bcc14f3b7cf533` / `993cd13d581a15821cb170df14627af1f1c1b1c3`
- glm AI marker: The exact BIC commit object identifies human author and committer Tobi <jahlives@gmx.ch> and contains both exact AI markers: "🤖 Generated with Claude Code" and "Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>".
- grok AI marker: 🤖 Generated with Claude Code Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>

- glm flaw origin: Commit 50bec5d3656d62b8dbbb0ce082fd67b8436677fd created openssl_encrypt/modules/plugin_system/plugin_ast_analyzer.py and wired analyze_plugin_code() into PluginManager._validate_plugin_file(). Its new DangerousPatternVisitor.visit_Call() and visit_Attribute() recognized specific dangerous names but had no dangerous-dunder set or general dunder-attribute check, thereby first writing the advisory's flawed AST-validation mechanism.
- grok flaw origin: The incomplete visitor was first written in 50bec5d3656d62b8dbbb0ce082fd67b8436677fd ('feat: Replace regex-based analysis with AST-based validation'), which added plugin_ast_analyzer.py as a new file. visit_Attribute only special-cased __builtins__.{eval,exec,...}; there was no DANGEROUS_DUNDER_ATTRIBUTES set and no __subclasses__() call check. Parent cdc9c7d814915a9a2c568987b7bcc14f3b7cf533 has no plugin_ast_analyzer.py (regex checks lived in plugin_manager.py). First-party GHSA-w7gr-9g4g-33mx…

### A2. `w001` — GHSA-pj8r-rv9w-cfg8 — `jahlives/openssl_encrypt`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `fdc475f1ea7bb5c303732701c9a992f9b8effe7e` / `5cce56cf73a737ea904251319358973490d851a3` / `1c122790d6d914909514dbe026d051bc06c50844`
- grok BIC / parent / fix: `fdc475f1ea7bb5c303732701c9a992f9b8effe7e` / `5cce56cf73a737ea904251319358973490d851a3` / `1c122790d6d914909514dbe026d051bc06c50844`
- glm AI marker: absent — the exact BIC commit object names author Tobi <tobster@brain-force.ch> and committer Tobi <tobster@brain-force.ch>; its message has no Co-Authored-By, Generated-with, bot identity, AI trailer, or other AI-attribution marker.
- grok AI marker: absent: author Tobi <tobster@brain-force.ch>, committer Tobi <tobster@brain-force.ch>; commit object has no Co-Authored-By, Generated-with, or bot author

- glm flaw origin: fdc475f1ea7bb5c303732701c9a992f9b8effe7e introduced the original 1.4 v10/v8 generate_key() composition path. It correctly recorded each KDF output but then made the false assumption documented by its new comment, 'The sequential result is NOT in the accumulator yet', and appended the last output a second time. The direct parent already had supporting normalization/XOR helpers but had neither use_xor_composition nor xor_accumulator in generate_key(), so it did not contain the vulnerable composit…
- grok flaw origin: The redundant sequential_result append was first written on the 1.4 line in fdc475f1ea7bb5c303732701c9a992f9b8effe7e ('[1.4] feat(kdf): Update generate_key with v10/v8 XOR logic'), which introduced use_xor_composition, xor_accumulator, per-KDF snapshots, and the comment 'The sequential result is NOT in the accumulator yet - add it now'. Immediate parent 5cce56cf73a737ea904251319358973490d851a3 has XOR helper/collection for hashes but no xor_accumulator and no sequential_result in generate_key. …

### A3. `w002` — GHSA-9557-234j-7rv9 — `gitpython-developers/gitpython`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent, parent-absence flag
- glm BIC / parent / fix: `b825dc74773ffa5c7a45b48d72616b222ad2023e` / `a0cb95c5df7a559633c48f5b0f200599c4a62091` / `4b4e47fc1224e23b0c8ee7220a7192818f2e4abb`
- grok BIC / parent / fix: `3fd37230e76a014cf5c45d55daf0be2caa6948b7` / `9513aa01fab73f53e4fe18644c7d5b530a66c6a1` / `4b4e47fc1224e23b0c8ee7220a7192818f2e4abb`
- glm AI marker: absent: the exact b825dc74773ffa5c7a45b48d72616b222ad2023e commit object names Sebastian Thiel <byronimo@gmail.com> as both author and committer and contains no Co-Authored-By, Generated-with, Assisted-by, agent marker, or bot identity in its message or trailers.
- grok AI marker: absent: author Sebastian Thiel <byronimo@gmail.com>, committer Sebastian Thiel <byronimo@gmail.com>; commit object has no Co-Authored-By, Generated-with, Assisted-by, or bot author

- glm flaw origin: Commit b825dc74773ffa5c7a45b48d72616b222ad2023e completed the vulnerable mechanism by adding multi-line quote state and string_decode() to git/config.py:247-324; string_decode() used unicode_escape/string_escape, converting a literal \n sequence into an embedded LF stored in _sections. The already-existing writer at git/config.py:366-373 emitted embedded LFs with replace('\n', '\n\t') and no quoting or backslash continuation. The direct parent had that unsafe serializer but no multi-line state,…
- grok flaw origin: The unsafe serialize was first written in 3fd37230e76a014cf5c45d55daf0be2caa6948b7 ('implemented config class as far as necessary...'), which added GitConfigParser._write/write_section to lib/git/config.py with fp.write("\t%s = %s\n" % (key, str(value).replace('\n', '\n\t'))). Immediate parent 9513aa01fab73f53e4fe18644c7d5b530a66c6a1 is only a config-reader frame with no _write, write_section, or newline-replace. Later commits (345d6be7 _read override, b825dc74 string_decode/unicode_escape mult…

### A4. `w003` — GHSA-fv4x-pgrr-xh57 — `n8n-io/n8n`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag, fix SHA
- glm BIC / parent / fix: `f81e76aca958dab7392942e8a74b7919e7db42b5` / `06dd4236482d345b1193b87b993c944b117698bd` / `c4488a956f3d48e53c5aa3cc6a99c5851e8b2009`
- grok BIC / parent / fix: `f81e76aca958dab7392942e8a74b7919e7db42b5` / `06dd4236482d345b1193b87b993c944b117698bd` / `3e4fb19caf73276a68b38d45d96b3da5baf7cab7`
- glm AI marker: absent: the exact f81e76aca958dab7392942e8a74b7919e7db42b5 commit object names author and committer Jan Oberhauser <jan.oberhauser@gmail.com>, has subject ':sparkles: Add Git-Node', and contains no Co-Authored-By, Generated-with, bot identity, or other AI trailer/marker.
- grok AI marker: absent: author Jan Oberhauser <jan.oberhauser@gmail.com>, committer Jan Oberhauser <jan.oberhauser@gmail.com>; commit object has no Co-Authored-By, Generated-with, or bot author

- glm flaw origin: The smallest source commit is pull-request member f81e76aca958dab7392942e8a74b7919e7db42b5. It created packages/nodes-base/nodes/Git/Git.node.ts, accepted baseDirectory, passed it to simpleGit({ baseDir, ... }), and immediately exposed add, commit, log, pull, push, and tag operations without neutralizing repository-local command configuration. The public main-history commit 3667b0dd01f82046549b795b98b88983bd7c7fbb is the squash landing of PR #1820, not the smallest BIC; the PR member history is…
- grok flaw origin: The un-neutralized simple-git invocation was first written in reconstructable PR member f81e76aca958dab7392942e8a74b7919e7db42b5 (':sparkles: Add Git-Node', 2021-03-13): Git.node.ts constructed simpleGit({baseDir}) with no git -c pin of command-bearing keys. Immediate parent 06dd4236482d345b1193b87b993c944b117698bd has no packages/nodes-base/nodes/Git/Git.node.ts. GitHub squash-merge 3667b0dd01f82046549b795b98b88983bd7c7fbb ('Add Git node (#1820)') re-landed the same mechanism on master and is …

### A5. `w010` — GHSA-cwxf-925x-2ccm — `n8n-io/n8n`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent, parent-absence flag
- glm BIC / parent / fix: `e23bfdfb3dedde4484b9966185342ae743cb8b71` / `864f869d9b67ff6cbdaa2bda547c0e17d469184f` / `2222fe3a6c886a9059f28e1b6d4bdb10ee420624`
- grok BIC / parent / fix: `d9a5defe88a9d96c0957eed9c3411d2bc6a6703e` / `a82de1dd8fb3a46b9ec2b62358fbda9a6530b31e` / `2222fe3a6c886a9059f28e1b6d4bdb10ee420624`
- glm AI marker: absent — the exact BIC commit object for e23bfdfb3dedde4484b9966185342ae743cb8b71 has author Andreas Fitzek <andreas.fitzek@n8n.io>, committer Andreas Fitzek <andreas.fitzek@n8n.io>, and the sole message 'Add identity resolution'; it contains no Co-Authored-By, Generated-with, b…
- grok AI marker: absent; author Andreas Fitzek <andreas.fitzek@n8n.io>, committer GitHub <noreply@github.com>; commit body is only 'feat(core): Add identity resolution for token exchange (no-changelog) (#28009)' with no Co-Authored-By/Generated-with/bot trailers

- glm flaw origin: The smallest reconstructable origin is PR #28009 member e23bfdfb3dedde4484b9966185342ae743cb8b71, which replaced the nonfunctional IdentityResolutionService skeleton with the email-fallback/linking implementation and the policy that an existing user was never blocked when a claimed role was absent or outside allowedRoles. That member introduced both causal omissions: no verified-email prerequisite before binding by email and no check of the matched user's current role against the trusted key's …
- grok flaw origin: d9a5defe88a9d96c0957eed9c3411d2bc6a6703e first replaced the identity-resolution skeleton with resolveByEmail/provisionUser that link or create users from claims.email. allowedRoles was applied only to an inbound role claim (resolveRoleForExistingUser/resolveRoleForNewUser), never as an authority ceiling on the already-matched local user, and email_verified was not consulted. Parent a82de1dd8fb3a46b9ec2b62358fbda9a6530b31e still threw 'Identity resolution is not yet implemented'.

### A6. `w011` — GHSA-298h-jpq4-m665 — `gitpython-developers/gitpython`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent
- glm BIC / parent / fix: `00c5497f190172765cc7a53ff9d8852a26b91676` / `806450db9b2c4a829558557ac90bd7596a0654e0` / `d9ddb55bdc66ffe8c9932fe460e6b8c8211e47c7`
- grok BIC / parent / fix: `33ebe7acec14b25c5f84f35a664803fcab2f7781` / `—` / `d9ddb55bdc66ffe8c9932fe460e6b8c8211e47c7`
- glm AI marker: absent — the exact BIC commit object records author Sebastian Thiel <byronimo@gmail.com> and committer Sebastian Thiel <byronimo@gmail.com>; its message contains no Co-Authored-By, Generated-with, Assisted-by, or other AI trailer, and neither identity is a bot.
- grok AI marker: absent; author/committer Michael Trier <mtrier@gmail.com>; root commit message is only 'initial project' with no Co-Authored-By/Generated-with/bot trailers

- glm flaw origin: Commit 00c5497f190172765cc7a53ff9d8852a26b91676 generalized the predecessor's bare-only initializer into the public Repo.init API, removed the mandatory --bare argument, retained unrestricted **kwargs, and called git.init(path, **kwargs). Its test explicitly exercised Repo.init(..., template=...). This was not merely a name-only move: enabling ordinary non-bare initialization created the reported template-hook-to-next-commit execution path. A later correction, 15ee0ac0d56a5fb5ba13fae4288621ddd2…
- grok flaw origin: 33ebe7acec14b25c5f84f35a664803fcab2f7781 (root 'initial project') first wrote Repo.init_bare(path, **kwargs) as git.init(**kwargs) plus Git.transform_kwargs, documenting kwargs as extra git-init options. That unguarded forwarding is the mechanism; later init_bare->init rename (00c5497f), package moves, and 15ee0ac0's git.init(path,**kwargs)->git.init(**kwargs) fix are not first-writes.

### A7. `w012` — GHSA-wv46-xpj8-pw53 — `gitpython-developers/gitpython`

- shared verdict: **AI_ROOT_CAUSE**
- disagreement topics: BIC SHA, BIC parent, parent-absence flag, AI-marker presence
- glm BIC / parent / fix: `e8d0fbf774d1f6baa3b481adfe48bd262e43b453` / `faf3c09038b03bc2bdd8545ef34bbf6d7f1cd11f` / `96a888f4d782cb2f80452148e48e60ce4af6d541`
- grok BIC / parent / fix: `701ce32fe5ba8cb622c0e0342a376a6beb47d738` / `65a72839c92768754bd51a37381235842a5ae0d8` / `96a888f4d782cb2f80452148e48e60ce4af6d541`
- glm AI marker: The exact BIC commit object contains `author GPT 5.6 <codex@openai.com>`, `committer Byron <sebastian.thiel@icloud.com>`, the message marker `<!-- agent -->`, and `Co-authored-by: Sebastian Thiel <sebastian.thiel@icloud.com>`. No Generated-with trailer is present. The AI identit…
- grok AI marker: author GPT 5.6 <codex@openai.com>; committer Sebastian Thiel <sebastian.thiel@icloud.com>; body includes 'Reviewed-by: Sebastian Thiel <sebastian.thiel@icloud.com>'; no Co-Authored-By trailer

- glm flaw origin: Commit e8d0fbf774d1f6baa3b481adfe48bd262e43b453 was an incomplete security fix: it first added split_single_char_options = kwargs.get(..., True) and the conditional `if len(key) == 1 and split_single_char_options` to Git._option_candidates in git/cmd.py. That conditional added value candidates for the split form but deliberately left the unsplit compatibility path represented only by the short key, despite transform_kwarg already serializing that path as a joined -<key><value> token. The commit…
- grok flaw origin: 701ce32fe5ba8cb622c0e0342a376a6beb47d738 first added Git._option_candidates as the shared pre-transform candidate list for check_unsafe_options. That first write appends only '-{key}' / '--{dashify(key)}' and never the joined '-{key}{value}' form that transform_kwarg already produced when split_single_char_options=False. Parent 65a72839c92768754bd51a37381235842a5ae0d8 has no _option_candidates. e8d0fbf774d1f6baa3b481adfe48bd262e43b453 later added value-token candidates only under split_single_c…

### A8. `w013` — GHSA-c472-7fxr-552c — `jahlives/openssl_encrypt`

- shared verdict: **AI_ROOT_CAUSE**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `4c7ae852c784c9986d087c5956a77fa563a05a35` / `457f88d09cc365cdbb85b083a29f0956804730be` / `57e618d32eab5163a329a69389f1f75f81fdc90b`
- grok BIC / parent / fix: `4c7ae852c784c9986d087c5956a77fa563a05a35` / `457f88d09cc365cdbb85b083a29f0956804730be` / `57e618d32eab5163a329a69389f1f75f81fdc90b`
- glm AI marker: BIC commit object 4c7ae852c784c9986d087c5956a77fa563a05a35 has human author and committer Tobi <tobster@brain-force.ch>, and contains the exact message marker "🤖 Generated with [Claude Code](https://claude.com/claude-code)" plus the exact trailer "Co-Authored-By: Claude Sonnet 4…
- grok AI marker: 🤖 Generated with [Claude Code](https://claude.com/claude-code); Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>; author/committer Tobi <tobster@brain-force.ch>

- glm flaw origin: The vulnerability first existed at 4c7ae852c784c9986d087c5956a77fa563a05a35, which created the telemetry standalone server and wrote the exact fallback postgresql://telemetry:telemetry@localhost:5432/telemetry in server/telemetry-server/app/config.py. Its direct parent did not contain that path. The child commit fafdfeed1b279cfe61e86cd8adc132b206eef8d4 later duplicated the same flawed design in the new key-server config with postgresql://keyserver:keyserver@localhost/keyserver; that expands the…
- grok flaw origin: 4c7ae852c784c9986d087c5956a77fa563a05a35 first added server/telemetry-server/app/config.py with os.getenv('DATABASE_URL', 'postgresql://telemetry:telemetry@localhost:5432/telemetry'). Parent 457f88d09cc365cdbb85b083a29f0956804730be has no telemetry-server config. fafdfeed1b279cfe61e86cd8adc132b206eef8d4 later copied the same default-URL pattern into the key-server; 8170b3e0be064cdaddbc8ef51c17e21c42d2d3f4 added a separate unified-server postgres_password='changeme' default. The smallest first-w…

### A9. `w014` — GHSA-6cm2-456v-hrq7 — `gitpython-developers/gitpython`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `b372e26366348920eae32ee81a47b469b511a21f` / `bb24f67e64b4ebe11c4d3ce7df021a6ad7ca98f2` / `1d51b891d7f236044a6aa17498ec682b63dad6e6`
- grok BIC / parent / fix: `b372e26366348920eae32ee81a47b469b511a21f` / `bb24f67e64b4ebe11c4d3ce7df021a6ad7ca98f2` / `1d51b891d7f236044a6aa17498ec682b63dad6e6`
- glm AI marker: absent: the exact BIC commit object names author Sebastian Thiel <byronimo@gmail.com> and committer Sebastian Thiel <byronimo@gmail.com>; its message contains no Co-Authored-By, Generated-with, AI, or bot trailer, and neither identity is a bot.
- grok AI marker: absent; author/committer Sebastian Thiel <byronimo@gmail.com>; commit body has no Co-Authored-By/Generated-with/bot trailers

- glm flaw origin: Commit b372e26366348920eae32ee81a47b469b511a21f created the generic Diffable.diff implementation in lib/git/objects/base.py, mixed it into Commit and Tree, accepted **kwargs, inserted other before the path delimiter, and forwarded both channels directly to self.repo.git.diff. This was not merely the later aed099a73025422f0550f5dd5c3e4651049494b2 file move: b372e26366348920eae32ee81a47b469b511a21f first introduced the generic unguarded kwargs sink and broadened the callable surface; subsequent m…
- grok flaw origin: b372e26366348920eae32ee81a47b469b511a21f first added Diffable.diff in lib/git/objects/base.py as git.diff(*args, **kwargs) with args.insert(0, other) when other is not None, documenting kwargs as extra git-diff options. Parent bb24f67e64b4ebe11c4d3ce7df021a6ad7ca98f2 still had Commit.diff(cls, repo, a, b=None, paths=None) without kwargs forwarding or pre-separator other insertion. Later moves (aed099a7 into git/diff.py, cb68eef0 package layout, ea33fe8b Index mixin) are not first-writes of the …

### A10. `w020` — GHSA-5vwr-vwx4-9hc3 — `scriban/scriban`

- shared verdict: **NOT_AI**
- disagreement topics: AI-marker presence
- glm BIC / parent / fix: `46054810b50b03a6d19cd51886321cbbefa5d589` / `—` / `dde661d36bb6b06414546c6b1272fc1b517078c9`
- grok BIC / parent / fix: `46054810b50b03a6d19cd51886321cbbefa5d589` / `—` / `dde661d36bb6b06414546c6b1272fc1b517078c9`
- glm AI marker: absent: the exact BIC commit object (git cat-file -p 46054810b50b03a6d19cd51886321cbbefa5d589) names author Alexandre Mutel <alexandre_mutel@live.com> and committer Alexandre Mutel <alexandre_mutel@live.com>, has the message exactly 'Initial version', contains no Co-Authored-By …
- grok AI marker: —

- glm flaw origin: The earliest public source commit, 46054810b50b03a6d19cd51886321cbbefa5d589 (Initial version), introduced the flawed design atomically: src/Textamina.Scriban/TemplateOptions.cs created LoopLimit with a default of 1000; src/Textamina.Scriban/Runtime/ScriptBinaryExpression.cs implemented range generators as unchecked yield loops; and src/Textamina.Scriban/Helpers/ArrayFunctions.cs implemented Size(IEnumerable) by exhausting non-collections with list.Cast<object>().Count(), with other built-ins li…
- grok flaw origin: Root commit 46054810 first wrote LoopLimit/StepLoop, ArrayFunctions.Size slow-path Count(), RangeInclude yield loops, and unbounded string multiplication together. Later ScriptRange (7d73abb5) relocated range iteration; 2d01bd15/dde661d3 are 2026 remediations, not first-writes.

### A11. `w021` — GHSA-7j6f-2mq2-g5vq — `lin-snow/ech0`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag, AI-marker presence
- glm BIC / parent / fix: `fcbe5084a4f095760ac691039ef1999ce50db333` / `51690dd61a629f7a0f1728583c6de55282699e70` / `6df5673010720847e35d8bb8f60403e2cc4ab313`
- grok BIC / parent / fix: `fcbe5084a4f095760ac691039ef1999ce50db333` / `51690dd61a629f7a0f1728583c6de55282699e70` / `6df5673010720847e35d8bb8f60403e2cc4ab313`
- glm AI marker: absent — the exact fcbe5084a4f095760ac691039ef1999ce50db333 commit object has author and committer 'L1nSn0w <l1nsn0w@qq.com>' and contains no Co-Authored-By, Generated-with, bot identity, or other AI-attribution trailer/marker.
- grok AI marker: —

- glm flaw origin: fcbe5084a4f095760ac691039ef1999ce50db333 introduced the complete flawed mechanism in one feature commit: internal/router/dashboard.go added all three /system/logs routes without an admin gate; internal/handler/dashboard/dashboard.go added GetSystemLogs, SSESubscribeSystemLogs, and WSSubscribeSystemLogs with no role check beyond token validity; and internal/service/dashboard/dashboard.go added direct log query/stream methods with no compensating authorization. At that commit, internal/router/rou…
- grok flaw origin: fcbe5084 first added GetSystemLogs/SSESubscribeSystemLogs/WSSubscribeSystemLogs and the three /system/logs routes without RequireScopes or ensureAdmin. Parent 51690dd6 has dashboard.go with only metrics routes and no log APIs. 6df56730 later added ScopeAdminSettings on HTTP GET routes (first in v4.4.3); OSV git event b934467d is an unrelated Vue refactor.

### A12. `w030` — GHSA-9x7q-v2pf-x72v — `budibase/budibase`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent
- glm BIC / parent / fix: `5787dd3f93d67a0e98d6df645a46aa5f6d69328a` / `80ebb9a740feb94af7bcdc609b6bd5af3305fc96` / `1fecb3fc3497e8db7b60b42cc514ce304ffe3a41`
- grok BIC / parent / fix: `ba9f7724b342491b8274f2c218494b386bf352a9` / `f4c9bd1ec6ea2fdae4b2fa8e16a8cabab2f1b8bd` / `1fecb3fc3497e8db7b60b42cc514ce304ffe3a41`
- glm AI marker: absent — the exact BIC commit object names author and committer Martin McKeaveney <martin@shogunsystems.co.uk>, has the message "REST integration end to end", and contains no Co-Authored-By, Generated-with, bot identity, or other trailers.
- grok AI marker: absent; author/committer Adrià Navarro Redó <adria@budibase.com>; no Co-Authored-By/Generated-with trailers; commit object has no Claude/OpenAI/Copilot/Cursor/Codex/Anthropic marker

- glm flaw origin: The earliest non-refactor origin is 5787dd3f93d67a0e98d6df645a46aa5f6d69328a, which created packages/server/src/integrations/rest.js and passed the builder-controlled datasource URL plus query path directly to node-fetch without connection-time address pinning. Its direct parent has no REST integration file. The later TypeScript rewrite ffc54c37204b69f5b43414c381c694ca91f5d043, blacklist addition 564c724be11895fa6bc1766aef3a149fae3223e3, redirect/helper refactors 9273dfb98130a5673a515d8f1708fbe…
- grok flaw origin: ba9f7724b342491b8274f2c218494b386bf352a9 (Improve security on query import, Adrià Navarro Redó, 2026-03-23) first wrote the OpenAPI validate-then-unpinned-fetch TOCTOU: assertUrlIsSafe plus fetch(currentUrl, {redirect: "manual"}). Immediate parent f4c9bd1ec6ea2fdae4b2fa8e16a8cabab2f1b8bd still had fetchFromUrl as an unguarded fetch(url) with no blacklist check and no assertUrlIsSafe. A later REST remaining sink (9273dfb98130a5673a515d8f1708fbeb2fcbe9ce introducing local fetchWithBlacklist+setDi…

### A13. `w040` — GHSA-5v96-p23j-5mwq — `roskus/prospero-flow-crm`

- shared verdict: **AI_ROOT_CAUSE**
- disagreement topics: fix SHA
- glm BIC / parent / fix: `a9c4845f24e969789360bb711bbf16f2280bf7d5` / `b4cbb51057dcc4eb49798267d6a9d25d694cb1d9` / `3ab1b254782e6cb13855f635176fa4bf2b437304`
- grok BIC / parent / fix: `a9c4845f24e969789360bb711bbf16f2280bf7d5` / `b4cbb51057dcc4eb49798267d6a9d25d694cb1d9` / `5fd1fe862bbdcbacf5d7e05c1c123981d8809674`
- glm AI marker: Present in the exact BIC commit object: "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>". The BIC object names human author and committer Gustavo Novaro <gnovaro@gmail.com>; no other AI trailer or bot identity appears. AI attribution was assessed from this BIC object …
- grok AI marker: Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- glm flaw origin: Commit a9c4845f24e969789360bb711bbf16f2280bf7d5 first connected accounting records to bank accounts and cards: it added the nullable foreign-key columns, accepted bank_account_id and bank_card_id with integer-only validation in app/Http/Controllers/Account/AccountSaveController.php, mass-assigned them, added the Account model relations, and rendered related bank/card data in resources/views/account/index.blade.php. The same commit changed APP_VERSION from 4.9.0 to 4.9.1. Later commit 49d4979bab…
- grok flaw origin: The unvalidated bank foreign keys were first written in a9c4845f24e969789360bb711bbf16f2280bf7d5 (APP_VERSION 4.9.1) when AccountSaveController::save() gained 'bank_account_id'/'bank_card_id' => ['nullable','integer'] and fill() of those fields, and Account gained the matching fillable columns plus unscoped bankAccount()/bankCard() relations. Later Account→Transaction rename (49d4979babf0a8863a5d68b8a9703cf1e29134f8) and extraction of TransactionSaveRequest (8b2633ddb2178c2f79718efdfb906e051ba2…

### A14. `w060` — GHSA-45m3-398w-m2m9 — `olivetin/olivetin`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `6a7187fb5b6a7fa900d7df0f0da8fdb3ebf02734` / `b31cdf15a20c29f6301f02a3ba4ef97b9d99e48c` / `f044d90d5525c4c8e3f421b32ed7eff771c22d36`
- grok BIC / parent / fix: `6a7187fb5b6a7fa900d7df0f0da8fdb3ebf02734` / `b31cdf15a20c29f6301f02a3ba4ef97b9d99e48c` / `f044d90d5525c4c8e3f421b32ed7eff771c22d36`
- glm AI marker: absent: the exact raw BIC commit object has author 'jamesread <contact@jread.com>', committer 'James Read <contact@jread.com>', subject 'feature: OAuth2! :-D', no message body or trailers, no Co-Authored-By or Generated-with marker, and no bot identity.
- grok AI marker: absent; author jamesread <contact@jread.com>, committer James Read <contact@jread.com>; cat-file shows no Co-Authored-By, Generated-with, Copilot, Cursor, ChatGPT, or other AI trailers

- glm flaw origin: Commit 6a7187fb5b6a7fa900d7df0f0da8fdb3ebf02734 introduced OAuth2 in internal/httpservers/oauth2.go as a new file, including the shared registeredStates map, the unlocked registeredStates[state] assignment in handleOAuthLogin, unlocked state lookups, and public /oauth/login and /oauth/callback route registration in internal/httpservers/singleFrontend.go. Its direct parent has neither the OAuth2 source file nor any registeredStates symbol. Later commit a62d58f11955fe192f45da13e23ba996a2759404 mo…
- grok flaw origin: The first OAuth2 implementation added a package-level registeredStates map and wrote it from handleOAuthLogin without a mutex. Later moves into OAuth2Handler and the 3k auth rebuild kept the unsynchronized map; the race existed from that first write until the mutex fix.

### A15. `w080` — GHSA-xm8c-hvjf-c5q9 — `raineorshine/npm-check-updates`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `43bac8b12f6cdbc121c11cc0839e97d7abba0138` / `2ae1ed2d0573d086815dfb7d98e7ecc82aeb0a11` / `b554b84848fc0b08a9d2b3d3db15e351387168cf`
- grok BIC / parent / fix: `43bac8b12f6cdbc121c11cc0839e97d7abba0138` / `2ae1ed2d0573d086815dfb7d98e7ecc82aeb0a11` / `b554b84848fc0b08a9d2b3d3db15e351387168cf`
- glm AI marker: absent: the exact commit object for 43bac8b12f6cdbc121c11cc0839e97d7abba0138 names author Jason O'Neill <CreativeTechGuy@users.noreply.github.com> and committer Jason O'Neill <CreativeTechGuy@users.noreply.github.com>; its message is only 'Add repo urls to new --output command',…
- grok AI marker: absent: BIC author and committer are Jason O'Neill <CreativeTechGuy@users.noreply.github.com>; git cat-file -p and %(trailers) show no Co-Authored-By, Generated-by/Generated-with, Copilot, Cursor, Claude, OpenAI, or other AI commit-object markers.

- glm flaw origin: Commit 43bac8b12f6cdbc121c11cc0839e97d7abba0138 first created the vulnerable repository-display path. In lib/logging.js lines 89-92 it computed repoUrl as getRepoUrl(dep) || '' and appended it directly to the terminal table row; the same commit's new lib/repo-url.js returned a qualifying packageJson.repository string verbatim. Commit c273d79d7ea5daa2cdf9000120c8f5e7f084017b later extended the same unsanitized table mechanism to packageJson.homepage. Refactors and option renames preserved the or…
- grok flaw origin: The first public write of the sink is 43bac8b12f6cdbc121c11cc0839e97d7abba0138 ('Add repo urls to new --output command'). That commit added lib/repo-url.js getRepoUrl() and printed its return value unsanitized in lib/logging.js toDependencyTable() when output includes 'repositoryLink' (later renamed --format repo). For https GitHub/GitLab/Bitbucket repository strings it returns the raw gitURL; hosted-git-info browse URLs are also returned without control-character stripping. Immediate parent 2a…

### A16. `w081` — GHSA-r8rp-5f55-5j9x — `krayin/laravel-crm`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent, fix SHA
- glm BIC / parent / fix: `fc536cbc35cbd3e095379ae0934784b12f6b033e` / `c155fb4d8f3d94bcddb2a46d8e691f326220fb79` / `97953fd3200b9c67e779b87c61f1846e0e430d4b`
- grok BIC / parent / fix: `ca3e1b35292849fc311d28e63fa5b8a63ab5a70f` / `—` / `—`
- glm AI marker: absent: the exact BIC commit object names author and committer as jitendra <jitendra@webkul.com>; its message is only 'Fixed issue when selected a option type attribute' and contains no Co-Authored-By, Generated-with, bot identity, or other AI-attribution trailer.
- grok AI marker: absent: BIC author and committer are jitendra <jitendra@webkul.com>; git cat-file -p shows message 'first commit' with no Co-Authored-By, Generated-by/Generated-with, Copilot, Cursor, Claude, OpenAI, or other AI commit-object markers.

- glm flaw origin: The unsafe update sink already existed as unreachable controller code, but fc536cbc35cbd3e095379ae0934784b12f6b033e is the smallest causal introducer: it first registered Route::put('edit/{id}', 'UserController@update') beneath only the authenticated user middleware, making the attacker-controlled id reach the authorization-free password-update handler. Its direct parent still had UserController::update but no update route, so the reported HTTP attack path was absent.
- grok flaw origin: The smallest surviving public first-write is root commit ca3e1b35292849fc311d28e63fa5b8a63ab5a70f ('first commit'). packages/Webkul/Admin/src/Http/Controllers/User/AdminController.php::update(AdminForm $request, $id) already did $data=$request->all(); bcrypt optional password; $adminRepository->update($data,$id) with no caller-vs-target ownership test. AdminForm::authorize() returns true. Later aa35c242 renamed AdminController to Setting/UserController (move), 0d05af1 renamed Setting to Setting…

### A17. `w092` — GHSA-rf5q-vwxw-gmrf — `mtrudel/bandit`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent, fix SHA
- glm BIC / parent / fix: `190ada4e3f300d5bd55f57eeefc63c1a2f01464e` / `90191d3e120a44482085ad4526280bc233a7ef33` / `32a89b351d09d06b61054daa3bdebb246980ac06`
- grok BIC / parent / fix: `e73e379ab59840e8561b5730878f16e29ab06217` / `267b4af2bda92db66ae42c4ecc05f6da6aa2e9e8` / `ae3520dfdbfab115c638f8c7f6f6b805db34e1ab`
- glm AI marker: absent: git cat-file -p 190ada4e3f300d5bd55f57eeefc63c1a2f01464e shows author Mat Trudel <mat@geeky.net>, committer Mat Trudel <mat@geeky.net>, and only the message 'Fix error where we weren't maintaining tail buffer at the end of chunked reads'; there is no Co-Authored-By trail…
- grok AI marker: absent; BIC author Mat Trudel <mat@geeky.net>, committer GitHub <noreply@github.com>; cat-file -p and git log trailers show no Co-Authored-By, Generated-with/Generated-by, Cursor/Copilot/ChatGPT/OpenAI/Claude/Anthropic/Gemini/Aider/Codex/Devin, or bot identity.

- glm flaw origin: The smallest causal change is PR #437 member 190ada4e3f300d5bd55f57eeefc63c1a2f01464e. It narrowed the pre-existing ["0", _] terminal match to ["0", "\r\n" <> rest] and explicitly left trailers unread. That made trailer bytes flow into the already-present non-progress fallback; its direct parent terminated on every zero-size line and therefore did not contain this trailer-triggered recursion. Mainline commit e73e379ab59840e8561b5730878f16e29ab06217 is the squash aggregate, not the smallest BIC.
- grok flaw origin: The hang was first written in e73e379ab59840e8561b5730878f16e29ab06217 ('Handle pipelined requests (#437)'). That commit changed the last-chunk clause from ["0", _] (which matched any remainder after 0\r\n and returned without looping) to ["0", "\r\n" <> rest] so leftover bytes after an empty trailer could be preserved for pipelining, but it did not consume trailer fields. Immediate parent 267b4af2bda92db66ae42c4ecc05f6da6aa2e9e8 still used ["0", _] and had no 'We should be reading (and ignorin…

### A18. `w094` — GHSA-frh3-6pv6-rc8j — `mtrudel/bandit`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent
- glm BIC / parent / fix: `c17de3f3ea24f0c92b808013cecd20b4cd0d9988` / `537d560d2a1aef62e74109bc041e60ca15a89cd7` / `8156921a51e684a951221da7bc30a70a022f722e`
- grok BIC / parent / fix: `da4027cff7d2b80319e76fe7a32f84beceec490a` / `8968834cea815c31df6aaa6919e0a4f103b2418d` / `8156921a51e684a951221da7bc30a70a022f722e`
- glm AI marker: absent: the exact c17de3f3ea24f0c92b808013cecd20b4cd0d9988 commit object names author Mat Trudel <mat@geeky.net> and committer Mat Trudel <mat@geeky.net>, contains only the subject 'Implement per-message inflate support on read', and has no Co-Authored-By, Generated-with, bot id…
- grok AI marker: absent; BIC author Mat Trudel <mat@geeky.net>, committer GitHub <noreply@github.com>; cat-file -p and git log trailers show no Co-Authored-By, Generated-with/Generated-by, Cursor/Copilot/ChatGPT/OpenAI/Claude/Anthropic/Gemini/Aider/Codex/Devin, or bot identity.

- glm flaw origin: The smallest original commit that wrote the flawed read-side mechanism is pull-request member c17de3f3ea24f0c92b808013cecd20b4cd0d9988, 'Implement per-message inflate support on read'. It added the inflate context, the unbounded :zlib.inflate/2 call, the full IO.iodata_to_binary/1 materialization, and the connection's do_inflate path. GitHub squash da4027cff7d2b80319e76fe7a32f84beceec490a later landed PR #39 on the main branch; the vulnerable file in the final member tree and squash tree is byt…
- grok flaw origin: Unbounded inflate was first written in da4027cff7d2b80319e76fe7a32f84beceec490a (Implement WebSocket extension + permessage-deflate support (#39)), which added lib/bandit/websocket/permessage_deflate.ex with inflate/2 as :zlib.inflate(...) then IO.iodata_to_binary() and no ratio/output cap. Immediate parent 8968834cea815c31df6aaa6919e0a4f103b2418d (Version bump to 0.5.8) has no permessage_deflate.ex and no zlib.inflate in the websocket tree. 8156921a51e684a951221da7bc30a70a022f722e is the first…

### A19. `w123` — GHSA-239c-9qhp-4xc9 — `gnuboard/gnuboard5`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent
- glm BIC / parent / fix: `a4b2e70e4d68d7cadad58f170b47aef36ae4fbe5` / `8751c57ffc0cad044ff247283af7af48db135802` / `e03e01d41098f6a42788e53cb8bd5894ce47cd15`
- grok BIC / parent / fix: `41d21074b5fcf579633c255f3b499434b2d4d46b` / `04c3efa279d60f646bf3b430750ab5a98fcc6eef` / `e03e01d41098f6a42788e53cb8bd5894ce47cd15`
- glm AI marker: absent — the exact BIC commit object names author and committer `whitedot <whitedot@naver.com>` and contains only the message `비표준 그누보드4 첫커밋`; it has no Co-Authored-By, Generated-with, bot identity, or other AI trailer.
- grok AI marker: absent; BIC author/committer gnuboard <kagla@naver.com> 2013-09-13; cat-file -p subject "그누보드5" with no Co-Authored-By, Generated-with, Copilot, ChatGPT, Claude, Cursor, Gemini, Aider, or bot-author trailers.

- glm flaw origin: The vulnerable data-to-form-action mechanism first appears in reachable source history at a4b2e70e4d68d7cadad58f170b47aef36ae4fbe5: the new member-confirmation skin assigns the request-derived $url to f.action during submit without a host allowlist. fd92af89ec6d9822397184f3f20e9eb0b9b86336 later refactored the same sink into a direct <form action="<?php echo $url ?>"> without changing trust semantics. The 974-file GnuBoard5 import 41d21074b5fcf579633c255f3b499434b2d4d46b is not the BIC: its two…
- grok flaw origin: The 2013 import 41d21074b5fcf579633c255f3b499434b2d4d46b first wrote both bbs/member_confirm.php and skin/member/basic/member_confirm.skin.php with form action="<?php echo $url ?>", while common.php @extract($_GET) already populated $url from the query string. Immediate parent 04c3efa279d60f646bf3b430750ab5a98fcc6eef is README-only. Later incomplete remediations added parse_url same-host checks (752ccd850, 2014) and check_url_host (458aecdf7, 2015) but still missed a lone leading backslash. Dir…

### A20. `w140` — GHSA-qvfj-hqjq-cmgm — `aeon-toolkit/aeon`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `849946a6862cf8392c1464eb9b8eb63c9007934f` / `800c3b5388219850c853d14201a9e841187851f6` / `751918052c0cce266b4f7cd4b084408526efc015`
- grok BIC / parent / fix: `849946a6862cf8392c1464eb9b8eb63c9007934f` / `800c3b5388219850c853d14201a9e841187851f6` / `751918052c0cce266b4f7cd4b084408526efc015`
- glm AI marker: absent — the BIC commit object for 849946a6862cf8392c1464eb9b8eb63c9007934f identifies author Arik Ermshaus and committer Arik Ermshaus (both non-bot; patch author address `ermshaua@informatik.hu-berlin.de`), has the subject `Added time series segmentation benchmark (TSSB) and h…
- grok AI marker: absent; author Arik Ermshaus <ermshaua@informatik.hu-berlin.de>, committer Arik Ermshaus <ermshaua@informatik.hu-berlin.de>; commit message has no Co-Authored-By, Generated-with, Cursor, Copilot, ChatGPT, Claude, or bot trailer. Squash-merge 8f81a73 is authored by Arik Ermshaus …

- glm flaw origin: Original feature implementation, not a move or refactor: PR #1755 member commit 849946a6862cf8392c1464eb9b8eb63c9007934f created `aeon/datasets/_tss_data_loaders.py` and first added both the vulnerable loader and the unrestricted `eval(val)` converter. GitHub later squash-landed the two-member PR as 8f81a7324a4f116dd862feda68788b03ff9dc39b.
- grok flaw origin: The eval() CSV converters were first written when the TSSB/HAS data loaders were added in PR #1755. The reconstructable first-write member 849946a6862cf8392c1464eb9b8eb63c9007934f created aeon/datasets/_tss_data_loaders.py with converters = {col: lambda val: np.array(eval(val)) for col in np_cols} in load_time_series_segmentation_benchmark (and a sibling eval converter in load_human_activity_segmentation_datasets). The file and eval sink are absent from that commit parent 800c3b5388219850c853d1…

### A21. `w141` — GHSA-pfvm-w89x-94jw — `sipsorcery-org/sipsorcery`

- shared verdict: **AI_ROOT_CAUSE**
- disagreement topics: BIC SHA, BIC parent, parent-absence flag
- glm BIC / parent / fix: `dd767827e6005e653ec6e8ddc9a43eb1de84d865` / `4b9732a2fb4f776f375f5a4f1e220b5943ef92a5` / `ccb0b5a845efa2fb131fd00de4f5321bae627f29`
- grok BIC / parent / fix: `6edd60f593a467be6ac654c71f57284665f59df1` / `781c6b8e7b8972428a8d520fa16edfc6da8d50ac` / `ccb0b5a845efa2fb131fd00de4f5321bae627f29`
- glm AI marker: present — the BIC commit message (a squash-merged PR by CraziestPower) contains three AI trailers: two lines "Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>" (lines 15 and 23 of the body) and one line "Co-authored-by: Claude Opus 4.6 <noreply@anthropic.com>" (line 27), …
- grok AI marker: Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>; author CraziestPower <29004923+CraziestPower@users.noreply.github.com>, committer CraziestPower <29004923+CraziestPower@users.noreply.github.com>. Squash dd767827 carries the same Claude Opus 4.6 trailer. AI-only-on-fix do…

- glm flaw origin: Commit dd767827e6005e653ec6e8ddc9a43eb1de84d865 ("Add lightweight in-process TURN relay server (RFC 5766) (#1513)", 2026-02-17) introduced src/net/TURN/TurnServer.cs wholesale, including the vulnerable ReceiveUdpAsync structure (line 430: inner try around only ReceiveAsync; line 444: HandleUdpDatagram inside while but outside the inner try; lines 447-450: generic catch outside the while) and the unsupervised fire-and-forget Start() (line 258). The file did not exist in the parent tree (4b9732a2…
- grok flaw origin: The catch-outside-loop UDP receive structure, unguarded HandleUdpDatagram/ParseSTUNMessage, and fire-and-forget Start() were first written when the in-process RFC 5766 TurnServer was added. Reconstructable PR #1513 member 6edd60f593a467be6ac654c71f57284665f59df1 created src/net/TURN/TurnServer.cs with that exact mechanism (ReceiveUdpAsync lines 430-452, HandleUdpDatagram calling ParseSTUNMessage at 478, Start _ = ReceiveUdpAsync() at 258). Parent 781c6b8e7b8972428a8d520fa16edfc6da8d50ac has no …

### A22. `w142` — GHSA-jwjp-4649-v8jp — `sipsorcery-org/sipsorcery`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `e8f32451ede6430766edfe7753c220f83aca1d31` / `411af73e97b450b181978b7ad937819c513f3f7c` / `a2466550bb2a28821c73fb1961bc33dcc467f8cf`
- grok BIC / parent / fix: `e8f32451ede6430766edfe7753c220f83aca1d31` / `411af73e97b450b181978b7ad937819c513f3f7c` / `a2466550bb2a28821c73fb1961bc33dcc467f8cf`
- glm AI marker: absent — the raw BIC commit object has author `Aaron Clauson <aaron@sipsorcery.com> 1617466617 +0100`, committer `Aaron Clauson <aaron@sipsorcery.com> 1618069363 +0100`, subject `Wired up gap blocks and duplicate TSN count to SACK chunk.`, and no body or trailers; there is no bo…
- grok AI marker: absent; author Aaron Clauson <aaron@sipsorcery.com>, committer Aaron Clauson <aaron@sipsorcery.com>; commit message has no Co-Authored-By, Generated-with, Cursor, Copilot, ChatGPT, Claude, or bot trailer. AI-only-on-fix ignored: a2466550 has Co-authored-by: Claude Opus 5 <norepl…

- glm flaw origin: Commit e8f32451ede6430766edfe7753c220f83aca1d31 replaced the parent parser's stored count fields and unimplemented "TODO: Parse reports" with two concrete count-driven parsing loops in src/net/SCTP/Chunks/SctpSackChunk.cs, but did not bound either wire count by chunkLen or the available buffer. That is the smallest commit that created the exploitable unchecked iteration; the direct parent read the counts but did not iterate over attacker-selected report entries.
- grok flaw origin: The unbounded count loops were first written in e8f32451ede6430766edfe7753c220f83aca1d31 (Wired up gap blocks and duplicate TSN count to SACK chunk), which replaced a TODO: Parse reports stub with for (int i=0; i < numGapAckBlocks; i++) and a duplicate-TSN loop using NetConvert.ParseUInt16/32 and no length check. Parent 411af73e97b450b181978b7ad937819c513f3f7c already had the SACK file and parsed the two count fields but did not iterate them. Earlier import d30f229e4333c9e97a056d736544b48211e65…

### A23. `w143` — GHSA-785c-v4m5-q4wg — `appwrite/templates`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `7840536b88784d791ee19461ff091528d6fb5b81` / `59fa20b14997f155cd0980cf50579977b2ccdfc9` / `—`
- grok BIC / parent / fix: `7840536b88784d791ee19461ff091528d6fb5b81` / `59fa20b14997f155cd0980cf50579977b2ccdfc9` / `—`
- glm AI marker: absent: the BIC commit object identifies author and committer as loks0n (Luke B. Silver; non-bot GitHub user), with identical authored/committed timestamps; its complete message is only `fix: esm migration`, its body is empty, and it has no Co-Authored-By, Generated-with, AI, Co…
- grok AI marker: absent; author loks0n <22452787+loks0n@users.noreply.github.com>, committer loks0n <22452787+loks0n@users.noreply.github.com>; commit message is only "fix: esm migration" with no Co-Authored-By, Generated-with, Cursor, Copilot, ChatGPT, Claude, or bot trailer.

- glm flaw origin: Commit 7840536b88784d791ee19461ff091528d6fb5b81 extracted the old inline rejection predicate `missing signature || verified signature` from main.js into a new method named verifyWebhook, returned that predicate unchanged, and changed main.js to reject only `!verifyWebhook(req)`. This semantic inversion converted `missing signature` from a rejection case in the direct parent into a successful verification result. The later TypeScript template commit 4d69364b6a5b9aa1e0d8d9a66c4914b341480718 copie…
- grok flaw origin: The missing-header bypass was first written in 7840536b88784d791ee19461ff091528d6fb5b81 (fix: esm migration). That commit added GithubService.verifyWebhook returning the OR expression as a boolean success value and changed main.js to if (!(await github.verifyWebhook(req))). Parent 59fa20b14997f155cd0980cf50579977b2ccdfc9 inlined if (typeof signature !== "string" || await verify(...)) { return 401 }, which rejects a missing header. Later class/path moves (1a585a21, 34d3aeed) and the TypeScript p…

### A24. `w150` — GHSA-6p2w-vm5p-8648 — `chatgptnextweb/nextchat`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `038fa3b301794050ec7e59325aa00f25b3ce3257` / `9a8497299d11706f096a4fc10ff0ab5af43465c7` / `—`
- grok BIC / parent / fix: `038fa3b301794050ec7e59325aa00f25b3ce3257` / `9a8497299d11706f096a4fc10ff0ab5af43465c7` / `—`
- glm AI marker: absent — the BIC commit object names author and committer Fred <fred@nextchat.dev> (2024-03-14), message body is the single line "fix: add webdav request filter"; no Co-Authored-By, Generated-with, or bot/AI identity anywhere on the object (grep over %an/%ae/%cn/%ce/%B found not…
- grok AI marker: absent; BIC author/committer Fred <fred@nextchat.dev>; no Co-Authored-By, Generated-with, or bot trailers on the commit object

- glm flaw origin: Commit 038fa3b301794050ec7e59325aa00f25b3ce3257 ("fix: add webdav request filter", 2024-03-14, author Fred <fred@nextchat.dev>) created app/api/webdav/[...path]/route.ts and wrote the vulnerable pattern in the same change: `const endpointPath = subpath.join('/');`, suffix-only guards (`endpointPath.endsWith(folder/fileName)`), and `const targetUrl = `${protocol}://${endpoint + endpointPath}`;` with no dot-segment rejection. The parent tree (9a8497299d11706f096a4fc10ff0ab5af43465c7) lacks the fi…
- grok flaw origin: 038fa3b301794050ec7e59325aa00f25b3ce3257 first created app/api/webdav/[...path]/route.ts. That introduction already joined unsanitized catch-all segments into the upstream URL and enforced access only with endsWith(folder)/endsWith(fileName) checks. The parent tree 9a8497299d11706f096a4fc10ff0ab5af43465c7 has no app/api/webdav/ tree; earlier WebDAV support (6f83fbd21278c90cd978108abe54291c38ec10d7) only added a client helper plus a generic CORS proxy. Later commits (99aa0643 joining the full pa…

### A25. `w151` — GHSA-8fjq-3x3v-5fgg — `dundee/gdu`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag, fix SHA
- glm BIC / parent / fix: `30356670ad7f9b4154f78bcb97c2e97de34aeb4e` / `064c8eeda80afa04aa955fdace1f037f5e2f27d4` / `5d76fab735f190fd645896de90ac9982b6382aeb`
- grok BIC / parent / fix: `30356670ad7f9b4154f78bcb97c2e97de34aeb4e` / `064c8eeda80afa04aa955fdace1f037f5e2f27d4` / `f1d803d815181a0779e0a4bd14bce60783b46203`
- glm AI marker: absent — the BIC commit object names author and committer Daniel Milde <daniel@milde.cz> (2021), message is "feat: print current directory path and quit on `Q` key / closes #85"; no Co-Authored-By, Generated-with, or bot/AI identity anywhere on the object.
- grok AI marker: absent; BIC author/committer Daniel Milde <daniel@milde.cz>; body 'closes #85'; no Co-Authored-By, Generated-with, or bot trailers on the commit object

- glm flaw origin: Commit 30356670ad7f9b4154f78bcb97c2e97de34aeb4e ("feat: print current directory path and quit on `Q` key", 2021-08-18, author Daniel Milde <daniel@milde.cz>) introduced the first unguarded post-TUI print: it added `case 'Q': ui.app.Stop(); fmt.Fprintf(ui.output, "%s\n", ui.currentDirPath);` to tui/keys.go, whose parent tree (064c8eeda80afa04aa955fdace1f037f5e2f27d4) contains zero Fprintf occurrences in keys.go. The second sink is commit c6207db5e4611efe7c2ace35869992a80693a75a ("feat: print mar…
- grok flaw origin: 30356670ad7f9b4154f78bcb97c2e97de34aeb4e first added the Q-key handler that stops the TUI then fmt.Fprintf(ui.output, "%s\n", ui.currentDirPath) with no sanitization, plus the io.Writer output field. Parent 064c8eeda80afa04aa955fdace1f037f5e2f27d4 only stopped the app on 'q' and never printed a path. Later c6207db5e4611efe7c2ace35869992a80693a75a added a second unsanitized sink (printMarkedPaths). ee9e4e27e55a9acf34ee04f350a024be9face3de only extracted the existing print into doQuit. 5d76fab735…

### A26. `w152` — GHSA-42r3-x6vx-x49x — `crmne/ruby_llm`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `cd0ca3e859d784cf0441f1872de706579d546db3` / `2b7ff0eefcca66ec65727bfb4b49fa6dd0d20e99` / `9d75b033d7d00c4e1baa9b0afb4828faa8bd6602`
- grok BIC / parent / fix: `cd0ca3e859d784cf0441f1872de706579d546db3` / `2b7ff0eefcca66ec65727bfb4b49fa6dd0d20e99` / `9d75b033d7d00c4e1baa9b0afb4828faa8bd6602`
- glm AI marker: absent — the BIC commit object identifies both author and committer as Carmine Paolino (@crmne), has `committerAttribution:false`, an empty body (`bodyMessageHtml:""`), no Co-Authored-By or Generated-with trailer, and no bot identity.
- grok AI marker: absent; BIC author/committer Carmine Paolino <carmine@paolino.me>; empty body; no Co-Authored-By, Generated-with, or bot trailers on the commit object

- glm flaw origin: The flaw originated in `cd0ca3e859d784cf0441f1872de706579d546db3`, which first replaced explicitly supplied tool names with automatic class-name derivation and added the vulnerable two-`gsub` CamelCase-to-snake_case implementation in `lib/ruby_llm/tool.rb` lines 27-32. Later normalization/refactor/revert commits preserved those regexes, and `17a0ec4f01c2ac1186599551b9ba0c13fad54334` moved the same logic into `RubyLLM::Utils.underscore` and shared it with agent/tool-choice naming; that move is n…
- grok flaw origin: cd0ca3e859d784cf0441f1872de706579d546db3 first wrote Tool.name as super.gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2').gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase.delete_suffix('_tool'). Parent 2b7ff0eefcca66ec65727bfb4b49fa6dd0d20e99 used an explicit tool name string with no CamelCase-splitting regex. Later 1ba6a78 / 818b8ca2 moved and restored the same pattern; ff9c7923 copied it into Agent prompt path generation; 17a0ec4f extracted it into Utils.underscore without changing the regex. 9d75b033d7d00c4e1…

### A27. `w153` — GHSA-4c22-7xx9-4rpv — `lazyagi/lazyllm`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `1289fd08aa192543fea8239ab1225a33daa7cab2` / `ae8c505a296a1706f09b052a0998b83e1d71c88b` / `—`
- grok BIC / parent / fix: `1289fd08aa192543fea8239ab1225a33daa7cab2` / `ae8c505a296a1706f09b052a0998b83e1d71c88b` / `—`
- glm AI marker: absent — the BIC commit object names author and committer wangzhihong <wangzhihong@sensetime.com> (2025-06-03), message "add processer service (#519)"; no Co-Authored-By, Generated-with, or bot/AI identity anywhere on the object.
- grok AI marker: absent; BIC author wangzhihong <wangzhihong@sensetime.com>, committer GitHub <noreply@github.com>; empty body; no Co-Authored-By, Generated-with, or bot trailers on the commit object

- glm flaw origin: Commit 1289fd08aa192543fea8239ab1225a33daa7cab2 ("add processer service (#519)", 2025-06-03, author wangzhihong <wangzhihong@sensetime.com>) first added the /_call endpoint with the lazyllm_call function named by the advisory: `fname, args, kwargs = await request.json(); args, kwargs = load_obj(args), load_obj(kwargs); r = getattr(func, fname)(*args, **kwargs)`, where load_obj() performs cloudpickle.loads on attacker-controlled base64 data. The parent tree (ae8c505a296a1706f09b052a0998b83e1d71c…
- grok flaw origin: 1289fd08aa192543fea8239ab1225a33daa7cab2 first added @app.post('/_call') async def lazyllm_call that does args, kwargs = load_obj(args), load_obj(kwargs) then getattr(func, fname)(*args, **kwargs). Parent ae8c505a296a1706f09b052a0998b83e1d71c88b had only /generate plus CLI-time load_func of operator-supplied --function/--before_function/--after_function; it had no /_call request-body pickle. Earlier c543d8b0529725869899585c19cf21390031294a introduced relay cloudpickle.loads of CLI before/after …

### A28. `w160` — GHSA-xqqh-3w52-q8p7 — `sparklemotion/nokogiri`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `5f0b432a1a9b766eee45d3080384192ea4e84253` / `c0cac010c847724a395d285817a7a33813d54cef` / `5b77f3d1c48cc09c92d10046c448a0866380eb4a`
- grok BIC / parent / fix: `5f0b432a1a9b766eee45d3080384192ea4e84253` / `c0cac010c847724a395d285817a7a33813d54cef` / `5b77f3d1c48cc09c92d10046c448a0866380eb4a`
- glm AI marker: absent — the BIC commit object names author and committer Aaron Patterson <aaron.patterson@gmail.com> (2010-06-14), message "canonicalize takes a block" with no trailer of any kind; no Co-Authored-By, Generated-with, or bot/AI identity anywhere on the object.
- grok AI marker: absent: author Aaron Patterson <aaron.patterson@gmail.com>, committer Aaron Patterson <aaron.patterson@gmail.com>, authorDate 2010-06-14 / commitDate 2011-09-30; message is only 'canonicalize takes a block'; no Co-Authored-By, Generated-with, or bot identity on the commit object

- glm flaw origin: Commit 5f0b432a1a9b766eee45d3080384192ea4e84253 ("canonicalize takes a block", 2010-06-14, author Aaron Patterson <aaron.patterson@gmail.com>) introduced Nokogiri's C14N wrapper in ext/nokogiri/xml_document.c with the call `xmlC14NExecute(doc, cb, ctx, XML_C14N_1_0, NULL, 0, buf);` immediately followed by `xmlOutputBufferClose(buf); return rb_funcall(io, "string", 0);` — no check of the return value, the exact unchecked-return pattern the advisory names. The parent tree (c0cac010c847724a395d285…
- grok flaw origin: The C canonicalize implementation was first written in 2010 as a block-capable wrapper around xmlC14NExecute with no ret<0 check. Later argument, leak, and mode patches kept the same unchecked call until 1.19.1 added rb_raise on failure.

### A29. `w161` — GHSA-2qqv-3jgq-vpm9 — `siyuan-note/siyuan`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent, parent-absence flag
- glm BIC / parent / fix: `ba2193403da71a679dcde24e5b6284278b7240da` / `536879cb848c634743a6559e55c2aa3aa291eaff` / `2d8b98395a910251aea87e90a4fad9c7f954befe`
- grok BIC / parent / fix: `a24f509fc894252d3840392033c7d88e95cea38d` / `0999115c9edf8f6247e7cebbf2d68030f10b904f` / `2d8b98395a910251aea87e90a4fad9c7f954befe`
- glm AI marker: absent — the BIC commit object names author Yingyi / 颖逸 <49649786+Zuoqiu-Yingyi@users.noreply.github.com> and committer GitHub <noreply@github.com> (2024-06-12), a long human feature message; no Co-Authored-By, Generated-with, or bot/AI identity anywhere on the object.
- grok AI marker: absent: author 颖逸 <49649786+Zuoqiu-Yingyi@users.noreply.github.com>, committer 颖逸 <49649786+Zuoqiu-Yingyi@users.noreply.github.com>, 2024-05-13; message is only ':art: Protect secret information'; no Co-Authored-By, Generated-with, or bot identity on the commit object

- glm flaw origin: Commit ba2193403da71a679dcde24e5b6284278b7240da ("Support read-only publish service", 2024-06-12, author Yingyi / 颖逸 <49649786+Zuoqiu-Yingyi@users.noreply.github.com>, committer GitHub) introduced the read-only publish service role that can reach getConf without authentication, together with the first HideConfSecret() implementation in kernel/model/conf.go — a hard-coded masking list (c.AI, c.Api, c.Flashcard, c.LocalIPs, c.Publish, c.Repo, c.Sync, c.System.{AppDir,ConfDir,DataDir,HomeDir,Name,…
- grok flaw origin: The incomplete HideConfSecret blocklist was first written when read-only publish was added. It enumerated AI/API/flashcard/publish/repo/sync and some System paths, but not Export.PandocBin which already existed. Later CookieKey (2025-12-26) and NotebookCrypto (2026-07-04) were added to AppConf without extending the same blocklist, so they leaked by the same fail-open design until 2026-07-24/25 security patches.

### A30. `w180` — GHSA-r232-48q8-3598 — `asyncfuncai/deepwiki-open`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `36d7fa915ecb08f4b19123796ee4af95c1a0eb2c` / `9f76ddd1f58fa3b4661efa93953c001dc35d9f97` / `—`
- grok BIC / parent / fix: `36d7fa915ecb08f4b19123796ee4af95c1a0eb2c` / `9f76ddd1f58fa3b4661efa93953c001dc35d9f97` / `—`
- glm AI marker: absent — BIC author/committer davideuler (human GitHub account), plain feature commit message, no AI trailers; marker grep (claude/copilot/anthropic/openai/generated/co-authored/cursor/junie/manus) on 36d7fa91 and 9df12b23 returns no hits (sentinels printed).
- grok AI marker: absent; author/committer davideuler <davideuler@github.com>; cat-file -p and log body have no Co-Authored-By, Generated-with, or bot identity

- glm flaw origin: Commit 36d7fa915ecb08f4b19123796ee4af95c1a0eb2c ("Move localstorage cache from browser to server side. Cached generated wiki content", 2025-05-08, author/committer davideuler <davideuler@github.com>) first wrote the vulnerable sink: it introduced get_wiki_cache_path() with the unsanitized f-string + os.path.join construction and the GET/POST /api/wiki_cache endpoints consuming user-controlled owner/repo/repo_type/language. The advisory's named sink — 'wiki-cache endpoint constructs file paths f…
- grok flaw origin: Commit 36d7fa915ecb08f4b19123796ee4af95c1a0eb2c first moved wiki cache from browser localStorage onto the server filesystem and introduced get_wiki_cache_path as filename = f"deepwiki_cache_{repo_type}_{owner}_{repo}_{language}.json" joined onto WIKI_CACHE_DIR, then used that path in read_wiki_cache/save_wiki_cache and the /api/wiki_cache endpoints. The parent tree only had a client-side localStorage key of the same shape, not a server path. Later commits added DELETE and relocated the helper t…

### A31. `w181` — GHSA-74m6-m3xx-3vmj — `keras-team/keras`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent, parent-absence flag
- glm BIC / parent / fix: `a762b418bfc162d16b92670d938d53c28ad2766c` / `7924aff56665c09bbd66330ec79de0d29154cafa` / `4933ea4a5b3fcc24ceacdc276f5bb5dfbd06756c`
- grok BIC / parent / fix: `a3ba0b92a2596fbe699356af6fc44572c38c9695` / `3788a9958261b3400e345972e53bb80ff2516b3e` / `4933ea4a5b3fcc24ceacdc276f5bb5dfbd06756c`
- glm AI marker: absent — BIC author/committer Francois Chollet (human, Keras creator), no trailers; marker grep (claude/copilot/anthropic/openai/generated/co-authored/cursor/junie/manus) on a762b418 (BIC), d865f5f0 and 9286df34 (decomposed wave), and 4933ea4a (fix) returns no hits (NONE sentine…
- grok AI marker: absent; author/committer Francois Chollet <francois.chollet@gmail.com>; cat-file -p and log body have no Co-Authored-By, Generated-with, or bot identity

- glm flaw origin: Commit a762b418bfc162d16b92670d938d53c28ad2766c ("Refactor handling of bfloat16 dtype in h5 files.", 2024-01-24, author/committer Francois Chollet <francois.chollet@gmail.com>) first wrote the unvalidated dataset-materialization sink: it introduced the H5Entry.__getitem__ that does `value = self.group[name]` (raw h5py subscript returning a lazy Dataset) followed by `np.array(value, dtype=ml_dtypes.bfloat16)` — the first unbounded np.array() materialization of an attacker-shaped h5 dataset on th…
- grok flaw origin: Commit a3ba0b92a2596fbe699356af6fc44572c38c9695 first added keras_core/saving/saving_lib.py with H5IOStore.get() returning h5py groups/datasets and load_own_variables doing store[key] with no size bound. Parent 3788a9958261b3400e345972e53bb80ff2516b3e has no H5IOStore or saving_lib. Later a762b418bfc162d16b92670d938d53c28ad2766c wrapped that access in H5Entry.__getitem__ (bfloat16 np.array only); 7c3278ff/d865f5f0 folded it into H5IOStore.__getitem__; 9286df3460cb980992c392e9f0fa65f72ba010ba ad…

### A32. `w182` — GHSA-rcw8-9qrw-27m2 — `nltk/nltk`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, BIC parent, parent-absence flag
- glm BIC / parent / fix: `cc344440f6e04fca7f472bad06dcad2eb1247d30` / `a7c0e45d77382cc48824cda9628c392ecdfa3a66` / `bc007200d123c1a98d74c2eb230f5e06c53886b8`
- grok BIC / parent / fix: `2eabeab4114c047649175487d8c97bc2d7f16b69` / `37aaec359272789122119dbfaefc17f4116ed85f` / `bc007200d123c1a98d74c2eb230f5e06c53886b8`
- glm AI marker: absent — the BIC commit object names author/committer Steven Bird, plain human rename/cleanup message (issue 251); grep for claude/copilot/anthropic/openai/generated/co-authored/cursor/junie/manus returns no hits (NONE-cc3444 sentinel via NONE-2EAB/NONE-AB83 screens on the wave …
- grok AI marker: absent; author/committer Dan Blanchard <dan.blanchard@gmail.com>; cat-file -p and log body have no Co-Authored-By, Generated-with, or bot identity

- glm flaw origin: Commit cc344440f6e04fca7f472bad06dcad2eb1247d30 (2009-02-08, Steven Bird, "Changed: files->fileids ... issue 251") wrote the `CorpusReader.__init__` root-handling contract that the advisory names: `if isinstance(root, basestring): ... root = FileSystemPathPointer(root)` — converting any caller-supplied string into a filesystem pointer with zero containment validation. Every subsequent reader inherited it: LinThesaurusCorpusReader (created 2eabeab4114c, 2012-03-28, Dan Blanchard) reads its simN.…
- grok flaw origin: The CWE-73 sinks are constructor-derived paths used without pathsec validation. LinThesaurusCorpusReader was first added in 2eabeab4114c047649175487d8c97bc2d7f16b69 with super().__init__(root, r"sim[A-Z].lsp") then with open(path) on self.abspaths(); parent 37aaec359272789122119dbfaefc17f4116ed85f has no lin.py. PanLexLite independently first bound sqlite3.connect to a caller root in ab8305f6ca297b70731181af89764772eb334c61 (parent used os.environ["PANLEX_LITE"] / hardcoded db.sqlite). pathsec …

### A33. `w190` — GHSA-xgmr-hcvf-x3qc — `owen2345/camaleon-cms`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `7dd48f47922526b5524b055c473d9c93a4cebcc6` / `298dc823fd2eff379c174ef239e571450d3562a4` / `092de84dc706e3d6ed2e66e5c634092dc488fb69`
- grok BIC / parent / fix: `7dd48f47922526b5524b055c473d9c93a4cebcc6` / `298dc823fd2eff379c174ef239e571450d3562a4` / `092de84dc706e3d6ed2e66e5c634092dc488fb69`
- glm AI marker: absent — BIC author Owen Peredo <owenperedo@gmail.com> (human, repo owner), committer same, plain 2016 feature message; marker grep (claude/copilot/anthropic/openai/generated/co-authored/cursor/junie/manus) on 7dd48f47 returns no hits (NONE-7DD48F sentinel).
- grok AI marker: absent; author Owen Peredo <owenperedo@gmail.com>, committer Owen Peredo <owenperedo@gmail.com>; cat-file -p shows only subject "admin: added button to send test emails \"smtp configuration\"" with no Co-Authored-By, Generated-with, or bot identity

- glm flaw origin: Commit 7dd48f47922526b5524b055c473d9c93a4cebcc6 ("admin: added button to send test emails \"smtp configuration\"", 2016-06-16, author Owen Peredo <owenperedo@gmail.com>; parent 298dc823fd2eff379c174ef239e571450d3562a4) first wrote the named sink: it created the test_email action in app/controllers/camaleon_cms/admin/settings_controller.rb with `CamaleonCms::HtmlMailer.sender(params[:email], 'Test', {content: 'Test content'}).deliver_now` and, on rescue, `render inline: e.message, status: 502` —…
- grok flaw origin: On 2016-06-16 Owen Peredo added test_email and chose render inline: e.message for SMTP errors. That is the first write of the SSTI sink. Later RuboCop and site-data edits kept the same inline render; the 2.9.2 fix only switched it to render plain:.

### A34. `w191` — GHSA-h4w6-wx8r-p68v — `ruby/webrick`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `037e8523a55f2c986b21106ef105517179bf3574` / `392296c12de9d7f9be03a8205250ba0844cb9d38` / `25b0e9206bf5991c6274893d53c428d23b3f2292`
- grok BIC / parent / fix: `037e8523a55f2c986b21106ef105517179bf3574` / `392296c12de9d7f9be03a8205250ba0844cb9d38` / `25b0e9206bf5991c6274893d53c428d23b3f2292`
- glm AI marker: absent — BIC 037e8523a55f2c986b21106ef105517179bf3574 is a 2003 git-svn import by human author gotoyuzo (GOTOU Yuuzou), author == committer, message is a plain '* lib/webrick: imported.' plus git-svn-id trailer; marker grep `git log --format='%an <%ae>%n%cn <%ce>%n%B' -1 037e852…
- grok AI marker: absent; author gotoyuzo <gotoyuzo@b2dd03c8-39d4-4d8f-98ff-823fe69b080e>, committer gotoyuzo <gotoyuzo@b2dd03c8-39d4-4d8f-98ff-823fe69b080e>; cat-file -p shows only svn import subject "* lib/webrick: imported." with git-svn-id and no Co-Authored-By, Generated-with, or bot identity

- glm flaw origin: Commit 037e8523a55f2c986b21106ef105517179bf3574 ("* lib/webrick: imported.", 2003-07-23, author/committer gotoyuzo <gotoyuzo@b2dd03c8-39d4-4d8f-98ff-823fe69b080e>, git-svn-id svn+ssh://ci.ruby-lang.org/ruby/trunk@4130, parent 392296c12de9d7f9be03a8205250ba0844cb9d38) is the first public commit of the webrick standalone tree and already contains the entire named sink verbatim: lib/webrick/httprequest.rb:297 `read_header(socket) # trailer + CRLF` inside read_chunked, :298 `@header.delete("transfe…
- grok flaw origin: The 2003 webrick import first wrote read_chunked calling read_header (commented trailer + CRLF) which always did @header = HTTPUtils::parse_header(@raw_header). That merge of trailer lines into the same header map is the SSTI-equivalent first write of this sink. Later smuggling patches (reject dual CL+TE, CRLF checks) left trailer CL promotion intact until 25b0e92 blocked content-length among DISALLOWED_TRAILERS.

### A35. `w192` — GHSA-mqp7-cg7m-4hhq — `renovatebot/renovate`

- shared verdict: **NOT_AI**
- disagreement topics: BIC SHA, parent-absence flag, fix SHA
- glm BIC / parent / fix: `969d455a3c9b97fb874e4fd11ec30cbc2c354304` / `5145c044ffcc89b88efe2eb57e8c1a823e9106f8` / `b3f7846c1609d9af420e5ef6647ce0d744947e0c`
- grok BIC / parent / fix: `969f2c5f8fff57851e70d199d706b19ab426e785` / `5145c044ffcc89b88efe2eb57e8c1a823e9106f8` / `f430552de4a07caadcdc6c413b2a506b539f10ee`
- glm AI marker: absent — the BIC commit object names author Rhys Arkins, committer GitHub, plain human message (#6003); no Co-Authored-By, Generated-with, or bot/AI identity anywhere on the object (grep NONE sentinel).
- grok AI marker: absent; author Rhys Arkins <rhys@arkins.net>, committer Rhys Arkins <rhys@arkins.net>; cat-file -p shows only subject "fix(gradle-wrapper): use distribution url instead of version" with no Co-Authored-By, Generated-with, or bot identity

- glm flaw origin: Commit 969d455a3c9b97fb874e4fd11ec30cbc2c354304 ("fix(gradle-wrapper): use distribution url instead of version (#6003)", 2020-04-19, author Rhys Arkins <rhys@arkins.net>, committer GitHub, no AI trailers) introduced `getDistributionUrl(newPackageFileContent)` — parsing distributionUrl out of the repository's gradle-wrapper.properties — and appended it into the shell command: `cmd += ' --gradle-distribution-url ${distributionUrl}'` unquoted, inside the string-command pipeline executed via exec. …
- grok flaw origin: PR #6003 member 969f2c5f (2020-04-19, Rhys Arkins) first added getDistributionUrl() and cmd += ` --gradle-distribution-url ${distributionUrl}` in lib/manager/gradle-wrapper/artifacts.ts. Parent 5145c044 only interpolated config.toVersion as --gradle-version. That command already went through child_process.exec (always a shell); 32.124.0 (892595aea) later switched to spawn but forced shell:true, preserving the same evaluation. 42.68.5 f430552de stopped using shell by default, which is the adviso…

### A36. `w193` — GHSA-m98p-5698-x2wc — `thorsten/phpmyfaq`

- shared verdict: **NOT_AI**
- disagreement topics: parent-absence flag
- glm BIC / parent / fix: `06df60e776115aaeaeb99397330786cb89fcae63` / `b1d25c3bf793de015917b6653facb8eef2e2a772` / `7a82e3ff591790a2f00a5fb4c7da861edaacde9b`
- grok BIC / parent / fix: `06df60e776115aaeaeb99397330786cb89fcae63` / `b1d25c3bf793de015917b6653facb8eef2e2a772` / `7a82e3ff591790a2f00a5fb4c7da861edaacde9b`
- glm AI marker: decomposed-wave marker only — b097f61004d8103e14c694fb727998ae440fa265 (2025-08-03, urldecode of image filenames, part of the file-read pipeline the disclosure flows through) is authored by copilot-swe-agent[bot] with 'Co-authored-by: thorsten'; the BIC 06df60e77611 itself carri…
- grok AI marker: absent; author Thorsten Rinne <thorsten@phpmyfaq.de>, committer Thorsten Rinne <thorsten@phpmyfaq.de>; cat-file -p shows only subject "fix: avoid image display errors in PDF due to SSL verification and caching issues" with no Co-Authored-By, Generated-with, or bot identity

- glm flaw origin: Commit 06df60e776115aaeaeb99397330786cb89fcae63 ("fix: avoid image display errors in PDF due to SSL verification and caching issues", 2024-11-08, author+committer Thorsten Rinne) rewrote the Wrapper::Image override to read EVERY resolved image path from disk — `$data = file_get_contents(PMF_ROOT_DIR . $file)` — before checking `checkBase64Image($data)`, i.e. imagecreatefromstring() on arbitrary local file bytes. This converted the image handler into the file-read + warning-exception primitive t…
- grok flaw origin: On 2024-11-08 Thorsten Rinne (06df60e7) rewrote Wrapper::Image() to load PMF_ROOT_DIR.$file via file_get_contents and validate with checkBase64Image() (imagecreatefromstring without swallowing warnings), then still called parent::Image(). Parent b1d25c3b only parse_url()d and delegated to TCPDF. Later 91ce6440/b709ebe6 restricted concatenatePaths to content/ and isWithinRoot (classic traversal), leaving the in-root leak. 4.1.7 7a82e3ff returns if checkBase64Image fails and swallows E_WARNING ar…

## Reproduction

```bash
python3 research/round10-top200-20260828/compare_results.py
python3 research/round10-top200-20260828/build_disagreement_report.py
```

Outputs: `comparison.jsonl`, `comparison-summary.json`, `disagreements.jsonl`, `disagreement-report.md`.

