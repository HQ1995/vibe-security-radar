# Original-baseline odd AI_INCOMPLETE_REMEDIATION (patch-delta)

**Status: `REVIEW_COMPLETE`.** Assigned original-baseline rows with `counting.fp211_released_publication_admitted=true` and `causal_class=AI_INCOMPLETE_REMEDIATION` were re-reviewed under the CONTRACT.md patch-delta rule. The original vulnerability need not be AI-origin. Rollback may reopen a broader old hole. KEEP requires an AI-authored explicit security attempt that materially adds or rewrites a guard/parser/normalizer/denylist/allowlist; a released artifact that contains that incomplete boundary; a first-party GHSA covering the residual bypass in that boundary; a later same-mechanism closure that directly amends the AI-added boundary; and no unrelated untouched sibling path. Identity, topology, release, and uniqueness must still pass. Label remains `AI_INCOMPLETE_REMEDIATION`. Old parity red-team verdicts are counterevidence, not binding.

Schema: every `AI_INCOMPLETE_REMEDIATION` row records `remediation_patch_delta_gate` in addition to the seven legacy gates. KEEP requires `remediation_patch_delta_gate=PASS` and `but_for_gate=PASS`, with `but_for_gate` interpreted by the patch-delta rule. NARROW/REJECT/UNKNOWN record the corresponding non-PASS patch-delta value. Substantive verdicts are unchanged.

Assigned ordinals exactly `[135, 137, 147, 161, 163, 167, 171, 179]`.

KEEP here is a proposal only. Canonical ledger, publication data, and other workers were not edited. No commit, reset, or clean.

| Ordinal | GHSA | Patch-delta | Old parity |
|--------:|------|-------------|------------|
| 135 | GHSA-FVVP-RJ8G-C7GC | **NARROW** | KEEP |
| 137 | GHSA-M4WX-M65X-GHRR | **KEEP** | KEEP |
| 147 | GHSA-56C3-VFP2-5QQJ | **KEEP** | KEEP |
| 161 | GHSA-VC8F-X9PP-WF5P | **KEEP** | KEEP |
| 163 | GHSA-Q6RR-FM2G-G5X8 | **NARROW** | NARROW |
| 167 | GHSA-6Q7J-XR26-3H2C | **NARROW** | NARROW |
| 171 | GHSA-MV93-W799-CJ2W | **KEEP** | KEEP |
| 179 | GHSA-5XXX-QHH7-9287 | **KEEP** | KEEP |

Clones: `/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-odd/clones/`. Advisory JSON: `/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-odd/pages/`.

## Verdicts

### Ordinal 135 - NARROW (GHSA-FVVP-RJ8G-C7GC)

Repo GHSA (global 404) aliases CVE-2026-34745 and states the CVE-2026-33645 checkSum sanitization was applied to authenticated `/api/uploadChunked` and not to unauthenticated `/api/uploadChunked/public`. Copilot 157386c8 (2025-11-23) is an explicit filename/Popen rem: `secure_filename` plus argv `Popen`. It leaves `checkSum = request.form.get('checkSum')` on the public chunked handler. Human 92c28953 (2026-03-22) is the first alnum `re.sub` on authenticated checkSum and is an ancestor of v1.5.2. Human 70b5b35a copies that checkSum/realpath pattern onto the public handler; merge carrier b7691560 is first in v1.5.3. The later closure amends the human sibling checkSum leftover, not Copilot's filename guard. Candidate is in v1.3.0-v1.5.2. Patch-delta KEEP refused.

### Ordinal 137 - KEEP (GHSA-M4WX-M65X-GHRR)

Peeled v3.11.1 commit equals Claude-coauthored 46cbbdde. That commit adds `options.nesting === true && options.require === false` and documents omit-require as out of scope. Repo and global GHSA alias CVE-2026-47137 and name that strict-equality bypass. Human 01a7552 is not an ancestor of v3.11.1 or v3.11.3 (`merge-base --is-ancestor` exit 1). Complete 86ab819f is absent from v3.11.3 and present in v3.11.4. Same constructor guard, omitted require shape. Pre-3.11.1 nesting RCE is the parent hole and is allowed under patch-delta.

### Ordinal 147 - KEEP (GHSA-56C3-VFP2-5QQJ)

Claude-coauthored fork-merge d9d847f2 first adds `validateUrlSync` (parent 643c98bc has the file without that function). Official range starts at 2.47.4. Helper is IPv4 `PRIVATE_IP_RANGES` / localhost-set only. GHSA names IPv4-mapped IPv6 bypass of that sync validator for SDK embedders. 9639f757 extends the same function; first in v2.47.14. Window v2.47.4-v2.47.13. Async IPv6 on `validateWebhookUrl` is a different deployment path named as not primarily affected.

### Ordinal 161 - KEEP (GHSA-VC8F-X9PP-WF5P)

Claude 042af9ca rewrites the parse_str prototype-pollution guard from `key.includes(...)` to `/__proto__|constructor|prototype/.test(key)`. First tag v2.0.39; absent from v2.0.38. GHSA aliases CVE-2026-33994 and names `RegExp.prototype.test` overwrite as the residual of that rewrite. 345a6211 replaces the regex with `Set.has` in `parse_str.ts`; first in v3.0.25. Same sink, omitted hijackable builtin. The same commit also touches unserialize; this row does not count that sibling.

### Ordinal 163 - NARROW (GHSA-Q6RR-FM2G-G5X8)

Repo GHSA names `array * int` in `ScriptArray<T>.TryEvaluate` as a missed sibling of GHSA-c875 / GHSA-24c8, range `>= 3.0.0`. Copilot 2d01bd15 (7.0.0) edits `ScriptBinaryExpression.cs` and `ArrayFunctions.cs`, not `ScriptArray.cs`. Completing 205ca6a7 edits `ScriptArray.cs`. Untouched sibling path. Distinct from 167.

### Ordinal 167 - NARROW (GHSA-6Q7J-XR26-3H2C)

Repo GHSA names non-enforcing `ExpressionDepthLimit` (log then continue), range `>= 6.6.0`. Human b5ac4bf (2026-03-19) already has that helper on 6.6.0. Copilot f55280a0 (2026-03-21) wraps `ParseArrayInitializer` with `EnterExpression`/`LeaveExpression` and does not rewrite the helper. 8fdbd687 throws `FatalParserException` inside `EnterExpression`, amending the pre-AI helper. Distinct from 163.

### Ordinal 171 - KEEP (GHSA-MV93-W799-CJ2W)

Codex c417af46 adds `_value_to_string_safe` rejecting CR/LF/NUL in values only; first in 3.1.49, absent from 3.1.48. Repo GHSA names section/option newline as bypass of that CVE-2026-42215 patch. Codex 54538428 adds `_assure_config_name_safe` on `add_section`/`set`/`set_value`/`add_value`; first in 3.1.50. Same write API, omitted name fields. Distinct from 179. Shared SHA with later GitPython config rows does not merge mechanisms.

### Ordinal 179 - KEEP (GHSA-5XXX-QHH7-9287)

Codex 701ce32f author `GPT 5.6 <codex@openai.com>` introduces `unsafe_git_revision_options = ["--output","-o"]` and wires it to `Repo.blame`. Parent has no denylist. Tags 3.1.51-3.1.58. Repo GHSA (global 404) names omitted `--contents`/`-S` on that blame denylist. 1b0d2d9b adds `unsafe_git_blame_options = unsafe_git_revision_options + ["--contents","-S"]`; first in 3.1.59. Same denylist, omitted read options. Distinct from 171.

## Sources

| Clone | HEAD | Date |
|-------|------|------|
| fireshare | `7889e7f1166c5092c42a00768d03a3182d23193b` | 2026-08-08T08:33:21-06:00 |
| vm2 | `7a1f5100b96f48d34e0fe104ab37c0acc5944f92` | 2026-05-19T00:24:37+09:00 |
| n8n-mcp | `5e3c425faaf0823b320c67ed8936903b00c55267` | 2026-08-09T12:48:38+02:00 |
| locutus | `0f8ed0e29dd1d8073a718d4c2226a330eb9c4e46` | 2026-05-16T12:15:55+02:00 |
| scriban | `420513a9d017fa54b23ba78a9f21a12187a8dd97` | 2026-07-29T09:18:31+02:00 |
| GitPython | `f44c1fb0e5dc3b3f0df58c7834ceed336f0d36fc` | 2026-08-11T15:54:56+02:00 |

Leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical ledger SHA-256 `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`.
