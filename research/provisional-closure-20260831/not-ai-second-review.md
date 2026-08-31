# Independent negative-control second review

Date: 2026-08-31  
Scope: the six cases routed to `NOT_AI_REVIEW` by shards 02–05. This is an
independent replay of the immediate parent, scoped but-for condition, release
containment, and BIC-local AI marker. I did not treat a later AI remediation as
the origin and did not rely on the shard conclusion as evidence.

## Result

| Case | Second-review result | AI-site action | Narrowest defensible AI scope, if any |
|---|---|---|---|
| `CVE-2025-62615` / `GHSA-R55V-Q5PC-J57F` | **AGREE** | Remove the root-cause case from the AI catalog | At most: Claude rewrote the already unsafe RSS fetch from `feedparser` to explicit `urlopen`; non-counting implementation-bearer history only. |
| `GHSA-J383-Q79V-268X` / `CVE-2025-13120` | **AGREE** | Remove from the AI catalog | At most: Rovo wrote a later, unreleased pointer-only regression repaired before 4.0; it is not the published 3.x vulnerability origin. |
| `GHSA-P6Q4-FGR8-VX4P` | **AGREE** | Remove this root-vulnerability row; retain the separate `GHSA-6Q7J-XR26-3H2C` AI incomplete-remediation row | Copilot's `f55280a...` attempted to instrument the old array-recursion path but used a non-enforcing guard. |
| `CVE-2026-45582` / `GHSA-F3RG-XQJJ-CJ9W` | **DISAGREE** | Keep after replacing the false candidate and rebuilding the chain | Claude-authored security remediation `597bd290...` deliberately preserved URL paths/context and thereby created the advisory's partial-fragment leakage; classify as `AI_INCOMPLETE_REMEDIATION`, not direct product-feature root. |
| `GHSA-8X5V-CPV7-8JJP` | **AGREE** | Remove this root-cause case from the AI catalog | At most: Claude later copied the human `is_global` predicate into connect-time DNS-rebinding guards; remediation/carrier context, not the predicate's first write. |
| `GHSA-RFR2-MQ9M-X2QX` | **AGREE** | Remove the root-cause case from the AI catalog | At most: Claude later added a remote-reference opt-in/warning gate that defaulted to allow and did not repair the 2021 unvalidated HTTP fetch. |

Accounting: **5 AGREE, 1 DISAGREE**. Five current AI-root cases should leave
the AI catalog. One case (`CVE-2026-45582`) should remain, but only after its
candidate, causal class, and release start are corrected.

## 1. CVE-2025-62615 — AGREE

- **Parent / first write:** human commit
  `a00df25092ff60d94bcd1d41f18f778a2f27c573`, parent
  `ea698ab0fee5b72b5ee8bf35c896754c4a31063f`, creates the RSS reader and
  `parse_feed(url) -> feedparser.parse(url)`. The file is absent from its
  parent. The commit has only a human coauthor and no AI marker.
- **Claimed AI change:** Claude-marked PR member
  `583a9a9eb39673ed633b102e13894199992a4060`, later represented on main by
  `57a06f70883ce6be18738c6ae8bb41085c71e266`, replaces that call with
  request-controlled `urllib.request.urlopen` plus scheme/size controls.
- **But-for:** **FAIL for AI root cause.** Reverting the AI delta restores the
  pre-existing unfiltered network fetch. It changes the implementation named
  in the advisory, but does not remove the SSRF-capable source-to-sink path.
- **Release:** `v0.6.32`/`v0.6.33` contain the Claude carrier without fix
  `a6a2f71458928f112c5e74b3bc1a95f9c76f20d5`; `v0.6.34` contains the fix.
  This proves the AI rewrite shipped, but release containment cannot repair a
  failed but-for gate.
- **AI marker:** direct and valid on `583a9a9...` and the squash carrier; none
  on the human first writer.

**Disposition:** remove from AI-root publication. If retained as historical
context, the text must say only that Claude rewrote an already unsafe RSS
fetch and that the eventual fix replaced the Claude-era implementation. It
must not say “AI introduced the SSRF.”

Primary replay: [first-party advisory](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-r55v-q5pc-j57f)
and `.ai-slop/state/repos/significant-gravitas_autogpt`.

## 2. GHSA-J383-Q79V-268X — AGREE

- **Parent / first write:** the affected 3.4.0 tree already has human-written
  `sort_cmp` modification checks, including the pointer-plus-index-length
  predicate. Commit `752ebe6b7f0ad24f3841602f6b21ec5b808c66c5`
  is human-authored and has no AI marker.
- **Claimed AI change:** single-parent
  `cf8faed585e14ab57cc390173d1b571aee438390` carries an Atlassian Rovo Dev
  coauthor trailer and rewrites the comparator to a pointer-only post-callback
  check. `eb398971bfb43c38db3e04528b68ac9a7ce509bc` adds full pointer and
  original-length comparison.
- **But-for:** **FAIL for the published identity.** Reverting `cf8faed...`
  restores the human 3.x-style check, while the advisory explicitly declares
  versions through 3.4.0 affected. The later AI delta therefore cannot be the
  origin of that released vulnerability.
- **Release:** **FAIL for the AI-origin claim.** `cf8faed...` is absent from
  3.4.0. Every surviving 4.0/4.0-rc tag containing it also contains the fix.
- **AI marker:** direct on the post-3.4.0 development commit, absent from the
  relevant human 3.x lineage.

**Disposition:** remove from the AI catalog. A very narrow non-counting note
may record that Rovo wrote a later pointer-only development regression, fixed
before the 4.0 release. Do not conflate it with CVE-2025-13120's stated 3.x
range.

Primary replay: [published advisory](https://github.com/advisories/GHSA-j383-q79v-268x),
[upstream issue 6649](https://github.com/mruby/mruby/issues/6649), and
`.ai-slop/state/repos/mruby_mruby`.

## 3. GHSA-P6Q4-FGR8-VX4P — AGREE

- **Parent / first write:** root commit
  `46054810b50b03a6d19cd51886321cbbefa5d589` creates
  `ParseArrayInitializer` and its recursive call into expression parsing.
  Author/committer Alexandre Mutel, 2016; no parent and no AI marker.
- **Claimed AI role:** Copilot-coauthored
  `f55280a09575e577fcf7f5629007e0814594e3ac` wraps the old array path in
  `EnterExpression`/`LeaveExpression`. It is a remediation attempt, not the
  recursive parser's BIC. Its guard only logs and continues, as the later
  first-party `GHSA-6Q7J-XR26-3H2C` explains.
- **But-for:** **FAIL for AI root cause.** Rolling back `f55280a...` exposes the
  same older unbounded array recursion; Copilot neither creates the parser nor
  closes the DoS. The correct AI-causal claim is the separate incomplete
  remediation edge `f55280a... -> 8fdbd687...`.
- **Release:** the human root spans all historical releases. `7.0.0` through
  `7.2.0` contain the Copilot attempt but not the enforcing fix;
  `7.2.1` contains `8fdbd687bbe8f00085c4c4c5b2b3b8d529933949`.
- **AI marker:** direct on the partial fix only; absent from the human root.

**Disposition:** remove the standalone P6Q4 root case from the AI catalog.
Retain confirmed `GHSA-6Q7J-XR26-3H2C` with the narrow label “AI incomplete
remediation of a pre-existing parser-recursion DoS.” Do not count both as AI
roots.

Primary replay: [GHSA-P6Q4](https://github.com/scriban/scriban/security/advisories/GHSA-p6q4-fgr8-vx4p),
[follow-up GHSA-6Q7J](https://github.com/scriban/scriban/security/advisories/GHSA-6q7j-xr26-3h2c),
and `.ai-slop/state/repos/scriban_scriban`.

## 4. CVE-2026-45582 — DISAGREE

The shard correctly disproved current candidate `47510ef6...`, but its
“remove from AI” conclusion stops one commit too early.

- **Parent / original feature:** human
  `5960d2826eb23e87ed142b3a88cf5d8ac0eddc42`, parent
  `78abda601ab0c34fb60cb760ed18a2fa5ae3c232`, creates telemetry and the URL
  sanitizer. It initially treats keys containing `url`/`endpoint` as
  sensitive; there is no BIC-local AI marker.
- **True AI causal delta:** Claude-Code-generated/coauthored security commit
  `597bd290b69459c3b84bbd7cffc5e51c4aa0f28b`, parent
  `99c5907b71a6c3228d345a2f0879cd893f30cd7e`, changes sanitization to treat
  URL-shaped fields specially. For them it preserves context, replacing only
  the domain while retaining path/query fragments; for authenticated URLs it
  explicitly preserves the path. This is the exact behavior the advisory
  says leaked customer/tenant identifiers, short query secrets, and signed
  parameters.
- **False current candidate:** Claude-marked `47510ef6...` does not edit
  `src/telemetry/workflow-sanitizer.ts`; its only relevant change is generated
  declaration ordering. It must be removed from this case.
- **But-for:** **PASS under incomplete-remediation patch-delta semantics.** The
  parent of `597bd290...` redacts URL-field values as `[REDACTED]`; the AI
  security delta intentionally preserves the fragments; fix
  `6cf6fef653fcd6d598f2f356aac4754931c7329f` directly reverses this by fully
  redacting URL-like fields as `[REDACTED_URL]`. Rolling back the AI delta
  removes this specific fragment-retention behavior.
- **Release:** tag `v2.22.17` first contains `597bd290...`; every release
  through `v2.51.2` contains it without the fix; tag `v2.51.3` is the fix
  commit itself. This is a stronger, narrower boundary than the advisory's
  broad `introduced: 0` range.
- **AI marker:** direct, repeated Claude Code generation and Claude coauthor
  trailers on the exact causal commit.

**Corrected structured edge:** 

```json
{
  "candidate_set": ["597bd290b69459c3b84bbd7cffc5e51c4aa0f28b"],
  "carrier_set": [],
  "minimum_fix_set": ["6cf6fef653fcd6d598f2f356aac4754931c7329f"],
  "contribution_class": "AI_INCOMPLETE_REMEDIATION",
  "vulnerable_release": {"kind": "git_tag", "tag": "v2.22.17"},
  "fixed_release": {"kind": "git_tag", "tag": "v2.51.3"},
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  }
}
```

**Disposition:** keep on the AI site after replacing the candidate and class.
The scope must be exactly: “Claude-authored security refactoring preserved
paths/query fragments in URL-shaped telemetry fields; the later fix fully
redacted those fields.” Do not claim AI created anonymous telemetry generally,
and do not use `47510ef6...`.

Primary replay: [first-party GHSA-F3RG](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-f3rg-xqjj-cj9w),
the reviewed advisory-database object, and
`.ai-slop/state/repos/czlonkowski_n8n-mcp`.

## 5. GHSA-8X5V-CPV7-8JJP — AGREE

- **Parent / first write:** human single-parent
  `0753409e7b18ffe4fc95a0a821f605d25b58ccad`, parent
  `b78dabb442dacd5430f0e8777aa65accf3d78c08`, first installs the relevant
  literal-address predicate `ipaddress.ip_address(ip).is_global`. Its message
  even identifies this as an allowlist approach. No AI marker is present.
- **Claimed AI role:** the current AI PR member `051cbc65...` is represented
  on main by Claude-coauthored `854440f703c625f8cfc1b52c7e81aac67b6143c5`.
  It adds connect-time DNS-rebinding defenses and reuses the existing
  `is_global` decision in `_ssrf_safe_new_conn` and `_SSRFSafeResolver`.
- **But-for:** **FAIL for AI root cause.** The advisory's NAT64 gap exists in
  the human literal predicate before the AI hardening. Reverting the AI delta
  removes two later checkpoints but leaves `validate_url()` with the same
  NAT64-vulnerable test. This is not an AI first write.
- **Release:** v0.9.0 through v0.10.2 contain the human predicate and exclude
  fix `1717b493d83c86afa82aa8bc50139250852dd2f3`; v0.11.0 contains the fix.
- **AI marker:** direct on the later connection-layer hardening, absent on the
  predicate origin.

**Disposition:** remove the root-cause row from the AI catalog. If non-counting
context is valuable, state only that Claude later propagated the human
predicate into connect-time guards; do not present that propagation as the
NAT64 vulnerability's introduction. This is also not a clean incomplete-
remediation case: the AI commit addressed DNS rebinding, a different invariant.

Primary replay: [first-party advisory](https://github.com/open-webui/open-webui/security/advisories/GHSA-8x5v-cpv7-8jjp)
and `.ai-slop/state/repos/open-webui_open-webui`.

## 6. GHSA-RFR2-MQ9M-X2QX — AGREE

- **Parent / first write:** human single-parent
  `5609aa5bd79a18d6f77066e6d6321d7f37349fea`, parent
  `69e9c5c1c593c7fb1cb941b21e9200aa8c0acf69`, creates the HTTP URL input,
  shared `get_body` fetcher, and direct response-to-schema path in 2021. No AI
  marker appears on that BIC.
- **Claimed AI role:** Claude-coauthored
  `f6d4cbd3440a84e801566fa758ab2bf483322082` later adds
  `--allow-remote-refs`, error/status handling, and a compatibility default
  that warns but still allows remote references. It does not add IP/host
  validation and is not the `--url` fetch origin.
- **But-for:** **FAIL for AI root cause.** Reverting `f6d4cbd...` restores the
  pre-existing unrestricted 2021 fetch; the advisory's direct `--url` SSRF
  remains. Direct fix `5fdba4a09f2d7a9996a504975b7ef7d63e3715bb`
  finally adds network-destination/redirect validation.
- **Release:** human origin ships from 0.9.1; releases through 0.60.2 exclude
  the fix; 0.61.0 contains it. The AI gate is later release context, not the
  affected range's beginning.
- **AI marker:** direct on the later partial policy/error-handling commit,
  absent from the first writer.

**Disposition:** remove from the AI-root catalog. The narrowest permissible
AI note is that Claude later added a non-default-blocking remote-reference
policy/warning without repairing the older shared fetcher. Do not call this
the direct `--url` SSRF origin or count it as a separate AI vulnerability.

Primary replay: [first-party advisory](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-rfr2-mq9m-x2qx)
and `.ai-slop/state/repos/koxudaxi_datamodel-code-generator`.

## Integration recommendation

Route the five `AGREE` cases through explicit ledger transactions before
removing their pages; do not merely hide banners while retaining AI-root
records. For `CVE-2026-45582`, reject the shard's removal recommendation and
backfill the corrected seven-gate `597bd290... -> 6cf6fef...` incomplete-
remediation chain. No ledger, site, generated data, commit, or push was changed
by this review.
