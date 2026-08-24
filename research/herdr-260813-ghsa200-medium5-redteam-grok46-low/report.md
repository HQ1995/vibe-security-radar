# Red-team: five uncounted fp211 CONFIRM/MEDIUM identities

**Status: `REDTEAM_COMPLETE`.** Hostile hypothesis: none of these five is countable until independently proved. Independent first-parent, AI-marker, topology, patch-delta, reversal, artifact, and uniqueness replay from `/tmp/ghsa200-worker-clones/upgrade-b/clones`. **No KEEP.** Publication remains **HOLD**. Worker KEEP would still only be a proposal; this packet produces none.

Leader contract frozen at SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Count requires seven exact PASS. Incomplete remediation uses the patch-delta rule: residual must be an omitted case in the AI-added boundary, not an untouched sibling path.

| Ordinal | GHSA | Product | fp211 | Red-team |
|--------:|------|---------|-------|----------|
| 114 | GHSA-P52P-4VMG-4VQ3 | Hermes | CONFIRM/MEDIUM all PASS | **NARROW** |
| 128 | GHSA-4MR5-G6F9-CFRH | PraisonAI | CONFIRM/MEDIUM all PASS | **NARROW** |
| 130 | GHSA-QF5V-M7P4-95RP | Fission | CONFIRM/MEDIUM all PASS | **NARROW** |
| 139 | GHSA-94P4-4CQ8-9G67 | GitPython | CONFIRM/MEDIUM all PASS | **NARROW** |
| 143 | GHSA-P538-C434-8V24 | GitPython | CONFIRM/MEDIUM all PASS | **NARROW** |

None of the five identifiers is in frozen `strict_73` (73 ids). Uniqueness against that set is PASS and does not promote a row.

## Ordinal 114 — NARROW (identity)

Global GHSA-p52p-4vmg-4vq3 is `type=unreviewed`, `vulnerabilities=[]`, `repository_advisory_url` null, `source_code_location` empty. Repository advisory API is 404. CVE-2026-49973 is a CNA/NVD alias on the unreviewed object. The contract identity gate needs a first-party GHSA object that names repository, mechanism, and public identity. An unreviewed empty-range GHSA plus a matching hunk is routing.

Member `b8b62722` (Claude Opus 4.6) first-parent-introduces `_set_password` in `api/config.py` (blob `0c774162`). Released `v0.51.357` config blob is `a12c3ef18`, equal to carrier `1126e541` and fix `f2ef2851`, not the member. Carrier is a two-parent merge of `v0.51.357` and `f2ef2851`; the first parent already has `_set_password`. The released residual is ungated first-password on `api/routes.py`. `f2ef2851` patches that route. The AI member hunk is not the released mechanism.

Failed: `identity_gate`, `topology_gate`, `but_for_gate`, `release_gate`.

## Ordinal 128 — NARROW (patch-delta / exact artifact)

Reviewed global and repo GHSA-4mr5-g6f9-cfrh / CVE-2026-47392. Package `praisonaiagents <= 1.6.39` patched `1.6.40`. Identity PASS.

`3cd664bf` (claude[bot]) first-parent-introduces `safe_builtins`. Parent used full `__builtins__`. First-party GHSA Gap 1 is `__self__` missing from AST `_blocked_attrs`. That frozenset is added by later human `cb820212e`, not by the AI commit. `179cab02` (Cursor trailer, human author) adds `__self__` to that later list.

Exact mapping: PyPI `praisonaiagents-1.6.39` wheel `python_tools.py` git hash-object `c4ba5d9763` equals `v4.6.39` and is **not** candidate blob `fcaf2927`. Wheel `1.6.40` equals `179cab02` / `v4.6.40` `83c5d833`. The vulnerable released artifact contains the later AST residual, not the AI candidate blob.

Failed: `but_for_gate`, `remediation_patch_delta_gate`, `release_gate` (exact candidate-to-wheel). Distinct from countable `GHSA-5C6W-WWFQ-7QQM` on the same origin SHA.

## Ordinal 130 — NARROW (topology / exact artifact)

Reviewed global and repo GHSA-qf5v-m7p4-95rp / CVE-2026-50570. Go package `github.com/fission/fission <= 1.24.0` patched `1.25.0`. Identity PASS.

Member `2db76f65` is not a `v1.24.0` ancestor. Carrier `e484df84` has its own Claude trailer and first-parent-introduces `podspec_safety.go`. Blobs are three-way unequal (member `af473d26`, carrier `330fccee`, tag `1d7219e7`). GitHub Release `v1.24.0` is `prerelease=true`. `v1.25.0` is not a prerelease and equals fix blob `43e361d3` / `2569b42b`.

The GHSA names SYS_TIME omitted from a six-capability denylist. That is same-boundary language, but the claimed AI SHA does not map onto the released tag blob, and the vulnerable GitHub Release is a prerelease. Authorship may not be transferred from member to a rewritten tag blob. Patch-delta is not closed without that mapping.

Failed: `topology_gate`, `but_for_gate`, `release_gate`, `remediation_patch_delta_gate`.

## Ordinal 139 — NARROW (sibling path)

Reviewed GHSA-94p4-4cq8-9g67. GPT 5.6 `8ac5a305` sets clone `expand_vars=False`. Parent `Remote.create` already called `Git.polish_url(url)` with default expansion. Candidate `Submodule.add` still `Git.polish_url(url)`. GHSA text: "guarded only that one caller" / "sibling caller the fix missed". `86341745` sets `expand_vars=False` on Remote/Submodule; clone already had False.

Wheels: `GitPython 3.1.54` `git/remote.py` equals candidate; `3.1.55` equals fix. Artifact mapping PASS. Sibling-path rule fails patch-delta. GHSA array `<= 3.1.53` understates git: `3.1.54` still lacks the sibling fix.

Failed: `but_for_gate`, `remediation_patch_delta_gate`.

## Ordinal 143 — NARROW (sibling API)

Reviewed GHSA-p538-c434-8v24. GPT 5.6 `701ce32f` guards `Commit.iter_items` with new `unsafe_git_rev_options` including `--output`. Parent `Commit.count` already forwarded `**kwargs` into `rev_list`. Count body is unchanged at the candidate. GHSA text: "the guard exists only in the sibling iter_items" / "distinct, uncovered sink". Human Sebastian `38553b6f` (GPT co-author) wires `count`; it does not amend the `iter_items` guard.

Wheels: `3.1.55` `git/objects/commit.py` equals candidate; `3.1.56` equals fix. Mapping PASS. Shared origin SHA with `GHSA-R9MR-M37C-5FR3` (in strict_73) and `GHSA-539M-9XH6-Q6RR` is a different sink, not an alias.

Failed: `but_for_gate`, `remediation_patch_delta_gate`.

## Claim boundary

This packet does not rebuild the 48-case strict-released lower bound and does not support a more-than-200 claim. No worker or red-team proposal changes the count.
