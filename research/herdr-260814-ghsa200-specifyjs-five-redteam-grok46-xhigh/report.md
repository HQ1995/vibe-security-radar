# SpecifyJS five hostile red-team

**KEEP proposal: 5. NARROW/REJECT/UNKNOWN/BLOCKED: 0.**

Worker PASS is proposal only. Causal admission is false. Publication and more-than-200 remain HOLD. Canonical73 still holds 73 strict released first-party GHSA identities. None of the five assigned IDs are in that set. This packet does not rebuild the lower bound.

Conservation: assigned=5, reviewed=5, unreviewed=0. Source worker `herdr-260814-ghsa200-directroot-batch4-grok46-high` proposed these five as `AI_INCOMPLETE_REMEDIATION`. Its verdicts and prose were not trusted.

Hostile hypothesis: ranking bound all five to SAST commit `caa8fbfa` because they share closer `25d1fb49`; the candidates were not explicit security attempts on the named boundaries; the residual never shipped in a separate release before that closer; the closer is only a pentest merge; the five GHSA IDs are aliases or duplicate projections. KEEP requires each row to close all seven contract gates plus incomplete-remediation patch-delta, with its own candidate hunk and no Cartesian candidate-fix relation.

Shared topology (proved once, reused): both `30f9b76f` and `caa8fbfa` are single-parent Claude Opus 4.6 commits. `30f9b76f` is an ancestor of `caa8fbfa`. Both are ancestors of npm `0.2.134`/`0.2.135` and of closer `25d1fb49`. The closer is not an ancestor of those vulnerable versions. Partial clone has zero git tags; annotated tags `v0.2.134`/`v0.2.135`/`v0.2.136` peel to `4d98a9b8` / `a84103e7` / `25d1fb49`. npm `@asymmetric-effort/specifyjs` `0.2.135` `gitHead` equals `a84103e7` (published 2026-05-28T22:22:23Z). npm `0.2.136` `gitHead` equals `25d1fb49` (published 2026-05-29T03:10:01Z). npm `0.2.134` is an earlier residual with the same three source blobs as `0.2.135`. GitHub Release objects are 404; npm is the GHSA ecosystem. Repo advisory REST GET is 404; identity uses GitHub-reviewed global GHSA objects (`type=reviewed`, `withdrawn_at=null`, `source_code_location=https://github.com/asymmetric-effort/specifyjs`). Package rename (`liquidjs-framework` / `specifyjs-framework` at the candidate commits) does not transfer authorship: the hunks persist into the named npm package.

`25d1fb49` is itself Claude-marked. commit-first-af REJECT attached that closer marker to all five as origin. That is the wrong SHA. The closer is the reversal, not the incomplete attempt. It also edits PT-008 (localhost / `GHSA-XW57-23P8-9WC5`, already rejected in batch3). Extra hunks in the bundled pentest commit do not create a Cartesian relation: each KEEP row binds one candidate hunk to one PT reversal.

## GHSA-8882-FRVV-92W4 — KEEP (parse-fail-open)

Reviewed npm `@asymmetric-effort/specifyjs` `< 0.2.136`, alias CVE-2026-50288, CWE-918. Claude `30f9b76f` creates `assertSecureUrl` with `catch { return }` on `new URL()` failure. Parent `a2ee52ac` has no `secure-fetch.ts`. GHSA names that residual. Closer PT-001 throws. V135 blame of the `return` is `30f9b76f`. Later Claude test `ef00e291` only rewrites the catch comment to a v8 ignore. Ranked `caa8fbfa` only adds a protocol-relative throw. npm 0.2.135 tarball still contains `v8 ignore next 2`; 0.2.136 runtime contains `unable to validate URL`.

## GHSA-J5QP-P44G-2M49 — KEEP (redirect follow)

Same package range. Claude `30f9b76f` introduces `secureFetch` as `fetch(input, init)`. GHSA names the residual bypass: `assertSecureUrl` validated only the initial URL while `fetch` follows redirects. That omitted case sits inside the wrapper they added, not in a sibling function. Closer PT-004 sets `redirect: 'error'`. V135 blame of `fetch(input, init)` is `30f9b76f`. npm 0.2.136 tarball contains `redirect: 'error'`; 0.2.135 does not.

## GHSA-2944-57XV-2682 — KEEP (unbounded data: allowlist)

Same package range. Claude `30f9b76f` explicitly allowlists `data:` with no size cap. GHSA names that residual (memory exhaustion). CWE-918 on the GHSA is a copied pentest stamp; the named mechanism is the unbounded allowlist. Closer PT-005 caps at 1MB on the same `startsWith('data:')` branch. V135 blame of those lines is `30f9b76f`. npm 0.2.135 tarball contains `Data URLs are allowed`; 0.2.136 contains `data: URI exceeds 1MB`.

## GHSA-5C7W-4WM3-85VW — KEEP (gql warn-not-throw)

Same package range, CWE-943. Claude `caa8fbfa` M-8 warns on `{}():` interpolation and still concatenates. Parent `56749d12` concatenated with no check; original concat need not be AI-origin. GHSA names the warn-and-still-concat residual. Closer PT-002 throws. `graphql.ts` blob `83221c09` is identical from `caa8fbfa` through npm 0.2.134/0.2.135. `30f9b76f` does not touch this file. npm 0.2.135 tarball contains the warn string; 0.2.136 does not.

## GHSA-93Q6-WWJH-JC6H — KEEP (CSS sanitizer bypass)

Same package range, alias CVE-2026-50290, CWE-79. Claude `caa8fbfa` L-6 strips `expression(` and `url(javascript:` with two regex replaces. Parent had no those replaces. GHSA names unicode-escape and CSS-comment bypass of that sanitizer. Closer PT-003 normalizes escapes and comments before matching. V135 blame of the strip lines is `caa8fbfa` despite later `1645f2e` recursion edits elsewhere in the file. `30f9b76f` does not touch `render-to-string.ts`. npm 0.2.136 tarball contains `normalizedCss`; 0.2.135 does not.

## Uniqueness and Cartesian refusal

Five distinct first-party GHSA identities, two CVEs that are not aliases of each other, three mechanisms in `secure-fetch.ts` plus gql plus CSS. Shared candidate SHAs and shared closer SHA do not merge them. Ranking's file-overlap of `caa8fbfa` against the three-file closer is routing, not proof. `GHSA-XW57-23P8-9WC5` (PT-008 localhost expansion) is a different identity and is not reviewed here.

## Claim boundary

No worker or red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical73 and does not support a more-than-200 claim.
