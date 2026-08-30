# Moved-repo recall — 2026-08-26

Recall pass on the ~28.6k leftover funnel (`in_window_zero_pct_leftover`)
and the in-window clusters that never got a product git identity. Ledger
not written. Universe JSONL not rebuilt.

Companion: `artifacts/moved-repo-recall-20260826.json`.
Round8 audit checkpoint lives in
`artifacts/round8-independent-double-confirm-20260826.md`.

## What “couldn't find a repo” actually was

| Bucket | n | Meaning |
|---|---|---|
| In-window, no product git at all | 56,167 | 50,248 never had a forge URL; 4,390 dropped as PoC; 1,034 `no_source`; 495 advisory DB |
| 0% leftover clone `Repository not found` | 101 GitHub identities | Deleted dumps, truncated GHSA URLs, org-page false slugs |
| In-window reviewed, no repo | 163 | Best place to fish: GHSA usually has *some* URL |

GitHub's API **does not keep a 301** for these 404s. Zero slugs came back as
`full_name` ≠ old slug. Recovery is: sibling URL already in the GHSA,
truncated slug next to the real one, org-page parsed as `owner/repo`, or a
same-name repo under a new owner.

## High-confidence attaches (do these first)

Parser already sees the good URL; clustering picked a worse sibling
(first GitHub slug wins). `SKIP_GITHUB_OWNERS` now includes `orgs` /
`users`. Do not treat these as BIC/AI work until the identity is attached
and scanned.

| Old identity | Attach | Clusters | Why |
|---|---|---|---|
| `orgs/spree` | `spree/spree` | 1 | GHSA has `github.com/spree/spree`; `github.com/orgs/spree` is an org page |
| `orgs/surrealdb` | `surrealdb/surrealdb` | 2 | Same pattern; GHSA already has the product repo + commit |
| `pytest-dev/pytes` | `pytest-dev/pytest` | 1 | GHSA contains both `.../pytes` (404) and commit/PR URLs on `pytest` |
| `openfga/helm-ch` | `openfga/helm-charts` (and `openfga/openfga`) | 1 | Same truncation next to real `helm-charts` + `openfga` commit |
| `astokr/papermark` | `papermark/papermark` | 1 | Old slug 404; same-name hit 8974★. Not a GitHub transfer redirect |

`users/god-mellon` (1 cluster) is a user page; `god-mellon/god-mellon` is also 404. Leave unknown.

## Deleted, not moved (do not invent a home)

| Identity | Clusters | Note |
|---|---|---|
| `lunary-ai/lunary` | 6 | API 404; same-name hits are unrelated low-star repos |
| `tillywork/tillywork` | 1 | 404, no plausible successor |

Most of the other 101 404s are deleted PoC dumps (`jjjjj-zr/*`,
`luoye197-prog/*`, `cve-*` names). Leave them out.

## False PoC drops that hid real products

`^poc[_-]?` matched any name starting with `poc`, including **pocket**.
`projectdiscovery` was a blanket PoC-aggregator owner, which also dropped
**nuclei** (the product). Both are fixed in `scripts/oss_git_repos.py`;
tests cover `pocket-id`, `pocketbase`, `pocketmine-mp`, `nuclei` vs
`nuclei-templates`.

Reviewed no-repo that now parse to a **product** git identity (claude-code
`no_source` facades excluded): **52** GHSA clusters, including
`pocket-id/pocket-id`, `pocketbase/pocketbase`, `pmmp/pocketmine-mp`,
`projectdiscovery/nuclei`, `daytonaio/daytona`, `pyca/cryptography`,
`twisted/twisted`, `minio/minio-java`, `gophish/gophish`,
`apache/lucene-solr`, `pydantic/mcp-run-python`, `graphql-hive/envelop`,
`dotnet/wpf`, `dotnet/runtime`. Full list is in the JSON under
`reviewed_no_repo_now_has_git_urls` (filter with `non_product_reason` +
skip `anthropics/claude-code`).

Leave `anthropics/claude-code` as `no_source` (public tree is not the CLI).

## Parser / clustering bugs to use on the next universe rebuild

1. `github_slug` / `SKIP_GITHUB_OWNERS` must drop `orgs`, `apps`, `users`,
   `sponsors`, `security` (now aligned with `oss_git_repos`).
2. `primary_repo` must not prefer a 404 truncated slug over a commit-backed
   sibling (`pytes` sorts before `pytest`). Prefer `identities_from_urls`
   commit strength, then a live GitHub slug.
3. PoC name regex: `^pocs?([_-]|$)`, not `^poc[_-]?`.
4. Do not mark the whole `projectdiscovery` owner as PoC.

## Not done

- Ledger / `upstream-deduped-20260826.jsonl` not rewritten.
- 0% leftover not re-scanned for the five high-confidence new identities.
- Unreviewed 50k with empty skip_reason not crawled (no forge URL in NVD/GHSA).
