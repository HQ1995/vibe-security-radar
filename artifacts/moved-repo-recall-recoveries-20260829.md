# Moved-repo recall recoveries — 2026-08-29

Recall expansion of the 101 clone-404 GitHub identities and the 163 in-window reviewed clusters with no product git. **Ledger not written.** Universe JSONL not rebuilt.

Prior pass: `artifacts/moved-repo-recall-20260826.md` (JSON archived under `artifacts/archive/round-intermediates/moved-repo-recall-20260826.json`).

## Counts

| Bucket | n | This pass |
| --- | --- | --- |
| Clone `Repository not found` GitHub identities | 101 | Same set as 2026-08-26 |
| High-confidence clone-404 attaches | 5 | Live GitHub 200 + GHSA sibling or truncation |
| Medium-confidence transfer | 1 | `salihciftci/liman` → `limanmys/core` |
| Deleted, not moved | 2 | `lunary-ai/lunary`, `tillywork/tillywork` |
| In-window reviewed, no repo | 163 |  |
| Those with any GHSA git URL | 86 |  |
| Product attachable (live 200, not dump/facade) | 46 | Ready to attach on next universe rebuild |
| Issue-tracker only | 4 | `umbraco/umbraco.forms.issues` — do not BIC/AI scan |
| Reviewed identities now 404 | 2 | `bruce0203/fast_map`, `douinc/mkdocs-mcp-plugin` |
| Claude Code facade | 28 | Leave `no_source` |

GitHub `/repos` **does not keep a 301** for these 404s. Zero of the 101 old slugs came back as `full_name` ≠ old slug. Recovery is: sibling URL already in the GHSA, truncated slug next to the real one, org-page parsed as `owner/repo`, or a same-name repo under a new owner.

Live transfers seen while probing (not from the 404 slug itself):

- `limanmys/liman` → `limanmys/core` (62★)
- `mfts/papermark` → `papermark/papermark` (8981★) — confirms the papermark product identity

## High-confidence clone-404 attaches (do these first)

Parser already sees the good URL; clustering picked a worse sibling (first GitHub slug wins). `SKIP_GITHUB_OWNERS` includes `orgs` / `users`. Do not treat these as BIC/AI work until the identity is attached and scanned.

| Old identity | Attach | Clusters | IDs | Why |
| --- | --- | --- | --- | --- |
| `orgs/spree` | `spree/spree` | 1 | `CVE-2011-10019`, `GHSA-97vm-c39p-jr86` | org page false slug |
| `orgs/surrealdb` | `surrealdb/surrealdb` | 2 | `GHSA-6wqw-vhfr-9999`, `GHSA-f82j-v89j-mf86` | org page false slug |
| `pytest-dev/pytes` | `pytest-dev/pytest` | 1 | `CVE-2025-71176`, `GHSA-6w46-j5rx-g56g` | truncated sibling in ghsa |
| `openfga/helm-ch` | `openfga/openfga` (also `openfga/helm-charts`) | 1 | `CVE-2026-55689`, `GHSA-hcxc-wf8j-23hv` | truncated sibling in ghsa |
| `astokr/papermark` | `papermark/papermark` | 1 | `CVE-2026-57957`, `GHSA-4cq7-5c7c-cc5r` | same name new owner and ghsa sibling |

- `orgs/spree` → `spree/spree`: GHSA-97vm-c39p-jr86 PACKAGE url is github.com/spree/spree; github.com/orgs/spree is an org page. Live 200, 15652 stars.
- `orgs/surrealdb` → `surrealdb/surrealdb`: Both GHSAs have PACKAGE + commit URLs on surrealdb/surrealdb; github.com/orgs/surrealdb/discussions is an org page. Live 200, 32945 stars.
- `pytest-dev/pytes` → `pytest-dev/pytest`: GHSA-6w46-j5rx-g56g PACKAGE url is truncated github.com/pytest-dev/pytes (404); issue/PR/commit/release URLs are on pytest-dev/pytest. Live 200, 14458 stars.
- `openfga/helm-ch` → `openfga/openfga`: GHSA-hcxc-wf8j-23hv is an OpenFGA OIDC bug. Truncated github.com/openfga/helm-ch (404) sits next to openfga/helm-charts release tag and openfga/openfga commit 44596773. Attach the product tree (openfga), not the chart. Live 200, 5673 stars (openfga) / 47 stars (helm-charts).
- `astokr/papermark` → `papermark/papermark`: GHSA-4cq7-5c7c-cc5r cites github.com/papermark/papermark/issues/2178 and github.com/AstoKr/papermark/pull/1 (404). GitHub API: astokr/papermark 404; papermark/papermark 200 8981 stars. mfts/papermark 301/rename to papermark/papermark (confirms product identity; not a live 301 from astokr).

`users/god-mellon` stays unknown (user page; `god-mellon/god-mellon` 404).

## Medium-confidence transfer (do not book yet)

| Old identity | Candidate | IDs | Why not high |
| --- | --- | --- | --- |
| `salihciftci/liman` | `limanmys/core` | `CVE-2020-37007`, `GHSA-wx76-4vvv-7j37` | Different owner; no live 301 from the 404 slug; GHSA only has archive.org |

GHSA only has an archive.org snapshot of github.com/salihciftci/liman (404). Live GitHub: salihciftci/liman 404; limanmys/liman resolves to limanmys/core (moved=true, 62 stars, description matches Liman server-management product). Different owner; not a GitHub 301 from the old slug. Do not treat as BIC/AI work until a human confirms this is the same 0.7 tree.

## Deleted, not moved (do not invent a home)

| Identity | Clusters | Note |
| --- | --- | --- |
| `lunary-ai/lunary` | 6 in-window / 28 total | 404; same-name hits unrelated |
| `tillywork/tillywork` | 1 | 404; GHSA only has the dead slug |

Most of the other 101 404s are deleted PoC dumps (`jjjjj-zr/*`, `luoye197-prog/*`, `cve-*` names). Leave them out.

## Other 404s inspected, still unknown

| Identity | Note |
| --- | --- |
| `users/god-mellon` | User page, not a repo. god-mellon/god-mellon 404. god-mellon/test2 exists (0★, description test1) and is not the product. |
| `user-attachments/files` | GitHub attachment dump parsed as owner/repo. clone_url already returns None. Clustering still picks it as primary when it sorts first. Prefer commit-backed siblings (caddy, dolibarr, openbabel, vikunja, wasm3, …). Do not attach user-attachments/files. |
| `wpchill/modula-lite` | GHSA commit URLs on WPChill/modula-lite now 404. WordPress plugin; no live GitHub successor (modula-best-grid-gallery also 404). Leave unknown. |
| `openviglet/shio` | openviglet/shio 404. Sibling shio-* repos exist (shio-media, shio-cli, …) but are not the CMS tree. Leave unknown. |
| `owasp-blt/blt` | 404. No GHSA git URLs. OWASP-BLT/BLT and OWASP/BLT also 404. Leave unknown. |
| `seal773/openclaw-claude-bridge` | Bridge repo 404. Do NOT attach to openclaw/openclaw (different product). Same-name forks exist (shinglokto/openclaw-claude-bridge 153★) but are not a verified transfer. |
| `bruce0203/fast_map` | Reviewed no-repo GHSA identity now 404. No successor. |
| `douinc/mkdocs-mcp-plugin` | Reviewed no-repo GHSA identity now 404. No successor. |

Do **not** attach `seal773/openclaw-claude-bridge` to `openclaw/openclaw`.

## Reviewed no-repo → live product git

False PoC drops that hid real products (`^poc[_-]?` matching **pocket**, blanket `projectdiscovery` owner dropping **nuclei**) are already fixed in `scripts/oss_git_repos.py`. Tests cover `pocket-id`, `pocketbase`, `pocketmine-mp`, `nuclei` vs `nuclei-templates`.

**46** clusters now parse to a live product identity (claude-code facades, advisory DBs, and XSS/CVE dumps excluded). Unique scan identities: **24**.

| Attach | n | Example IDs | Notes |
| --- | --- | --- | --- |
| `pmmp/pocketmine-mp` | 6 | `GHSA-fqqv-56h5-f57g` | 3576★ archived |
| `dotnet/wpf` | 5 | `CVE-2026-62897`, `GHSA-fx4q-gjrx-2jw6` | 7719★ |
| `daytonaio/daytona` | 4 | `CVE-2026-54324`, `GHSA-qwxf-2m7m-2m3x` | 71864★ |
| `dotnet/runtime` | 4 | `CVE-2026-62901`, `GHSA-m93f-wj8c-rp8p` | 18234★ |
| `pocket-id/pocket-id` | 4 | `CVE-2026-28513`, `GHSA-qh6q-598w-w6m2` | 9045★ |
| `projectdiscovery/nuclei` | 2 | `CVE-2026-41646`, `GHSA-29rg-wmcw-hpf4` | 30908★ |
| `pyca/cryptography` | 2 | `CVE-2026-39892`, `GHSA-p423-j2cm-9vmq` | 7731★ |
| `pydantic/mcp-run-python` | 2 | `CVE-2026-25905`, `GHSA-pfv4-wmph-5gc6` | 194★ archived |
| `tendenci/tendenci` | 2 | `CVE-2025-70959`, `GHSA-g7hj-29xq-r64w` | 554★ |
| `apache/lucene-solr` | 1 | `CVE-2026-44825`, `GHSA-qhr7-h655-pw6r` | 4363★ |
| `cadmium-org/cadmium-cms` | 1 | `CVE-2025-51511`, `GHSA-qx44-p258-3c2v` | 10★ |
| `cmusphinx/pocketsphinx` | 1 | `CVE-2026-54559`, `GHSA-56r5-2p2f-7cxp` | 4335★ |
| `gophish/gophish` | 1 | `CVE-2026-39904`, `GHSA-42jc-v69j-g38f` | 14162★ |
| `graphql-hive/envelop` | 1 | `GHSA-h3hw-29fv-2x75` | 827★ |
| `intelliants/subrion` | 1 | `CVE-2025-70958`, `GHSA-9jjm-mc56-3qxv` | 284★ |
| `jenkinsci/ibm-cloud-devops-plugin` | 1 | `CVE-2025-53663`, `GHSA-pgrx-5f8q-r5mq` | 6★ |
| `m00nl1ght-dev/steam-workshop-deploy` | 1 | `GHSA-x6gv-2rvh-qmp6` | 2★ |
| `minio/minio-java` | 1 | `CVE-2025-59952`, `GHSA-h7rh-xfpj-hpcm` | 1305★ |
| `ozi-project/publish` | 1 | `CVE-2025-47271`, `GHSA-2487-9f55-2vg9` | 1★ |
| `pocketbase/pocketbase` | 1 | `CVE-2026-44166`, `GHSA-pq7p-mc74-g65w` | 60868★ |
| `puchunjie/doc-tools-mcp` | 1 | `CVE-2026-7738`, `GHSA-gcmm-c94j-j47x` | 11★ |
| `twisted/twisted` | 1 | `CVE-2026-42304`, `GHSA-grgv-6hw6-v9g4` | 5978★ |
| `universal-tool-calling-protocol/python-utcp` | 1 | `CVE-2026-12210`, `GHSA-ppx3-28rw-8fpf` | 646★ |
| `zcaceres/fetch-mcp` | 1 | `CVE-2025-65513`, `GHSA-8fxj-2g9q-8fjw` | 816★ |

Sibling dumps dropped in favor of the product tree: `emirhanyucelll/tendenci`, `emirhanyucell/subrion-cms-4.2.1`, `ashikmd7/gophish-0.12.1`, `gola-leya/cve_submit`, `brucejqs/public_exp`, `team-off-course/mcp-server-vuln-analysis`.

Prefer `dotnet/wpf` / `dotnet/runtime` over `dotnet/announcements`. Prefer `graphql-hive/envelop` (commit) over `graphql-hive/graphql-modules`.

### Issue tracker only — attach identity, do not scan as product tree

| class_id | IDs | Identity |
| --- | --- | --- |
| `alias-31ac397a94e9a98e5ab2ecb0` | `CVE-2025-47280`, `GHSA-2qrj-g9hq-chph` | `umbraco/umbraco.forms.issues` |
| `alias-2320ce8fa6aa78b37b3f1dc6` | `CVE-2026-24687`, `GHSA-hm5p-82g6-m3xh` | `umbraco/umbraco.forms.issues` |
| `alias-531855e9db6432fbcd642748` | `GHSA-7jxj-rpx7-ph2c` | `umbraco/umbraco.forms.issues` |
| `alias-f3aaa671d1c2ca0e0cd9653b` | `CVE-2025-68924`, `GHSA-vrgw-pc9c-qrrc` | `umbraco/umbraco.forms.issues` |

### Full product cluster list

| class_id | IDs | Attach | strength |
| --- | --- | --- | --- |
| `alias-836495cad4bf37ea8513152c` | `CVE-2025-59952`, `GHSA-h7rh-xfpj-hpcm` | `minio/minio-java` | commit |
| `alias-f64ba8a55a3904a10ecc4199` | `GHSA-fqqv-56h5-f57g` | `pmmp/pocketmine-mp` | commit |
| `alias-f815a479cd4f37a07629fd59` | `CVE-2025-51511`, `GHSA-qx44-p258-3c2v` | `cadmium-org/cadmium-cms` | repo |
| `alias-8df77c80e429227b08667961` | `CVE-2025-65513`, `GHSA-8fxj-2g9q-8fjw` | `zcaceres/fetch-mcp` | repo |
| `alias-ef1eb91b80022f7de7e0adce` | `CVE-2025-47271`, `GHSA-2487-9f55-2vg9` | `ozi-project/publish` | commit |
| `alias-10ac7be14b5bd84f5d13225a` | `CVE-2025-53663`, `GHSA-pgrx-5f8q-r5mq` | `jenkinsci/ibm-cloud-devops-plugin` | repo |
| `alias-30212af20e67fc8d70561c77` | `GHSA-x6gv-2rvh-qmp6` | `m00nl1ght-dev/steam-workshop-deploy` | commit |
| `alias-1afd4002b6f9268fa39dfa9d` | `CVE-2025-70959`, `GHSA-g7hj-29xq-r64w` | `tendenci/tendenci` | repo |
| `alias-f082ccb89901ddf7a3adaa4c` | `CVE-2025-70960`, `GHSA-6fvp-wmh6-jg95` | `tendenci/tendenci` | repo |
| `alias-4d85660f41efb851ba03e218` | `CVE-2026-25905`, `GHSA-pfv4-wmph-5gc6` | `pydantic/mcp-run-python` | repo |
| `alias-bc63baf7c514bf9106804ccd` | `CVE-2025-70958`, `GHSA-9jjm-mc56-3qxv` | `intelliants/subrion` | repo |
| `alias-a3b28b9a7e4f970c2d504f42` | `CVE-2026-25904`, `GHSA-6fgp-m6q4-j3q5` | `pydantic/mcp-run-python` | repo |
| `alias-d74fcced894b00ac719b37f4` | `CVE-2026-54324`, `GHSA-qwxf-2m7m-2m3x` | `daytonaio/daytona` | repo |
| `alias-3b37c0d43dd78befe8c92205` | `CVE-2026-54321`, `GHSA-ww63-pv5x-vfc8` | `daytonaio/daytona` | repo |
| `alias-f34b68f2b359ffddbe471648` | `CVE-2026-39904`, `GHSA-42jc-v69j-g38f` | `gophish/gophish` | repo |
| `alias-71d67af6955309cd8e1ea040` | `CVE-2026-44825`, `GHSA-qhr7-h655-pw6r` | `apache/lucene-solr` | repo |
| `alias-53f72e3406e1866d8379be6b` | `CVE-2026-54322`, `GHSA-qxvm-pcfm-qc39` | `daytonaio/daytona` | repo |
| `alias-8e3202fea386c05253079fdd` | `CVE-2026-54319`, `GHSA-fjv8-j4p5-cr9m` | `daytonaio/daytona` | repo |
| `alias-a65532db0c884d56d6ecf57a` | `GHSA-h6rj-3m53-887h` | `pmmp/pocketmine-mp` | commit |
| `alias-ba8acdf768993d4e8fec8afa` | `GHSA-788v-5pfp-93ff` | `pmmp/pocketmine-mp` | commit |
| `alias-c1a34e9c2691a393bc985c7d` | `GHSA-7hmv-4j2j-pp6f` | `pmmp/pocketmine-mp` | commit |
| `alias-ed9ac3aa2e17642c8a0a01e6` | `CVE-2026-41646`, `GHSA-29rg-wmcw-hpf4` | `projectdiscovery/nuclei` | commit |
| `alias-b364c7de1fa73215bd0e9f33` | `CVE-2026-39892`, `GHSA-p423-j2cm-9vmq` | `pyca/cryptography` | repo |
| `alias-e8465d9ffac08a7b7093ad98` | `CVE-2026-41645`, `GHSA-jm34-66cf-qpvr` | `projectdiscovery/nuclei` | commit |
| `alias-cce832e3facb754ad78dc966` | `GHSA-xp4f-g2cm-rhg7` | `pmmp/pocketmine-mp` | commit |
| `alias-b73177dfe1df2f5e08c23651` | `GHSA-f9jp-856v-8642` | `pmmp/pocketmine-mp` | commit |
| `alias-118a7f1e5e4b145e6cd80a3b` | `CVE-2026-28513`, `GHSA-qh6q-598w-w6m2` | `pocket-id/pocket-id` | repo |
| `alias-8a8cba728dabaa379dbd5fb1` | `CVE-2026-34073`, `GHSA-m959-cc7f-wv43` | `pyca/cryptography` | repo |
| `alias-a0576a84e813f76ec3e2088c` | `CVE-2026-28512`, `GHSA-9h33-g3ww-mqff` | `pocket-id/pocket-id` | commit |
| `alias-4e8887b7882078b94154788f` | `CVE-2026-44166`, `GHSA-pq7p-mc74-g65w` | `pocketbase/pocketbase` | repo |
| `alias-878962b7fecb419e1e89b7dc` | `CVE-2026-7738`, `GHSA-gcmm-c94j-j47x` | `puchunjie/doc-tools-mcp` | repo |
| `alias-784f07229e0aba4eb37afa6f` | `CVE-2026-42304`, `GHSA-grgv-6hw6-v9g4` | `twisted/twisted` | commit |
| `alias-eaf4857d9b5bfc69dfd5ecda` | `GHSA-h3hw-29fv-2x75` | `graphql-hive/envelop` | commit |
| `alias-5a22a1ad79abc992a84a2992` | `CVE-2026-43983`, `GHSA-w6p7-2fxx-4f44` | `pocket-id/pocket-id` | commit |
| `alias-b485684c2a01c80c3bc17aaf` | `GHSA-hp74-gm6m-2qm5` | `pocket-id/pocket-id` | commit |
| `alias-71de46f21609eb4d72a91e8d` | `CVE-2026-54559`, `GHSA-56r5-2p2f-7cxp` | `cmusphinx/pocketsphinx` | repo |
| `alias-81166f7185e9a2ecac2de146` | `CVE-2026-62897`, `GHSA-fx4q-gjrx-2jw6` | `dotnet/wpf` | repo |
| `alias-e973c65b44de90a614715562` | `CVE-2026-62871`, `GHSA-vg44-h755-9hw7` | `dotnet/wpf` | repo |
| `alias-11a6e994329419eb7e0f36f1` | `CVE-2026-12210`, `GHSA-ppx3-28rw-8fpf` | `universal-tool-calling-protocol/python-utcp` | commit |
| `alias-067896b8c7fdaf6f6d3732d3` | `CVE-2026-62901`, `GHSA-m93f-wj8c-rp8p` | `dotnet/runtime` | repo |
| `alias-5238761deeca8f5e00ba86b7` | `CVE-2026-62898`, `GHSA-c494-m2fq-59mx` | `dotnet/runtime` | repo |
| `alias-a287c67a615e11b4b714a509` | `CVE-2026-62902`, `GHSA-9mrh-pw7c-9mqm` | `dotnet/wpf` | repo |
| `alias-4b2ce0c68cba1f2a8c2d1a0f` | `CVE-2026-70354`, `GHSA-gg8c-3338-xw2f` | `dotnet/wpf` | repo |
| `alias-0e77da56f799e88a812d942b` | `CVE-2026-62886`, `GHSA-jqhp-238x-qhgf` | `dotnet/wpf` | repo |
| `alias-e12e63dbd0be3f29379f6764` | `CVE-2026-62899`, `GHSA-r6mh-95jw-g7qg` | `dotnet/runtime` | repo |
| `alias-c638a80e36aa9f6e145226ce` | `CVE-2026-62909`, `GHSA-9mr8-pwpw-3j2w` | `dotnet/runtime` | repo |

Leave `anthropics/claude-code` as `no_source` (public tree is not the CLI) — 28 reviewed clusters.

## Parser / clustering bugs to use on the next universe rebuild

1. github_slug / SKIP_GITHUB_OWNERS must drop orgs, apps, users, sponsors, security (already in oss_git_repos).
2. Add user-attachments to SKIP_GITHUB_OWNERS so parse_git_identity does not emit user-attachments/files (clone_url already returns None).
3. primary_repo must not prefer a 404 truncated slug over a commit-backed sibling (pytes sorts before pytest; helm-ch before helm-charts/openfga). Prefer identities_from_urls commit strength, then a live GitHub slug.
4. PoC name regex: ^pocs?([_-]|$), not ^poc[_-]?. Tests cover pocket-id, pocketbase, pocketmine-mp.
5. Do not mark the whole projectdiscovery owner as PoC. nuclei is the product; nuclei-templates stays poc.
6. Do not treat github.com/orgs/<name> or github.com/users/<name> as owner/repo.

## Not done / next step

- Ledger / artifacts/funnel-account-20260817.jsonl was not written this pass. Leader-only via scripts/ledger_store.py export after Neon finalize.
- Do not rewrite .ai-slop/state/refresh-20260826/upstream-deduped-20260826.jsonl until the next universe rebuild.
- On that rebuild: attach the five high-confidence clone-404 identities and the 46 reviewed-no-repo product identities listed here; skip issue-tracker-only Umbraco Forms rows for BIC/AI scan; skip claude-code facades.
- Then clone/scan those new identities (openfga/openfga, pytest-dev/pytest, papermark/papermark, spree/spree, surrealdb/surrealdb, plus pocket-id, nuclei, daytona, cryptography, …).
- limanmys/core is medium-confidence only — confirm against CVE-2020-37007 before booking.
- Unreviewed ~50k with empty skip_reason still have no forge URL in NVD/GHSA; do not crawl them in this lane.

Machine-readable companion: `artifacts/moved-repo-recall-recoveries-20260829.json`.
