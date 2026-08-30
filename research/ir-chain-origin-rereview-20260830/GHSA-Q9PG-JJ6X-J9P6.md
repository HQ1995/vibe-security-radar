# GHSA-Q9PG-JJ6X-J9P6 original-introducer re-review

## Result

The missing `ir_chain.original_sha` can be closed for the attachment mechanism
stated on the published case. The smallest reconstructable public commit that
first made an uploaded file into a **draft release attachment** while the
pre-existing UUID download route served it without a draft/write check is:

| Field | Result |
|---|---|
| Repository | `go-gitea/gitea` |
| Residual advisory | `GHSA-Q9PG-JJ6X-J9P6` / `CVE-2026-58432` |
| Original advisory | `GHSA-X92V-F5GC-R34V` / `CVE-2026-27660` |
| Atomic original SHA | `a487fa8ef7012007a6c9d89a810403a39b568aea` |
| Immediate parent | `21927a98681bfc597a77eb7f6e68fd533f142ec0` |
| Parent absence | **Verified** |
| Mainline squash carrier | `64375d875b4d46a6081026290da8efd82c84b25f` |
| Author | `Philip Couling <couling@gmail.com>` |
| Committer | `Philip Couling <couling@gmail.com>` |
| Authored/committed | `2017-01-12T19:05:46Z` |
| Original author kind | `HUMAN` |
| AI marker on atomic BIC | **Absent** |
| Confidence | **HIGH** |
| Remaining gap | None for attachment-origin SHA, parent boundary, or authorship |

`a487fa8e` is a retained member of PR #673, not a mainline ancestor. GitHub
squashed the six PR members into `64375d87`. The public PR history permits the
aggregate to be decomposed, so the carrier must not be substituted for the
smaller BIC.

The existing `original_sink` text combines three independently introduced
surfaces. There is no truthful single SHA for the whole phrase “API release
routes and UUID-based web ServeAttachment routes.” For completeness:

| Surface | Atomic first write | Mainline carrier | Parent absence |
|---|---|---|---|
| Direct API draft-release data (`GET /releases/{id}`) | `0c301f7b5c7a9cc691421724c154b40247aa6959` | same SHA | Verified |
| Release attachment creation + UUID web download | `a487fa8ef7012007a6c9d89a810403a39b568aea` | `64375d875b4d46a6081026290da8efd82c84b25f` | Verified |
| API attachment/listing routes and `browser_download_url` | `25615b1430ddfdb6efeb3482bc71d0b0feb1b4d0` | `9a5e628a7e8bc8e7de6ed05f3621442de3388086` | Verified |

Because the displayed `original_mechanism` is specifically “Draft release
attachments could be downloaded,” `a487fa8e` is the correct primary
`original_sha`. The two API origins should be retained as secondary provenance,
not silently collapsed into it.

Primary sources:

- [Original GitHub advisory](https://github.com/advisories/GHSA-x92v-f5gc-r34v)
- [Gitea CNA CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-27660)
- [Residual first-party advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-q9pg-jj6x-j9p6)
- [PR #673: Attach to release](https://github.com/go-gitea/gitea/pull/673)
- [Atomic attachment BIC `a487fa8e`](https://github.com/go-gitea/gitea/commit/a487fa8ef7012007a6c9d89a810403a39b568aea)
- [Mainline carrier `64375d87`](https://github.com/go-gitea/gitea/commit/64375d875b4d46a6081026290da8efd82c84b25f)
- [PR #3478: Add Attachment API](https://github.com/go-gitea/gitea/pull/3478)
- [Atomic API-attachment origin `25615b14`](https://github.com/go-gitea/gitea/commit/25615b1430ddfdb6efeb3482bc71d0b0feb1b4d0)
- [Direct-release API origin `0c301f7b`](https://github.com/go-gitea/gitea/commit/0c301f7b5c7a9cc691421724c154b40247aa6959)
- [Attempted remediation PR #36659](https://github.com/go-gitea/gitea/pull/36659)
- [Final web fix PR #38318](https://github.com/go-gitea/gitea/pull/38318)

## Vulnerability mechanism and source-to-sink

Draft support already existed, and the immediate parent already mounted a
UUID-based download endpoint in an `ignSignIn` group:

```go
m.Get("/attachments/:uuid", func(ctx *context.Context) {
    attach, err := models.GetAttachmentByUUID(ctx.Params(":uuid"))
    // ...
    fr, err := os.Open(attach.LocalPath())
    // ...
    repo.ServeData(ctx, attach.Name, fr)
})
```

That handler made no repository, release, `IsDraft`, read-permission, or
write-permission decision. Before `a487fa8e`, however, the product had no
release upload form and no code that associated uploaded UUIDs with a release.

`a487fa8e` adds the missing source/linkage. The release form uploads to the
generic attachment endpoint, whose JSON response exposes the UUID; the shared
JavaScript places that UUID in a hidden `files` input. `NewReleasePost` passes
those UUIDs into `CreateRelease`, including when `form.Draft` sets `IsDraft`:

```go
rel := &models.Release{
    // ...
    IsDraft: len(form.Draft) > 0,
}

var attachmentUUIDs []string
if setting.AttachmentEnabled {
    attachmentUUIDs = form.Files
}
models.CreateRelease(ctx.Repo.GitRepo, rel, attachmentUUIDs)
```

The same commit resolves each UUID and writes its release linkage:

```go
for _, uuid := range attachmentUUIDs {
    attach, err := getAttachmentByUUID(x, uuid)
    // ...
    attachments = append(attachments, attach)
}

for i := range attachments {
    attachments[i].ReleaseID = issueID
    x.Id(attachments[i].ID).Update(attachments[i])
}
```

The first version incorrectly used the `InsertOne` rows-affected result
(`issueID`, normally `1`) rather than `rel.ID`. This does not defeat the BIC:
the upload endpoint has already returned a globally downloadable UUID, and a
first release with ID 1 is also linked. The next PR member, `aa4d9e08`, changes
the assignment to `rel.ID` and adds release-page download links, expanding the
same already-existing flaw rather than introducing it.

The completed source-to-sink at `a487fa8e` is therefore:

```text
authorized writer opens draft-release form
  -> generic /attachments upload returns UUID
  -> form supplies UUID to CreateRelease with IsDraft=true
  -> attachment is associated with the release
  -> /attachments/:uuid loads by UUID
  -> file bytes are served without a draft/write check
```

## Atomic BIC and immediate-parent absence

The local clone is complete (`git rev-parse --is-shallow-repository` returned
`false`). The retained first-party PR heads were fetched from
`refs/pull/673/head` and `refs/pull/3478/head`; all heavy Git work ran under
`numactl --cpunodebind=1 --membind=1`.

The raw atomic object has exactly one parent:

```text
commit:    a487fa8ef7012007a6c9d89a810403a39b568aea
parent:    21927a98681bfc597a77eb7f6e68fd533f142ec0
author:    Philip Couling <couling@gmail.com> 1484257546 +0000
committer: Philip Couling <couling@gmail.com> 1484257546 +0000
subject:   Implemented attachment upload on release page
```

Direct parent-tree checks establish the boundary:

```text
$ git grep -F 'attachments[i].ReleaseID' a487fa8e^ -- models/release.go
# no output

$ git grep -F 'attachmentUUIDs = form.Files' a487fa8e^ -- routers/repo/release.go
# no output

$ git grep -F 'm.Get("/attachments/:uuid"' a487fa8e^ -- cmd/web.go
cmd/web.go:289: m.Get("/attachments/:uuid", func(ctx *context.Context) {

$ git grep -F 'IsDraft' a487fa8e^ -- models/release.go
models/release.go:38: IsDraft bool ...
```

Thus the parent has both prerequisites—draft releases and an unchecked UUID
download handler—but no path that uploads or binds an attachment to a release.
`a487fa8e` is the last missing causal edge and the first vulnerable revision for
the attachment mechanism.

## Squash decomposition and mainline carrier

[PR #673](https://github.com/go-gitea/gitea/pull/673) retains six member
commits:

1. `21927a98681bfc597a77eb7f6e68fd533f142ec0` — move the generic attachment
   upload URL.
2. `a487fa8ef7012007a6c9d89a810403a39b568aea` — add release upload UI and bind
   uploaded UUIDs to newly created releases; **atomic BIC**.
3. `aa4d9e085adcb5a210bb14d5f4749a1ae2d87830` — correct the release-ID
   assignment and display download links.
4. `497b38fbfac9659100ea0f3f50aff5484afdab27` — add archive MIME types.
5. `2df05d14d017e2c3f0621c87b6ba1e255be54026` — support attachments while
   editing a release.
6. `0e05278015c5fe83bd300447ac27a22986a2a139` — rename the upload handler.

GitHub reports `64375d875b4d46a6081026290da8efd82c84b25f` as the PR's squash merge.
Its message concatenates all six member subjects and its tree contains the
cumulative release-attachment implementation. It is the mainline carrier, not
the smallest public origin. The carrier is present in the first stable
containing release, [v1.1.0](https://github.com/go-gitea/gitea/releases/tag/v1.1.0),
published 2017-03-09.

## Independent API origins

### Direct release data: `0c301f7b`

`0c301f7b5c7a9cc691421724c154b40247aa6959` creates
`routers/api/v1/repo/release.go` and mounts `GET /releases/{id}`. Its
`GetRelease` verifies only that `release.RepoID` matches the route repository;
it does not inspect `release.IsDraft` or require write permission. Its immediate
parent `b7e1bccc501c5246e6f8b9bed4853b90e9a447c5` has no such file or route.

This is the atomic origin for the original advisory's “draft release data”
branch, but it predates release attachments and therefore is not the right SHA
for the published attachment-specific `original_mechanism`.

### API attachments: `25615b14`

The first member of PR #3478,
`25615b1430ddfdb6efeb3482bc71d0b0feb1b4d0`, creates
`release_attachment.go`, mounts unauthenticated GET list/item routes, loads
attachments into release API responses, and serializes
`browser_download_url` as `/attachments/{uuid}`. Neither
`GetReleaseAttachment` nor `ListReleaseAttachments` checks `IsDraft` or write
permission. Its immediate parent
`011f128c892e86e753a8ac8d94d73e4676648db2` has no
`release_attachment.go` and no API attachment routes.

GitHub later squashed the 35-member PR into mainline carrier
`9a5e628a7e8bc8e7de6ed05f3621442de3388086`, first contained in stable
[v1.5.0](https://github.com/go-gitea/gitea/releases/tag/v1.5.0). This API origin
is secondary provenance for the composite chain, not a replacement for the
earlier web attachment BIC.

## Evolution into `ServeAttachment` and rejected false origins

The inline UUID handler was subsequently moved and hardened. In particular:

- `8b2407371365fc123fc368bfd46b15f55ba8ae6a` moved serving into an attachment
  handler and added `perm.CanRead(unitType)`. It is a partial hardening commit;
  it did not create release attachments and still did not distinguish drafts.
- `42919ccb7cd32ab67d0878baf2bac6cd007899a8` renamed/refactored the handler to
  `ServeAttachment` while adding predictable release URLs. It is not the first
  vulnerable write.
- `6a3611cc3d3b2e401464a855f4630f606f52eb67`, previously mentioned in the case's
  `research_status`, changes only license and gitignore data. It does not touch
  any attachment, release, router, or permission file and cannot be a BIC.

`git blame -M -C` on the pre-fix `ServeAttachment` correctly traces the
read-only permission line to `8b240737`, but blame of the final sink is not the
causal question. The release-attachment feature had already made the unchecked
UUID path exploitable in `a487fa8e`.

## Attempted remediation, residual bypass, and final closure

The attempted remediation
[`1eced4a7c099459af42412bb32a83241650c0f8f`](https://github.com/go-gitea/gitea/commit/1eced4a7c099459af42412bb32a83241650c0f8f)
adds `canAccessDraftRelease` to:

- API `GetRelease`;
- API release listing;
- API release-attachment item/list paths.

Its changed-file set contains only API routers, fixtures, and API tests. It does
not touch `routers/web/repo/attachment.go`. The commit is present on mainline
from v1.26.0; backport
`e7fca90a780e4d35eb1fa67b1f377ebd54e74611` shipped in
[v1.25.5](https://github.com/go-gitea/gitea/releases/tag/v1.25.5). Its message
contains `Co-authored-by: Copilot`, which is causal to the incomplete
remediation classification but not to original-BIC authorship.

The residual advisory precisely identifies the missed web mirror. Final
mainline fix
[`f7fd51022495737cf960b8c4053a27d69148f664`](https://github.com/go-gitea/gitea/commit/f7fd51022495737cf960b8c4053a27d69148f664)
and release/v1.27 backport
[`ab10e37acf7fabf7829a485cc3e13d118638a856`](https://github.com/go-gitea/gitea/commit/ab10e37acf7fabf7829a485cc3e13d118638a856)
add the `IsDraft` plus `CanWrite(unit.TypeReleases)` decision inside
`ServeAttachment`. The backport shipped in
[v1.27.0](https://github.com/go-gitea/gitea/releases/tag/v1.27.0).

Full-history ancestry checks passed for both mainline carriers before the
attempted fix, and for the attempted fix before the final mainline fix:

```text
64375d87 -> 1eced4a7^ : PASS
9a5e628a -> 1eced4a7^ : PASS
1eced4a7 -> f7fd5102^ : PASS
```

## Authorship and AI marker

The raw atomic BIC object identifies Philip Couling as both author and
committer. Its complete message is only `Implemented attachment upload on
release page`; it has no `Co-authored-by`, bot, Copilot, Claude, Codex, Cursor,
or generator trailer. GitHub also maps the PR member to the human account
`couling`. Under the audit protocol, `original_author_kind` is therefore
`HUMAN` and `original_ai_marker` is `absent`.

The squash carrier records Philip Couling as author and Lunny Xiao as
committer, also without an AI marker. The Copilot trailer on the 2026 attempted
remediation must not be projected backward onto either 2017 origin object.

## Recommended `ir_chain` correction

For the existing attachment-specific display fields:

```json
{
  "original_sha": "a487fa8ef7012007a6c9d89a810403a39b568aea",
  "original_author_kind": "HUMAN",
  "original_author_name": "Philip Couling"
}
```

For provenance-capable storage, retain the decomposition and composite origins:

```json
{
  "original_parent": "21927a98681bfc597a77eb7f6e68fd533f142ec0",
  "original_parent_absent": true,
  "original_squash_decomposed": true,
  "original_mainline_carrier": "64375d875b4d46a6081026290da8efd82c84b25f",
  "original_decomposed_shas": [
    "a487fa8ef7012007a6c9d89a810403a39b568aea"
  ],
  "original_ai_marker": "absent",
  "original_secondary_origins": [
    {
      "surface": "direct API release data",
      "sha": "0c301f7b5c7a9cc691421724c154b40247aa6959"
    },
    {
      "surface": "API release attachments and browser_download_url",
      "sha": "25615b1430ddfdb6efeb3482bc71d0b0feb1b4d0",
      "mainline_carrier": "9a5e628a7e8bc8e7de6ed05f3621442de3388086"
    }
  ]
}
```

If the publication schema cannot retain secondary origins, narrow
`original_sink` to “Gitea release-attachment linkage and UUID web download
route (later `ServeAttachment`)” rather than implying that one SHA introduced
all API and web surfaces.

## Evidence boundary

This closes the public Git origin, immediate-parent, squash-decomposition,
authorship, and AI-marker questions for the attachment mechanism. It does not
claim knowledge of Philip Couling's private tooling; `HUMAN` means the causal
public commit has a human identity and no explicit AI provenance marker under
the repository's audit rule. No canonical ledger, database, publication data,
or web artifact was modified by this re-review.
