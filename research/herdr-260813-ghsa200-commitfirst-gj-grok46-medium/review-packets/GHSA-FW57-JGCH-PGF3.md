# GHSA-FW57-JGCH-PGF3

repo: go-gitea/gitea

summary: Gitea: ParseAcceptLanguage quadratic-time DoS via Locale middleware on unauthenticated requests

aliases: ['CVE-2026-58436']

severity: HIGH

evidence: blame blamed_lines=1 files=['routers/api/v1/org/team.go']

intro: 0724344a8a0c2772b7f925e31014d37eaba1dab8

intro_subject: Fix CodeQL code scanning alerts (#36858)

intro_date: 2026-03-08T15:35:50+01:00

fix: f452c369acc9f1bd05ec6ef9c2e4399062dd6da1

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "code.gitea.io/gitea"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "1.27.0"
          }
        ]
      }
    ]
  }
]

DETAILS:
### Summary

The Locale middleware that runs in front of every unauthenticated request
calls `golang.org/x/text/language.ParseAcceptLanguage` on the raw
`Accept-Language` header without imposing a size or shape filter. The
underlying parser has quadratic-time behaviour on long lists of malformed
language tags. The CVE-2022-32149 guard that golang.org/x/text added in
v0.3.8 caps the number of `-` characters in the input at 1000, but it does
not cap `_` characters even though the parser's internal scanner aliases
`_` to `-` before parsing. A single unauthenticated GET request with an
`Accept-Language` header built out of `_` separators burns ~2 seconds of
server CPU on the host running Gitea; ten concurrent attackers saturate a
ten-core box for the duration of the attack while consuming ~1 MiB of
upstream bandwidth per request.

### Affected versions

`code.gitea.io/gitea` 1.22.6 and (per code inspection of `main`) all
earlier and later 1.22.x / 1.23.x / 1.24.x / 1.25.x / 1.26.x versions that
do not impose their own size limit on the `Accept-Language` header before
calling `ParseAcceptLanguage`. Verified on:

- the official `gitea/gitea:1.22.6` docker image (E2E below)
- `main` at commit `6f4027a6be28c876c0abaf37cc939658645b78a3` by reading
  `modules/web/middleware/locale.go` (the call site at line 38 is unchanged
  on `main`)

### Privilege required

Unauthenticated. The Locale middleware runs for every HTTP request
including the landing page and the sign-in page.

### Vulnerable code

[`modules/web/middleware/locale.go:38`](https://github.com/go-gitea/gitea/blob/fc396f0808187c358b4fc15dcefcd6957140a780/modules/web/middleware/locale.go#L38)
(blob SHA `fc396f0808187c358b4fc15dcefcd6957140a780`):

```go
// 3. Get language information from 'Accept-Language'.
// The first element in the list is chosen to be the default language automatically.
if len(lang) == 0 {
    tags, _, _ := language.ParseAcceptLanguage(req.Header.Get("Accept-Language"))
    tag := translation.Match(tags...)
    lang = tag.String()
}
```

`req.Header.Get("Accept-Language")` is the unfiltered HTTP header. Default
Go `net/http` `MaxHeaderBytes` is `1 << 20` = 1 MiB and Gitea does not
override it, so the parser is allowed to receive up to a megabyte of
attacker-controlled data.

CVE-2022-32149 hardened `ParseAcceptLanguage` by counting `-` characters
and rejecting inputs with more than 1000 of them. The guard does not count
`_` characters even though the scanner converts `_` to `-` at parse 

REFS:
- WEB https://github.com/go-gitea/gitea/security/advisories/GHSA-fw57-jgch-pgf3
- WEB https://github.com/go-gitea/gitea/pull/38323
- WEB https://github.com/go-gitea/gitea/commit/f452c369acc9f1bd05ec6ef9c2e4399062dd6da1
- PACKAGE https://github.com/go-gitea/gitea

INTRO_LOG:
0724344a8a0c2772b7f925e31014d37eaba1dab8
silverwind <me@silverwind.io>
2026-03-08T14:35:50+00:00
Fix CodeQL code scanning alerts (#36858)

Fixes 10 CodeQL code scanning alerts:

- Change `NewPagination`/`SetLinkHeader` to accept `int64` for total
count, clamping internally to fix incorrect-integer-conversion alerts
([#110](https://github.com/go-gitea/gitea/security/code-scanning/110),
[#114](https://github.com/go-gitea/gitea/security/code-scanning/114),
[#115](https://github.com/go-gitea/gitea/security/code-scanning/115),
[#116](https://github.com/go-gitea/gitea/security/code-scanning/116))
- Use `strconv.Atoi()` in `htmlrenderer.go` to avoid int64 intermediate
([#105](https://github.com/go-gitea/gitea/security/code-scanning/105),
[#106](https://github.com/go-gitea/gitea/security/code-scanning/106))
- Clamp regex match indices in `escape_stream.go` to fix
allocation-size-overflow
([#161](https://github.com/go-gitea/gitea/security/code-scanning/161),
[#162](https://github.com/go-gitea/gitea/security/code-scanning/162),
[#163](https://github.com/go-gitea/gitea/security/code-scanning/163))
- Cap slice pre-allocation in `GetIssueDependencies`
([#181](https://github.com/go-gitea/gitea/security/code-scanning/181))

---------

Co-authored-by: Claude (Opus 4.6) <noreply@anthropic.com>
Co-authored-by: wxiaoguang <wxiaoguang@gmail.com>


INTRO_STAT:
 modules/charset/escape_stream.go        |  8 +++++---
 modules/indexer/code/gitgrep/gitgrep.go |  4 ++--
 modules/indexer/code/search.go          |  4 ++--
 modules/templates/htmlrenderer.go       | 20 ++++++++++----------
 routers/api/v1/admin/adopt.go           |  2 +-
 routers/api/v1/admin/email.go           |  2 +-
 routers/api/v1/admin/hooks.go           |  2 +-
 routers/api/v1/admin/org.go             |  2 +-
 routers/api/v1/admin/user.go            |  2 +-
 routers/api/v1/notify/repo.go           |  2 +-
 routers/api/v1/notify/user.go           |  2 +-
 routers/api/v1/org/action.go            |  4 ++--
 routers/api/v1/org/member.go            |  2 +-
 routers/api/v1/org/org.go               |  4 ++--
 routers/api/v1/org/team.go              | 12 ++++++------
 routers/api/v1/packages/package.go      |  4 ++--
 routers/api/v1/repo/action.go           |  6 +++---
 routers/api/v1/repo/branch.go           |  2 +-
 routers/api/v1/repo/commits.go          |  2 +-
 routers/api/v1/repo/issue.go            |  4 ++--
 routers/api/v1/repo/issue_dependency.go |  4 ++--
 routers/api/v1/repo/mirror.go           |  2 +-
 routers/api/v1/repo/pull.go             |  6 +++---
 routers/api/v1/repo/release.go          |  2 +-
 routers/api/v1/repo/repo.go             |  2 +-
 routers/api/v1/repo/status.go           |  4 ++--
 routers/api/v1/repo/wiki.go             |  2 +-
 routers/api/v1/shared/action.go         |  4 ++--
 routers/api/v1/shared/block.go          |  2 +-
 routers/api/v1/use

INTRO_DIFF_OVERLAP:
diff --git a/routers/api/v1/org/team.go b/routers/api/v1/org/team.go
index 211b7a15b..3b5711eea 100644
--- a/routers/api/v1/org/team.go
+++ b/routers/api/v1/org/team.go
@@ -70,7 +70,7 @@ func ListTeams(ctx *context.APIContext) {
 		return
 	}
 
-	ctx.SetLinkHeader(int(count), listOptions.PageSize)
+	ctx.SetLinkHeader(count, listOptions.PageSize)
 	ctx.SetTotalCountHeader(count)
 	ctx.JSON(http.StatusOK, apiTeams)
 }
@@ -111,7 +111,7 @@ func ListUserTeams(ctx *context.APIContext) {
 		return
 	}
 
-	ctx.SetLinkHeader(int(count), listOptions.PageSize)
+	ctx.SetLinkHeader(count, listOptions.PageSize)
 	ctx.SetTotalCountHeader(count)
 	ctx.JSON(http.StatusOK, apiTeams)
 }
@@ -411,7 +411,7 @@ func GetTeamMembers(ctx *context.APIContext) {
 		members[i] = convert.ToUser(ctx, member, ctx.Doer)
 	}
 
-	ctx.SetLinkHeader(ctx.Org.Team.NumMembers, listOptions.PageSize)
+	ctx.SetLinkHeader(int64(ctx.Org.Team.NumMembers), listOptions.PageSize)
 	ctx.SetTotalCountHeader(int64(ctx.Org.Team.NumMembers))
 	ctx.JSON(http.StatusOK, members)
 }
@@ -583,7 +583,7 @@ func GetTeamRepos(ctx *context.APIContext) {
 		}
 		repos[i] = convert.ToRepo(ctx, repo, permission)
 	}
-	ctx.SetLinkHeader(team.NumRepos, listOptions.PageSize)
+	ctx.SetLinkHeader(int64(team.NumRepos), listOptions.PageSize)
 	ctx.SetTotalCountHeader(int64(team.NumRepos))
 	ctx.JSON(http.StatusOK, repos)
 }
@@ -827,7 +827,7 @@ func SearchTeam(ctx *context.APIContext) {
 		return
 	}
 
-	ctx.SetLinkHeader(int(maxResults), listOptions.PageSize)
+	ctx.SetLinkHeader(maxResults, listOptions.PageSize)
 	ctx.SetTotalCountHeader(maxResults)
 	ctx.JSON(http.StatusOK, map[string]any{
 		"ok":   true,
@@ -882,7 +882,7 @@ func ListTeamActivityFeeds(ctx *context.APIContext) {
 		ctx.APIErrorInternal(err)
 		return
 	}
-	ctx.SetLinkHeader(int(count), listOptions.PageSize)
+	ctx.SetLinkHeader(count, listOptions.PageSize)
 	ctx.SetTotalCountHeader(count)
 	ctx.JSON(http.StatusOK, convert.ToActivities(ctx, feeds, ctx.Doer))
 }


FIX_LOG:
f452c369acc9f1bd05ec6ef9c2e4399062dd6da1
bircni <bircni@icloud.com>
2026-07-10T16:39:01+00:00
fix: enforce public-only token scope and harden push options / locale parsing (#38323)

- **Locale DoS:** the `Locale` middleware passed the raw
`Accept-Language` header to `ParseAcceptLanguage`, whose guard only
counts `-` while the scanner aliases `_` to `-` — a large `_`-separated
header on an unauthenticated request burned CPU. The header is now
length-bounded before parsing.
- **Public-only token scope:** `GET /teams/{id}/repos`,
`.../repos/{org}/{repo}`, `/teams/{id}/activities/feeds`, and
`/users/{username}/orgs/{org}/permissions` still returned private
repo/activity/permission data to a public-only token. They now filter
via `TokenCanAccessRepo` / `ApplyPublicOnly` and reject non-public org
permissions.
- **Push-option visibility:** `repo.private` / `repo.template` push
options were applied to any existing repo, letting an owner/admin
silently flip visibility bypassing audit, webhooks, and notifications.
They are now honored only on push-to-create.


FIX_STAT:
 models/repo/org_repo.go                   | 25 ++++++++++---
 modules/web/middleware/locale.go          | 20 ++++++++++-
 modules/web/middleware/locale_test.go     | 27 ++++++++++++++
 routers/api/v1/org/org.go                 |  7 ++++
 routers/api/v1/org/team.go                | 30 +++++++++++++---
 routers/private/hook_post_receive.go      | 13 +++++--
 tests/integration/api_public_only_test.go | 58 +++++++++++++++++++++++++++++++
 tests/integration/git_push_test.go        | 38 ++++++++++++++++++++
 8 files changed, 204 insertions(+), 14 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/routers/api/v1/org/team.go b/routers/api/v1/org/team.go
index bc6bb54e9..f15196e48 100644
--- a/routers/api/v1/org/team.go
+++ b/routers/api/v1/org/team.go
@@ -567,10 +567,20 @@ func GetTeamRepos(ctx *context.APIContext) {
 
 	team := ctx.Org.Team
 	listOptions := utils.GetListOptions(ctx)
-	teamRepos, err := repo_model.GetTeamRepositories(ctx, &repo_model.SearchTeamRepoOptions{
+	// A public-only token must not expose (or count) private repos, even when the
+	// doer owning the token otherwise has access to them, so filter them out at the
+	// query level to keep the returned page and the total-count header consistent.
+	searchOpts := &repo_model.SearchTeamRepoOptions{
 		ListOptions: listOptions,
 		TeamID:      team.ID,
-	})
+		PublicOnly:  ctx.PublicOnly,
+	}
+	teamRepos, err := repo_model.GetTeamRepositories(ctx, searchOpts)
+	if err != nil {
+		ctx.APIErrorInternal(err)
+		return
+	}
+	count, err := repo_model.CountTeamRepositories(ctx, searchOpts)
 	if err != nil {
 		ctx.APIErrorInternal(err)
 		return
@@ -584,14 +594,16 @@ func GetTeamRepos(ctx *context.APIContext) {
 		}
 		// A team's repo list is reachable by non-team-members through the team's
 		// visibility tier, so never expose repos (incl. their names) the doer
-		// cannot access.
+		// cannot access. This per-repo visibility trim can't be expressed in the
+		// SQL count above without regressing per-unit public access, so for such
+		// non-members the total-count header may be a small upper bound.
 		if !permission.HasAnyUnitAccessOrPublicAccess() {
 			continue
 		}
 		repos = append(repos, convert.ToRepo(ctx, repo, permission))
 	}
-	ctx.SetLinkHeader(int64(team.NumRepos), listOptions.PageSize)
-	ctx.SetTotalCountHeader(int64(team.NumRepos))
+	ctx.SetLinkHeader(count, listOptions.PageSize)
+	ctx.SetTotalCountHeader(count)
 	ctx.JSON(http.StatusOK, repos)
 }
 
@@ -630,6 +642,12 @@ func GetTeamRepo(ctx *context.APIContext) {
 		return
 	}
 
+	// A public-only token must not confirm the existence of a private repo.
+	if !ctx.TokenCanAccessRepo(repo) {
+		ctx.APIErrorNotFound()
+		return
+	}
+
 	if !organization.HasTeamRepo(ctx, ctx.Org.Team.OrgID, ctx.Org.Team.ID, repo.ID) {
 		ctx.APIErrorNotFound()
 		return
@@ -889,6 +907,8 @@ func ListTeamActivityFeeds(ctx *context.APIContext) {
 		Date:           ctx.FormString("date"),
 		ListOptions:    listOptions,
 	}
+	// A public-only token must not receive private activity entries.
+	opts.ApplyPublicOnly(ctx.PublicOnly)
 
 	feeds, count, err := feed_service.GetFeeds(ctx, opts)
 	if err != nil {


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []