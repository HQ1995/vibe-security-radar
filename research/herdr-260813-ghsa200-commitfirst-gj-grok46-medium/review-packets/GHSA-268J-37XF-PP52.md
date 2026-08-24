# GHSA-268J-37XF-PP52

repo: gogs/gogs

summary: Gogs's write-level collaborators can mutate admin-only repository settings via API

aliases: ['CVE-2026-52808']

severity: HIGH

evidence: blame blamed_lines=3 files=['internal/route/api/v1/api.go']

intro: a1fa62b270bd87dc63a280b6eba98aa9cf9db845

intro_subject: all: decouple API types from go-gogs-client SDK (#8171)

intro_date: 2026-02-10T10:56:17-05:00

fix: 6283462119bd8894f1599d70339b5e823f99954a

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "gogs.io/gogs"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "0.14.3"
          }
        ]
      }
    ]
  }
]

DETAILS:
## Summary

Three API endpoints — `PATCH /api/v1/repos/:owner/:repo/issue-tracker`, `PATCH /api/v1/repos/:owner/:repo/wiki`, and `POST /api/v1/repos/:owner/:repo/mirror-sync` — are gated by `reqRepoWriter()` rather than `reqRepoAdmin()`. The equivalent operations in the web UI sit behind `reqRepoAdmin`, which requires `AccessMode >= AccessModeAdmin`. A write-level collaborator (who has `AccessMode == AccessModeWrite < AccessModeAdmin`) can therefore call these API endpoints directly to disable the native issue tracker or wiki, inject attacker-controlled external tracker/wiki URLs that redirect all repository visitors, or trigger mirror sync — none of which they are authorized to do.

## Severity

**High** (CVSS 3.1: 7.1)

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L`

- **Attack Vector:** Network — the API endpoints are reachable over HTTP/S.
- **Attack Complexity:** Low — a single API call is sufficient; no chaining or race condition required.
- **Privileges Required:** Low — only write-level collaborator access to the targeted repository is needed. The attacker does not need repo-admin or site-admin privileges.
- **User Interaction:** None — the attacker acts unilaterally.
- **Scope:** Unchanged — the impact is contained to the targeted repository's settings and its visitors.
- **Confidentiality Impact:** None — the attacker does not read confidential data directly.
- **Integrity Impact:** High — the attacker permanently mutates repository configuration, including injecting an external URL that redirects all visitors who click the Issues or Wiki tabs to an attacker-controlled site.
- **Availability Impact:** Low — disabling the native issue tracker or wiki reduces the availability of those features for all repository participants.


## Affected component

- `internal/route/api/v1/api.go` — route registration (lines 365–367)
- `internal/route/api/v1/repo_repo.go` — `issueTracker()` (line 400), `wiki()` (line 437), `mirrorSync()` (line 463)

## CWE

- **CWE-863**: Incorrect Authorization
- **CWE-269**: Improper Privilege Management

## Description

### Three admin-equivalent API endpoints are protected by write-level middleware

`api.go:365-367` registers the three settings endpoints with `reqRepoWriter()`:

```go
// internal/route/api/v1/api.go:365-367
m.Patch("/issue-tracker", reqRepoWriter(), bind(editIssueTrackerRequest{}), issueTracker)
m.Patch("/wiki", reqRepoWriter(), bind(editWikiRequest{}), wiki)
m.Post("/mirror-sync", reqRepoWriter(), mirrorSync

REFS:
- WEB https://github.com/gogs/gogs/security/advisories/GHSA-268j-37xf-pp52
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-52808
- WEB https://github.com/gogs/gogs/pull/8327
- WEB https://github.com/gogs/gogs/commit/6283462119bd8894f1599d70339b5e823f99954a
- PACKAGE https://github.com/gogs/gogs
- WEB https://github.com/gogs/gogs/releases/tag/v0.14.3

INTRO_LOG:
a1fa62b270bd87dc63a280b6eba98aa9cf9db845
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-02-10T10:56:17-05:00
all: decouple API types from go-gogs-client SDK (#8171)

Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>


INTRO_STAT:
 go.mod                                             |   1 -
 go.sum                                             |   2 -
 internal/database/actions.go                       |  28 +-
 internal/database/comment.go                       |  23 +-
 internal/database/issue.go                         |  93 ++++---
 internal/database/issue_label.go                   |   6 +-
 internal/database/milestone.go                     |  22 +-
 internal/database/pull.go                          |  24 +-
 internal/database/release.go                       |  10 +-
 internal/database/repo.go                          |  10 +-
 internal/database/repo_collaboration.go            |  10 +-
 internal/database/repositories.go                  |  10 +-
 internal/database/users.go                         |   8 +-
 internal/database/webhook.go                       |  61 ++---
 internal/database/webhook_dingtalk.go              |  56 ++--
 internal/database/webhook_discord.go               | 103 ++++---
 internal/database/webhook_slack.go                 |  85 +++---
 internal/route/api/v1/adapters.go                  | 303 +++++++++++++++++++++
 internal/route/api/v1/admin/org.go                 |  13 -
 internal/route/api/v1/admin/repo.go                |  18 --
 internal/route/api/v1/admin_org.go                 |   9 +
 .../v1/{admin/org_repo.go => admin_org_repo.go}    |  12 +-
 .../v1/{admin/org_team.go => admin_org_team.go}    |  31 ++-
 internal/route/api/v1/admin_repo.go                |  14 +
 .

INTRO_DIFF_OVERLAP:
diff --git a/internal/route/api/v1/api.go b/internal/route/api/v1/api.go
index 8304d876..b3033d0a 100644
--- a/internal/route/api/v1/api.go
+++ b/internal/route/api/v1/api.go
@@ -7,16 +7,9 @@ import (
 	"github.com/go-macaron/binding"
 	"gopkg.in/macaron.v1"
 
-	api "github.com/gogs/go-gogs-client"
-
 	"gogs.io/gogs/internal/context"
 	"gogs.io/gogs/internal/database"
 	"gogs.io/gogs/internal/form"
-	"gogs.io/gogs/internal/route/api/v1/admin"
-	"gogs.io/gogs/internal/route/api/v1/misc"
-	"gogs.io/gogs/internal/route/api/v1/org"
-	"gogs.io/gogs/internal/route/api/v1/repo"
-	"gogs.io/gogs/internal/route/api/v1/user"
 )
 
 // repoAssignment extracts information from URL parameters to retrieve the repository,
@@ -181,245 +174,245 @@ func RegisterRoutes(m *macaron.Macaron) {
 		m.Options("/*", func() {})
 
 		// Miscellaneous
-		m.Post("/markdown", bind(api.MarkdownOption{}), misc.Markdown)
-		m.Post("/markdown/raw", misc.MarkdownRaw)
+		m.Post("/markdown", bind(markdownRequest{}), markdown)
+		m.Post("/markdown/raw", markdownRaw)
 
 		// Users
 		m.Group("/users", func() {
-			m.Get("/search", user.Search)
+			m.Get("/search", searchUsers)
 
 			m.Group("/:username", func() {
-				m.Get("", user.GetInfo)
+				m.Get("", getUserProfile)
 
 				m.Group("/tokens", func() {
-					accessTokensHandler := user.NewAccessTokensHandler(user.NewAccessTokensStore())
+					accessTokensHandler := newAccessTokensHandler(newAccessTokensStore())
 					m.Combo("").
 						Get(accessTokensHandler.List()).
-						Post(bind(api.CreateAccessTokenOption{}), accessTokensHandler.Create())
+						Post(bind(createAccessTokenRequest{}), accessTokensHandler.Create())
 				}, reqBasicAuth())
 			})
 		})
 
 		m.Group("/users", func() {
 			m.Group("/:username", func() {
-				m.Get("/keys", user.ListPublicKeys)
+				m.Get("/keys", listPublicKeys)
 
-				m.Get("/followers", user.ListFollowers)
+				m.Get("/followers", listFollowers)
 				m.Group("/following", func() {
-					m.Get("", user.ListFollowing)
-					m.Get("/:target", user.CheckFollowing)
+					m.Get("", listFollowing)
+					m.Get("/:target", checkFollowing)
 				})
 			})
 		}, reqToken())
 
 		m.Group("/user", func() {
-			m.Get("", user.GetAuthenticatedUser)
+			m.Get("", getAuthenticatedUser)
 			m.Combo("/emails").
-				Get(user.ListEmails).
-				Post(bind(api.CreateEmailOption{}), user.AddEmail).
-				Delete(bind(api.CreateEmailOption{}), user.DeleteEmail)
+				Get(listEmails).
+				Post(bind(createEmailRequest{}), addEmail).
+				Delete(bind(createEmailRequest{}), deleteEmail)
 
-			m.Get("/followers", user.ListMyFollowers)
+			m.Get("/followers", listMyFollowers)
 			m.Group("/following", func() {
-				m.Get("", user.ListMyFollowing)
+				m.Get("", listMyFollowing)
 				m.Combo("/:username").
-					Get(user.CheckMyFollowing).
-					Put(user.Follow).
-					Delete(user.Unfollow)
+					Get(checkMyFollowing).
+					Put(follow).
+					Delete(unfollow)
 			})
 
 			m.Group("/keys", func() {
 				m.Combo("").
-					Get(user.ListMyPublicKeys).
-					Post(bind(api.CreateKeyOption{}), user.CreatePublicKey)
+					Get(listMyPublicKeys).
+					Post(bind(createPublicKeyRequest{}), createPublicKey)
 				m.Combo("/:id").
-					Get(user.GetPublicKey).
-					Delete(user.DeletePublicKey)
+					Get(getPublicKey).
+					Delete(deletePublicKey)
 			})
 
-			m.Get("/issues", repo.ListUserIssues)
+			m.Get("/issues", listUserIssues)
 		}, reqToken())
 
 		// Repositories
-		m.Get("/users/:username/repos", reqToken(), repo.ListUserRepositories)
-		m.Get("/orgs/:org/repos", reqToken(), repo.ListOrgRepositories)
+		m.Get("/users/:username/repos", reqToken(), listUserRepositories)
+		m.Get("/orgs/:org/repos", reqToken(), listOrgRepositories)
 		m.Combo("/user/repos", reqToken()).
-			Get(repo.ListMyRepos).
-			Post(bind(api.CreateRepoOption{}), repo.Create)
-		m.Post("/org/:org/repos", reqToken(), bind(api.CreateRepoOption{}), repo.CreateOrgRepo)
+			Get(listMyRepos).
+			Post(bind(createRepoRequest{}), createRepo)
+		m.Pos

FIX_LOG:
6283462119bd8894f1599d70339b5e823f99954a
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-06-05T23:21:15-04:00
security: require admin for repo settings API endpoints (#8327)




FIX_STAT:
 CHANGELOG.md                 | 1 +
 internal/route/api/v1/api.go | 6 +++---
 2 files changed, 4 insertions(+), 3 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/internal/route/api/v1/api.go b/internal/route/api/v1/api.go
index b3033d0a..0389096b 100644
--- a/internal/route/api/v1/api.go
+++ b/internal/route/api/v1/api.go
@@ -362,9 +362,9 @@ func RegisterRoutes(m *macaron.Macaron) {
 						Delete(deleteMilestone)
 				}, reqRepoWriter())
 
-				m.Patch("/issue-tracker", reqRepoWriter(), bind(editIssueTrackerRequest{}), issueTracker)
-				m.Patch("/wiki", reqRepoWriter(), bind(editWikiRequest{}), wiki)
-				m.Post("/mirror-sync", reqRepoWriter(), mirrorSync)
+				m.Patch("/issue-tracker", reqRepoAdmin(), bind(editIssueTrackerRequest{}), issueTracker)
+				m.Patch("/wiki", reqRepoAdmin(), bind(editWikiRequest{}), wiki)
+				m.Post("/mirror-sync", reqRepoAdmin(), mirrorSync)
 				m.Get("/editorconfig/:filename", context.RepoRef(), getEditorconfig)
 			}, repoAssignment())
 		}, reqToken())


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []