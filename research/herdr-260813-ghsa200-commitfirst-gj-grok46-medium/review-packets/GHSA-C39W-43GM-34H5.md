# GHSA-C39W-43GM-34H5

repo: gogs/gogs

summary: Gogs has Path Traversal in organization name that results in RCE through Git hooks

aliases: ['CVE-2026-52813']

severity: CRITICAL

evidence: blame blamed_lines=1 files=['internal/route/api/v1/org.go']

intro: a1fa62b270bd87dc63a280b6eba98aa9cf9db845

intro_subject: all: decouple API types from go-gogs-client SDK (#8171)

intro_date: 2026-02-10T10:56:17-05:00

fix: f6acd467305943aae8403cbac81f0118dd1235d7

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
### Summary

Organization names containing path traversal sequences (`../`) are accepted by Gogs, and repositories under them are written to paths following these path traversals. This allows storing/retrieving data for repositories at arbitrary locations on the filesystem.
By creating nested structure of Git repositories, one can overwrite the other's `hooks` configuration to result in Remote Code Execution (RCE).

### Details

During organization creation, `internal/database/org.go` calls `os.MkdirAll(repox.UserPath(org.Name))` without sanitizing `org.Name`. 

https://github.com/gogs/gogs/blob/d7571322a04a29476d4241406ed50bf7eef0a5b7/internal/database/org.go#L165

Repository creation uses this name to decide where to write the Git bare repository's (`org/name.git`). By setting the org name to `../../../../tmp/test`, and creating a repository under that organization, it gets written under `/tmp/test` on the server.

https://github.com/gogs/gogs/blob/d7571322a04a29476d4241406ed50bf7eef0a5b7/internal/repox/repox.go#L57-L58

An attacker can abuse this in a clever way by writing to the `/data/gogs/data/tmp/local-r/1` directory, being a local worktree of the git repositories inside of Gogs. These directories are editable by Git. By creating a repository nested inside of there, files like `config` and `hooks/update` are now referenced through the path traversal, and are editable by Git. This allows the attacker to edit the `hooks/update` script with malicious Bash commands and then to trigger the hook.

The steps to exploit this inside of Gogs are roughly (ignoring some syncing dummy actions):

1. Create regular outer repository and get its ID
2. Create organization named `../../../../data/gogs/data/tmp/local-r/{ID}/nested`
3. Create a repository inside this organization (eg. `rce`), which will be written into the local clone of the outer repository
4. From the outer repository, edit `nested/rce.git/hooks/update` to contain malicious shell commands
5. Interact with the `rce` repository again to trigger the updated hook, and RCE is achieved

### PoC

1. Set up a default Gogs instance by saving the following content to `docker-compose.yml` and running `docker compose up`:

```yml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: gogs
      POSTGRES_PASSWORD: gogs
      POSTGRES_DB: gogs
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: [ "CMD-SHELL", "pg_isready -

REFS:
- WEB https://github.com/gogs/gogs/security/advisories/GHSA-c39w-43gm-34h5
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-52813
- WEB https://github.com/gogs/gogs/pull/8334
- WEB https://github.com/gogs/gogs/commit/f6acd467305943aae8403cbac81f0118dd1235d7
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
diff --git a/internal/route/api/v1/org.go b/internal/route/api/v1/org.go
new file mode 100644
index 00000000..5f2a4710
--- /dev/null
+++ b/internal/route/api/v1/org.go
@@ -0,0 +1,121 @@
+package v1
+
+import (
+	"net/http"
+
+	"gogs.io/gogs/internal/context"
+	"gogs.io/gogs/internal/database"
+	"gogs.io/gogs/internal/route/api/v1/types"
+)
+
+type createOrgRequest struct {
+	UserName    string `json:"username" binding:"Required"`
+	FullName    string `json:"full_name"`
+	Description string `json:"description"`
+	Website     string `json:"website"`
+	Location    string `json:"location"`
+}
+
+func createOrgForUser(c *context.APIContext, apiForm createOrgRequest, user *database.User) {
+	if c.Written() {
+		return
+	}
+
+	org := &database.User{
+		Name:        apiForm.UserName,
+		FullName:    apiForm.FullName,
+		Description: apiForm.Description,
+		Website:     apiForm.Website,
+		Location:    apiForm.Location,
+		IsActive:    true,
+		Type:        database.UserTypeOrganization,
+	}
+	if err := database.CreateOrganization(org, user); err != nil {
+		if database.IsErrUserAlreadyExist(err) ||
+			database.IsErrNameNotAllowed(err) {
+			c.ErrorStatus(http.StatusUnprocessableEntity, err)
+		} else {
+			c.Error(err, "create organization")
+		}
+		return
+	}
+
+	c.JSON(201, toOrganization(org))
+}
+
+func listOrgsOfUser(c *context.APIContext, u *database.User, all bool) {
+	orgs, err := database.Handle.Organizations().List(
+		c.Req.Context(),
+		database.ListOrgsOptions{
+			MemberID:              u.ID,
+			IncludePrivateMembers: all,
+		},
+	)
+	if err != nil {
+		c.Error(err, "list organizations")
+		return
+	}
+
+	apiOrgs := make([]*types.Organization, len(orgs))
+	for i := range orgs {
+		apiOrgs[i] = toOrganization(orgs[i])
+	}
+	c.JSONSuccess(&apiOrgs)
+}
+
+func listMyOrgs(c *context.APIContext) {
+	listOrgsOfUser(c, c.User, true)
+}
+
+func createMyOrg(c *context.APIContext, apiForm createOrgRequest) {
+	createOrgForUser(c, apiForm, c.User)
+}
+
+func listUserOrgs(c *context.APIContext) {
+	u := getUserByParams(c)
+	if c.Written() {
+		return
+	}
+	listOrgsOfUser(c, u, false)
+}
+
+func getOrg(c *context.APIContext) {
+	c.JSONSuccess(toOrganization(c.Org.Organization))
+}
+
+type editOrgRequest struct {
+	FullName    string `json:"full_name"`
+	Description string `json:"description"`
+	Website     string `json:"website"`
+	Location    string `json:"location"`
+}
+
+func editOrg(c *context.APIContext, form editOrgRequest) {
+	org := c.Org.Organization
+	if !org.IsOwnedBy(c.User.ID) {
+		c.Status(http.StatusForbidden)
+		return
+	}
+
+	err := database.Handle.Users().Update(
+		c.Req.Context(),
+		c.Org.Organization.ID,
+		database.UpdateUserOptions{
+			FullName:    &form.FullName,
+			Website:     &form.Website,
+			Location:    &form.Location,
+			Description: &form.Description,
+		},
+	)
+	if err != nil {
+		c.Error(err, "update organization")
+		return
+	}
+
+	org, err = database.GetOrgByName(org.Name)
+	if err != nil {
+		c.Error(err, "get organization")
+		return
+	}
+	c.JSONSuccess(toOrganization(org))
+}


FIX_LOG:
f6acd467305943aae8403cbac81f0118dd1235d7
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-06-06T23:14:42-04:00
security: reject path traversal in owner and repository names (#8334)




FIX_STAT:
 CHANGELOG.md                 | 1 +
 internal/repox/repox.go      | 7 +++++--
 internal/route/api/v1/org.go | 2 +-
 3 files changed, 7 insertions(+), 3 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/internal/route/api/v1/org.go b/internal/route/api/v1/org.go
index 5f2a4710..9e0461f3 100644
--- a/internal/route/api/v1/org.go
+++ b/internal/route/api/v1/org.go
@@ -9,7 +9,7 @@ import (
 )
 
 type createOrgRequest struct {
-	UserName    string `json:"username" binding:"Required"`
+	UserName    string `json:"username" binding:"Required;AlphaDashDot;MaxSize(35)"`
 	FullName    string `json:"full_name"`
 	Description string `json:"description"`
 	Website     string `json:"website"`


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []