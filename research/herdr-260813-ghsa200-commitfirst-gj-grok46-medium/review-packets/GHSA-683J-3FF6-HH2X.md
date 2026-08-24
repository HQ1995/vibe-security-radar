# GHSA-683J-3FF6-HH2X

repo: go-gitea/gitea

summary: Gitea: Privilege Escalation via Access Token Scope Escalation in API

aliases: ['CVE-2026-56654']

severity: HIGH

evidence: file_history blamed_lines=0 files=['custom/conf/app.example.ini']

intro: 0ba862cb9779a6c720f5031c4838427ddf90f86f

intro_subject: Add DEFAULT_TITLE_SOURCE setting for pull request title default behavior (#37465)

intro_date: 2026-04-28T23:33:20+02:00

fix: de4b8277e9cb576f2315fb03b5ab6478b42a1d31

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
Gitea's API endpoint for creating Personal Access Tokens (`POST /users/{username}/tokens`) is protected by a middleware (`reqBasicOrRevProxyAuth`) that is intended to require password-based authentication, preventing a compromised token from being used to mint new ones. However, when a token is passed in the `Authorization: Basic <token>:x-oauth-basic` format, the Basic auth handler validates it and sets `AuthedMethod="basic"`, causing `IsBasicAuth=true` and fooling the middleware into passing the request. Once past the guard, the token creation handler applies no scope ceiling — it will create a new token with any requested scope regardless of the caller's scope. An attacker with a restricted token (e.g. `write:user` from a leaked CI secret) can therefore create a fully-privileged `all`-scoped token without knowing the account password.

### Data flow

#### Step 1 - Token extracted from Basic auth header
  
When the attacker sends Authorization: Basic base64(<token>:x-oauth-basic), parseAuthBasic detects that the password is "x-oauth-basic" and treats the username field as the token:

https://github.com/go-gitea/gitea/blob/9155a81b9daf1d46b2380aa91271e623ac947c1e/services/auth/basic.go#L55-L64

`VerifyAuthToken` then validates the token against the database and sets `LoginMethod = "access_token"` and `ApiTokenScope` to the token's actual scope (`write:user`):

https://github.com/go-gitea/gitea/blob/9155a81b9daf1d46b2380aa91271e623ac947c1e/services/auth/basic.go#L100-L106

#### Step 2 - `AuthedMethod` is set to `"basic"`, not `"access_token"`

`Basic.Verify()` returns the user successfully, so `group.Verify()` sets `AuthedMethod` to the method's name — `"basic"` — regardless of whether a password or token was used:

https://github.com/go-gitea/gitea/blob/9155a81b9daf1d46b2380aa91271e623ac947c1e/services/auth/group.go#L63-L65

#### Step 3 - `IsBasicAuth` is incorrectly set to true

`AuthShared` computes `IsBasicAuth` by comparing `AuthedMethod` against the constant `"basic"`. Since step 2 set that field to "basic" for a token-authenticated request, the flag is wrong:

https://github.com/go-gitea/gitea/blob/9155a81b9daf1d46b2380aa91271e623ac947c1e/routers/common/auth.go#L27

#### Step 4 - The guard is bypassed

`reqBasicOrRevProxyAuth` checks only `ctx.IsBasicAuth`. Because that flag is `true`, the middleware passes and the request reaches `CreateAccessToken`:

https://github.com/go-gitea/gitea/blob/9155a81b9daf1d46b2380aa91271e623ac947c1e/routers/api/v1/api

REFS:
- WEB https://github.com/go-gitea/gitea/security/advisories/GHSA-683j-3ff6-hh2x
- WEB https://github.com/go-gitea/gitea/pull/38406
- WEB https://github.com/go-gitea/gitea/pull/38426
- WEB https://github.com/go-gitea/gitea/commit/de4b8277e9cb576f2315fb03b5ab6478b42a1d31
- WEB https://github.com/go-gitea/gitea/commit/f69e15afe7496cc62e96dab244629c69eb31a7bf
- PACKAGE https://github.com/go-gitea/gitea
- WEB https://github.com/go-gitea/gitea/releases/tag/v1.27.0

INTRO_LOG:
0ba862cb9779a6c720f5031c4838427ddf90f86f
0xGREG <28388707+0xGREG@users.noreply.github.com>
2026-04-28T21:33:20+00:00
Add DEFAULT_TITLE_SOURCE setting for pull request title default behavior (#37465)

Adds a new `DEFAULT_TITLE_SOURCE` option under
`[repository.pull-request]` with three values:

- `first-commit` (default): uses the oldest commit summary, current
behavior since v1.26
- `auto`: normalizes branch name as title for multi-commit PRs (just
like GitHub), use commit summary for single-commit PRs

Closes: #37463
Co-authored-by: silverwind <me@silverwind.io>
Co-authored-by: Claude (Opus 4.7) <noreply@anthropic.com>
Co-authored-by: wxiaoguang <wxiaoguang@gmail.com>
Co-authored-by: Giteabot <teabot@gitea.io>
Co-authored-by: Nicolas <bircni@icloud.com>


INTRO_STAT:
 custom/conf/app.example.ini      |  5 +++
 modules/setting/repository.go    |  9 ++++++
 routers/web/repo/compare.go      | 45 ++++++++++++++++++++++++---
 routers/web/repo/compare_test.go | 66 +++++++++++++++++++++++++++++++---------
 4 files changed, 106 insertions(+), 19 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/custom/conf/app.example.ini b/custom/conf/app.example.ini
index 97af5fa5f..424595719 100644
--- a/custom/conf/app.example.ini
+++ b/custom/conf/app.example.ini
@@ -1169,6 +1169,11 @@ LEVEL = Info
 ;; Retarget child pull requests to the parent pull request branch target on merge of parent pull request. It only works on merged PRs where the head and base branch target the same repo.
 ;RETARGET_CHILDREN_ON_MERGE = true
 ;;
+;; Default source for the pull request title when opening a new PR.
+;; "first-commit" uses the oldest commit's summary.
+;; "auto" uses commit's summary if the PR only has one commit, normalizes the branch name if multiple commits.
+;DEFAULT_TITLE_SOURCE = first-commit
+;;
 ;; Delay mergeable check until page view or API access, for pull requests that have not been updated in the specified days when their base branches get updated.
 ;; Use "-1" to always check all pull requests (old behavior). Use "0" to always delay the checks.
 ;DELAY_CHECK_FOR_INACTIVE_DAYS = 7


FIX_LOG:
de4b8277e9cb576f2315fb03b5ab6478b42a1d31
Giteabot <teabot@gitea.io>
2026-07-12T17:41:58+00:00
fix: various security fixes (#38406) (#38426)

Backport #38406 by @bircni

Addresses a batch of privately reported security issues, grouped by
area:

- **SSRF** - migration PR-patch/asset fetches, OAuth2 avatar & OpenID
discovery, pull-mirror URL re-validation, and the outbound proxy path.
- **Access-token scope** - prevent scope escalation on token creation;
keep public-only tokens confined (feeds, packages, Actions listings,
star/watch lists, limited/private owners).
- **Access control / disclosure** - go-get default-branch leak, webhook
authorization-header leak, watch clearing on private transitions,
label/attachment scoping.
- **Denial of service** - input bounds for npm dist-tags, Debian control
files, Arch file lists, and SSH keys.

### 📌 Attention for site admins

Not breaking - existing configs keep working - but two changes are worth
a look:

- **New SSRF protection** Outbound requests (migrations, OAuth2 avatars,
OpenID discovery, pull mirrors, proxy path) are now validated against
the allow/block host lists. If your instance legitimately reaches
internal hosts, you may need to add them to
`[security].ALLOWED_HOST_LIST` (and the relevant `ALLOW_LOCALNETWORKS`
settings).
- **Deprecation** `[webhook].ALLOWED_HOST_LIST` is deprecated and will
be removed in a future release. Use `[security].ALLOWED_HOST_LIST`
instead; the old key still works for now.

Co-authored-by: bircni <bircni@icloud.com>
Co-authored-by: TheFox0x7 <thefox0x7@gmail.com>
Co-authored-by: techknowlogick <techknowlogick@gitea.io>
Co-authored-by: Lunny Xiao <xiaolunwen@gmail.com>
Co-authored-by: wxiaoguang <wxiaoguang@gmail.com>
Co-authored-by: Zettat123 <zettat123@gmail.com>


FIX_STAT:
 custom/conf/app.example.ini                      | 14 ++--
 models/actions/run_job_list.go                   |  7 ++
 models/actions/run_list.go                       |  7 ++
 models/asymkey/ssh_key_parse.go                  | 20 +++++-
 models/asymkey/ssh_key_test.go                   | 12 +++-
 models/auth/access_token_scope.go                | 30 +++++++++
 models/auth/access_token_scope_test.go           | 23 +++++++
 models/issues/comment.go                         |  7 ++
 models/issues/comment_test.go                    |  4 +-
 models/issues/issue_update.go                    | 32 +++++++++
 models/issues/issue_update_test.go               | 33 ++++++++++
 models/issues/label.go                           | 19 ++++--
 models/issues/label_test.go                      |  9 +--
 models/repo/repo_list.go                         | 48 ++++++++++++--
 models/repo/repo_list_test.go                    | 48 ++++++++++++++
 models/repo/user_repo.go                         | 10 ++-
 models/repo/user_repo_test.go                    | 37 +++++++++++
 modules/auth/openid/openid.go                    | 22 ++++++-
 modules/auth/openid/openid_test.go               | 29 ++++++++
 modules/hostmatcher/http.go                      | 16 +++++
 modules/packages/arch/metadata.go                | 14 +++-
 modules/packages/arch/metadata_test.go           | 25 +++++++
 modules/packages/debian/metadata.go              | 16 ++++-
 modules/packages/debian/metadata_test.go         | 12 ++++
 modules

FIX_DIFF_OVERLAP:
diff --git a/custom/conf/app.example.ini b/custom/conf/app.example.ini
index 2e3787cbb..7311742cf 100644
--- a/custom/conf/app.example.ini
+++ b/custom/conf/app.example.ini
@@ -536,6 +536,13 @@ INTERNAL_TOKEN =
 ;; Leave it empty to apply the default policy, or set it to "unset" to disable Content-Security-Policy.
 ;CONTENT_SECURITY_POLICY_GENERAL =
 
+;; Webhook and oauth2 clients can only call allowed hosts for security reasons. Comma separated list, eg: external, 192.168.1.0/24, *.mydomain.com
+;; Built-in: loopback (for localhost), private (for LAN/intranet), external (for public hosts on internet), * (for all hosts)
+;; CIDR list: 1.2.3.0/8, 2001:db8::/32
+;; Wildcard hosts: *.mydomain.com, 192.168.100.*
+;; This list is enforced on direct connections only. When an HTTP proxy is configured, restricting the proxied target is the proxy server's responsibility.
+;ALLOWED_HOST_LIST = external
+
 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 [camo]
@@ -1754,13 +1761,6 @@ LEVEL = Info
 ;; Deliver timeout in seconds
 ;DELIVER_TIMEOUT = 5
 ;;
-;; Webhook can only call allowed hosts for security reasons. Comma separated list, eg: external, 192.168.1.0/24, *.mydomain.com
-;; Built-in: loopback (for localhost), private (for LAN/intranet), external (for public hosts on internet), * (for all hosts)
-;; CIDR list: 1.2.3.0/8, 2001:db8::/32
-;; Wildcard hosts: *.mydomain.com, 192.168.100.*
-;; Since 1.15.7. Default to * for 1.15.x, external for 1.16 and later
-;ALLOWED_HOST_LIST = external
-;;
 ;; Allow insecure certification
 ;SKIP_TLS_VERIFY = false
 ;;


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []