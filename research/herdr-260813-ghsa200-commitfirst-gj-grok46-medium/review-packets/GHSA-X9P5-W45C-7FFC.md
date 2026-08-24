# GHSA-X9P5-W45C-7FFC

repo: gogs/gogs

summary: Gogs: Access tokens get exposed through URL params in API requests

aliases: ['CVE-2026-26196']

severity: MODERATE

evidence: blame blamed_lines=2 files=['.claude/commands/ghsa.md']

intro: ac21150a53bef3a3061f4da787ab193a8d68ecfc

intro_subject: template: escape untrusted names in locale strings piped through Safe (#8176)

intro_date: 2026-02-12T21:42:23-05:00

fix: 295bfba72993c372e7b338438947d8e1a6bed8fd

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
            "last_affected": "0.13.3"
          }
        ]
      }
    ]
  }
]

DETAILS:
### Summary

The Gogs API still accepts tokens in URL parameters such as `token` and `access_token`, which can leak through logs, browser history, and referrers.

### Details

A static review shows that the API still checks tokens in the URL query before looking at headers:

  - internal/context/auth.go reads `c.Query("token")`
  - internal/context/auth.go falls back to `c.Query("access_token")`
  - internal/context/auth.go only checks the `Authorization` header when the query token is empty
  - internal/context/auth.go authenticates using that token and marks the request as token-authenticated

Token-authenticated requests are accepted by API routes through `c.IsTokenAuth` checks:
  - internal/route/api/v1/api.go

### Impact

If tokens are sent in URLs such as `/api/v1/user?token=...`, they can leak in logs, browser or shell history, and referrer headers, and can be reused until revoked.

### Recommended Fix

- Authentication headers should be used exclusively for token transmission.
- Token parameters should be blocked at the proxy or WAF level.
- Query strings should be scrubbed from logs.
- A strict referrer policy should be set.

### Remediation

A fix is available at https://github.com/gogs/gogs/releases/tag/v0.14.2.

REFS:
- WEB https://github.com/gogs/gogs/security/advisories/GHSA-x9p5-w45c-7ffc
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-26196
- WEB https://github.com/gogs/gogs/pull/8177
- WEB https://github.com/gogs/gogs/commit/295bfba72993c372e7b338438947d8e1a6bed8fd
- PACKAGE https://github.com/gogs/gogs
- WEB https://github.com/gogs/gogs/releases/tag/v0.14.2

INTRO_LOG:
ac21150a53bef3a3061f4da787ab193a8d68ecfc
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-02-12T21:42:23-05:00
template: escape untrusted names in locale strings piped through Safe (#8176)

Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>


INTRO_STAT:
 .claude/commands/ghsa.md              | 11 +++++++++++
 templates/repo/branches/all.tmpl      |  2 +-
 templates/repo/branches/overview.tmpl |  6 +++---
 templates/repo/wiki/view.tmpl         |  2 +-
 4 files changed, 16 insertions(+), 5 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/.claude/commands/ghsa.md b/.claude/commands/ghsa.md
new file mode 100644
index 00000000..71b848c6
--- /dev/null
+++ b/.claude/commands/ghsa.md
@@ -0,0 +1,11 @@
+Analyze and help fix the GitHub Security Advisory (GHSA) at: $ARGUMENTS
+
+Steps:
+1. Fetch the GHSA page using `gh api repos/gogs/gogs/security-advisories` and understand the vulnerability details (description, severity, affected versions, CWE).
+2. Verify the reported vulnerability actually exists, and why.
+3. Identify the affected code in this repository.
+4. Propose a fix with a clear explanation of the root cause and how the fix addresses it. Check for prior art in the codebase to stay consistent with existing patterns.
+5. Implement the fix. Only add tests when there is something meaningful to test at our layer.
+6. Run all the usual build and test commands.
+7. Create a branch named after the GHSA ID, commit, and push.
+8. Create a pull request with a proper title and description, do not reveal too much detail and link the GHSA.


FIX_LOG:
295bfba72993c372e7b338438947d8e1a6bed8fd
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-02-13T15:27:48-05:00
context: reject access tokens passed via URL query parameters (#8177)




FIX_STAT:
 .claude/commands/ghsa.md            |  6 ++++--
 CHANGELOG.md                        |  1 +
 docs/api-reference/introduction.mdx | 14 +-------------
 docs/api-reference/openapi.json     |  6 ------
 internal/context/auth.go            | 18 ++++++------------
 5 files changed, 12 insertions(+), 33 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/.claude/commands/ghsa.md b/.claude/commands/ghsa.md
index 71b848c6..2c575628 100644
--- a/.claude/commands/ghsa.md
+++ b/.claude/commands/ghsa.md
@@ -7,5 +7,7 @@ Steps:
 4. Propose a fix with a clear explanation of the root cause and how the fix addresses it. Check for prior art in the codebase to stay consistent with existing patterns.
 5. Implement the fix. Only add tests when there is something meaningful to test at our layer.
 6. Run all the usual build and test commands.
-7. Create a branch named after the GHSA ID, commit, and push.
-8. Create a pull request with a proper title and description, do not reveal too much detail and link the GHSA.
+7. If a changelog entry is warranted (user will specify), add it to CHANGELOG.md with a placeholder for the PR link.
+8. Create a branch named after the GHSA ID, commit, and push.
+9. Create a pull request with a proper title and description, do not reveal too much detail and link the GHSA.
+10. If a changelog entry was added, update it with the PR link, then commit and push again.


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []