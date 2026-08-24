# GHSA-C54G-XJWJ-8G82

repo: gohugoio/hugo

summary: Hugo: XSS via text/html content files

aliases: ['CVE-2026-50133']

severity: MODERATE

evidence: file_history blamed_lines=0 files=['config/security/securityConfig.go', 'config/security/securityConfig_test.go']

intro: 454450a647111e5e0b41af595b310f3062c5630e

intro_subject: config/security: Restrict default http.urls "@" deny to userinfo

intro_date: 2026-04-29T10:42:35+02:00

fix: e41a06447daa3071a01f333fdcec0a5153c3c8d1

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "github.com/gohugoio/hugo"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "0.162.0"
          }
        ]
      }
    ]
  }
]

DETAILS:
**Commit:** [e41a06447d](https://github.com/gohugoio/hugo/commit/e41a06447d) — _Disallow HTML content by default_
**Affected versions:** all Hugo versions prior to v0.162.0.
**Fixed in:** v0.162.0.
**Severity:** Low to Medium, depending on threat model. Not an issue if you fully trust every file under `/content` and every content adapter you load.

**Description.** Hugo accepts content files in several markup formats. Files mapped to the `text/html` media type (typically `.html` files under `/content`, or pages produced by a content adapter that sets `content.mediaType = "text/html"`) had their body emitted verbatim into the rendered page. A site that ingests HTML content from an untrusted source — for example, a CMS-backed editor, a content adapter pulling from an external API, or an automated import pipeline — could therefore be served stored cross-site scripting.

**Mitigation.** v0.162.0 introduces a `security.allowContent` whitelist with `text/html` denied by default. Sites that intentionally author HTML content can opt back in:

```toml
[security]
allowContent = ['.*']
```

This only affects pages whose source file (or content adapter output) declares an HTML media type; Markdown, AsciiDoc, Org, Pandoc and reStructuredText content is unaffected.

REFS:
- WEB https://github.com/gohugoio/hugo/security/advisories/GHSA-c54g-xjwj-8g82
- WEB https://github.com/gohugoio/hugo/commit/e41a06447daa3071a01f333fdcec0a5153c3c8d1
- PACKAGE https://github.com/gohugoio/hugo
- WEB https://github.com/gohugoio/hugo/releases/tag/v0.162.0

INTRO_LOG:
454450a647111e5e0b41af595b310f3062c5630e
Bjørn Erik Pedersen <bjorn.erik.pedersen@gmail.com>
2026-04-29T13:50:37+02:00
config/security: Restrict default http.urls "@" deny to userinfo

The previous "! @" deny rule rejected any URL containing "@",
including legitimate version-pinned imports such as
https://cdn.jsdelivr.net/npm/mermaid@latest/dist/mermaid.esm.min.mjs.
Tighten it to "! (?i)^https?://[^/?#]*@" so only "@" inside the
authority section (i.e. real userinfo) is blocked.

Fixes #14825

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>



INTRO_STAT:
 config/security/securityConfig.go      |  2 +-
 config/security/securityConfig_test.go | 28 +++++++++++++++++++++++++++-
 2 files changed, 28 insertions(+), 2 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/config/security/securityConfig.go b/config/security/securityConfig.go
index 3ba397f6..e9590066 100644
--- a/config/security/securityConfig.go
+++ b/config/security/securityConfig.go
@@ -59,7 +59,7 @@ var DefaultConfig = Config{
 		URLs: MustNewWhitelist(
 			`(?i)^https?://[a-z]`,
 			`! (?i)localhost`,
-			`! @`,
+			`! (?i)^https?://[^/?#]*@`,
 		),
 		Methods: MustNewWhitelist("(?i)GET|POST"),
 	},
diff --git a/config/security/securityConfig_test.go b/config/security/securityConfig_test.go
index 4b5a1241..8b4223e5 100644
--- a/config/security/securityConfig_test.go
+++ b/config/security/securityConfig_test.go
@@ -135,7 +135,7 @@ func TestToTOML(t *testing.T) {
 	got := DefaultConfig.ToTOML()
 
 	c.Assert(got, qt.Equals,
-		"[security]\n  enableInlineShortcodes = false\n\n  [security.exec]\n    allow = ['^(dart-)?sass(-embedded)?$', '^go$', '^git$', '^node$', '^postcss$', '^tailwindcss$']\n    osEnv = ['(?i)^((HTTPS?|NO)_PROXY|PATH(EXT)?|APPDATA|TE?MP|TERM|GO\\w+|(XDG_CONFIG_)?HOME|USERPROFILE|SSH_AUTH_SOCK|DISPLAY|LANG|SYSTEMDRIVE|PROGRAMDATA)$']\n\n  [security.funcs]\n    getenv = ['^HUGO_', '^CI$']\n\n  [security.http]\n    methods = ['(?i)GET|POST']\n    urls = ['(?i)^https?://[a-z]', '! (?i)localhost', '! @']\n\n  [security.node]\n    [security.node.permissions]\n      allowAddons = ['tailwindcss']\n      allowRead = ['.']\n      allowWorker = ['tailwindcss']\n      allowWrite = []\n      disable = false",
+		"[security]\n  enableInlineShortcodes = false\n\n  [security.exec]\n    allow = ['^(dart-)?sass(-embedded)?$', '^go$', '^git$', '^node$', '^postcss$', '^tailwindcss$']\n    osEnv = ['(?i)^((HTTPS?|NO)_PROXY|PATH(EXT)?|APPDATA|TE?MP|TERM|GO\\w+|(XDG_CONFIG_)?HOME|USERPROFILE|SSH_AUTH_SOCK|DISPLAY|LANG|SYSTEMDRIVE|PROGRAMDATA)$']\n\n  [security.funcs]\n    getenv = ['^HUGO_', '^CI$']\n\n  [security.http]\n    methods = ['(?i)GET|POST']\n    urls = ['(?i)^https?://[a-z]', '! (?i)localhost', '! (?i)^https?://[^/?#]*@']\n\n  [security.node]\n    [security.node.permissions]\n      allowAddons = ['tailwindcss']\n      allowRead = ['.']\n      allowWorker = ['tailwindcss']\n      allowWrite = []\n      disable = false",
 	)
 }
 
@@ -247,6 +247,32 @@ urls = ['.*', '! ^https?://evil\.example\.com']
 	})
 }
 
+func TestCheckAllowedHTTPURLAtInPathIssue14825(t *testing.T) {
+	t.Parallel()
+	c := qt.New(t)
+
+	pc, err := DecodeConfig(config.New())
+	c.Assert(err, qt.IsNil)
+
+	for _, u := range []string{
+		"https://cdn.jsdelivr.net/npm/mermaid@latest/dist/mermaid.esm.min.mjs",
+		"https://unpkg.com/react@18/umd/react.production.min.js",
+		"https://example.org/foo@bar/baz",
+	} {
+		c.Assert(pc.CheckAllowedHTTPURL(u), qt.IsNil, qt.Commentf(u))
+	}
+
+	for _, u := range []string{
+		"http://user@127.0.0.1/",
+		"http://user:pass@example.org/",
+		"https://token@example.org/foo@bar",
+	} {
+		err := pc.CheckAllowedHTTPURL(u)
+		c.Assert(err, qt.IsNotNil, qt.Commentf(u))
+		c.Assert(err, qt.ErrorMatches, `(?s).*is not whitelisted in policy "security\.http\.urls".*`, qt.Commentf(u))
+	}
+}
+
 func TestDecodeConfigNodePermissions(t *testing.T) {
 	c := qt.New(t)
 


FIX_LOG:
e41a06447daa3071a01f333fdcec0a5153c3c8d1
Bjørn Erik Pedersen <bjorn.erik.pedersen@gmail.com>
2026-05-26T13:57:12+02:00
Disallow HTML content by default

For security reasons. Enable in security config, e.g.:

```toml
[security]
allowContent = ['.*']
```



FIX_STAT:
 config/security/securityConfig.go                  | 22 +++++++
 config/security/securityConfig_test.go             | 44 +++++++++++++-
 hugolib/page.go                                    |  3 +-
 hugolib/page__meta.go                              | 11 ++++
 hugolib/page_test.go                               |  2 +
 hugolib/pagebundler_test.go                        |  6 ++
 .../pagesfromgotmpl_integration_test.go            |  4 ++
 hugolib/rendershortcodes_test.go                   |  2 +
 hugolib/securitypolicies_test.go                   | 68 ++++++++++++++++++++++
 9 files changed, 160 insertions(+), 2 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/config/security/securityConfig.go b/config/security/securityConfig.go
index 3ecc67fc..9818fd13 100644
--- a/config/security/securityConfig.go
+++ b/config/security/securityConfig.go
@@ -74,6 +74,11 @@ var DefaultConfig = Config{
 			AllowChildProcess: []string{"tailwindcss"}, // detect-libc spawns getconf on some Linux setups.
 		},
 	},
+	// Content under /content is treated as untrusted. text/html bodies are
+	// emitted verbatim and are an XSS sink, so they are denied by default.
+	// Everything else is allowed because Whitelist treats a deny-only list as
+	// "allow anything not denied".
+	AllowContent: MustNewWhitelist("! ^text/html$"),
 }
 
 // Config is the top level security config.
@@ -92,6 +97,12 @@ type Config struct {
 	// Node holds Node.js security settings.
 	Node Node `json:"node"`
 
+	// AllowContent restricts which content media types may be used for
+	// pages under /content. Matched against the full MIME type (e.g.
+	// "text/html"). text/html is denied by default because Hugo emits the
+	// body verbatim.
+	AllowContent Whitelist `json:"allowContent"`
+
 	// Allow inline shortcodes
 	EnableInlineShortcodes bool `json:"enableInlineShortcodes"`
 }
@@ -200,6 +211,17 @@ func (c Config) CheckAllowedHTTPMethod(method string) error {
 	return nil
 }
 
+func (c Config) CheckAllowedContent(mediaType string) error {
+	if !c.AllowContent.Accept(mediaType) {
+		return &AccessDeniedError{
+			name:     mediaType,
+			path:     "security.allowContent",
+			policies: c.ToTOML(),
+		}
+	}
+	return nil
+}
+
 // ToSecurityMap converts c to a map with 'security' as the root key.
 func (c Config) ToSecurityMap() map[string]any {
 	// Take it to JSON and back to get proper casing etc.
diff --git a/config/security/securityConfig_test.go b/config/security/securityConfig_test.go
index da82b0c4..37ecaab6 100644
--- a/config/security/securityConfig_test.go
+++ b/config/security/securityConfig_test.go
@@ -135,7 +135,7 @@ func TestToTOML(t *testing.T) {
 	got := DefaultConfig.ToTOML()
 
 	c.Assert(got, qt.Equals,
-		"[security]\n  enableInlineShortcodes = false\n\n  [security.exec]\n    allow = ['^(dart-)?sass(-embedded)?$', '^go$', '^git$', '^node$', '^postcss$', '^tailwindcss$']\n    osEnv = ['(?i)^((HTTPS?|NO)_PROXY|PATH(EXT)?|APPDATA|TE?MP|TERM|GO\\w+|(XDG_CONFIG_)?HOME|USERPROFILE|SSH_AUTH_SOCK|DISPLAY|LANG|SYSTEMDRIVE|PROGRAMDATA)$']\n\n  [security.funcs]\n    getenv = ['^HUGO_', '^CI$']\n\n  [security.http]\n    methods = ['(?i)GET|POST']\n    urls = ['(?i)^https?://[a-z0-9]', '! ^https?://\\d+\\.', '! (?i)localhost', '! (?i)^https?://[^/?#]*@']\n\n  [security.node]\n    [security.node.permissions]\n      allowAddons = ['tailwindcss']\n      allowChildProcess = ['tailwindcss']\n      allowRead = ['.']\n      allowWorker = ['tailwindcss']\n      allowWrite = []\n      disable = false",
+		"[security]\n  allowContent = ['! ^text/html$']\n  enableInlineShortcodes = false\n\n  [security.exec]\n    allow = ['^(dart-)?sass(-embedded)?$', '^go$', '^git$', '^node$', '^postcss$', '^tailwindcss$']\n    osEnv = ['(?i)^((HTTPS?|NO)_PROXY|PATH(EXT)?|APPDATA|TE?MP|TERM|GO\\w+|(XDG_CONFIG_)?HOME|USERPROFILE|SSH_AUTH_SOCK|DISPLAY|LANG|SYSTEMDRIVE|PROGRAMDATA)$']\n\n  [security.funcs]\n    getenv = ['^HUGO_', '^CI$']\n\n  [security.http]\n    methods = ['(?i)GET|POST']\n    urls = ['(?i)^https?://[a-z0-9]', '! ^https?://\\d+\\.', '! (?i)localhost', '! (?i)^https?://[^/?#]*@']\n\n  [security.node]\n    [security.node.permissions]\n      allowAddons = ['tailwindcss']\n      allowChildProcess = ['tailwindcss']\n      allowRead = ['.']\n      allowWorker = ['tailwindcss']\n      allowWrite = []\n      disable = false",
 	)
 }
 
@@ -298,6 +298,48 @@ func TestCheckAllowedHTTPURLDigitHostnameIssue14837(t *testing.T) {
 	}
 }
 
+func TestCheckAllowedContent(t *testing.T) {
+	t.Parallel()
+	c := qt.New(t)
+
+	c.Run("text/html denied by default", func(c *qt.C) {
+		c.Parallel()
+		pc, err := DecodeConfig(config.New())
+		c.Assert(err, qt.Is

intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []