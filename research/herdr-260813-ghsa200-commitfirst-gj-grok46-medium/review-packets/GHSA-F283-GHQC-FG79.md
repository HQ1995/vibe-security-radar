# GHSA-F283-GHQC-FG79

repo: guzzle/guzzle

summary: Guzzle: Unbounded response cookies risk denial of service

aliases: ['CVE-2026-67353']

severity: MODERATE

evidence: file_history blamed_lines=0 files=['docs/quickstart.md', 'docs/request-options.md']

intro: 6e4dc82771ff4981153af4bb061f47af16c31f4d

intro_subject: Support QUERY redirects (#3702)

intro_date: 2026-06-24T23:54:14+01:00

fix: 7b68220d6543f6f80fe62e633361fc9d4ead14d4

affected: [
  {
    "package": {
      "ecosystem": "Packagist",
      "name": "guzzlehttp/guzzle"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "7.15.1"
          }
        ]
      }
    ]
  }
]

DETAILS:
### Impact

In affected versions, Guzzle's built-in `CookieJar` accepts any number of `Set-Cookie` header fields from one response, with no limit on the size of each field. When a later request matches the stored cookies, Guzzle places every match into one generated `Cookie` header without limiting the number of cookies or the total header length.

A malicious or compromised server can therefore return many large cookies, causing Guzzle to store attacker-controlled data in memory and copy it into later request headers. This can increase memory use and processing time. It can also make later requests fail when the generated header exceeds a limit in a handler, HTTP implementation, proxy, or destination server. A server on one sibling host, such as `attacker.example.com`, can also set parent-domain cookies that are later selected for another sibling, such as `service.example.com`. The denial can therefore affect a different service that uses the same jar.

An application is affected when it enables the built-in cookie support, receives an attacker-controlled response, and retains or reuses the jar. The issue affects both built-in handlers because Guzzle manages these cookies itself instead of using libcurl's native cookie engine. cURL addressed a similar denial-of-service issue in CVE-2022-32205 by limiting the cookies it accepts and sends, but those native limits do not protect Guzzle's separate jar. Applications that do not use cookies, use separate jars for untrusted origins, or use a third-party `CookieJarInterface` with suitable limits are not affected by this behavior. The demonstrated direct impact is limited to availability. The patch does not impose a lifetime limit on a jar built up over an unlimited number of responses or populated directly by application code.

### Patches

The issue is patched in `7.15.1` and later. Starting in that release, the built-in `CookieJar` ignores a `Set-Cookie` field value longer than 8,190 bytes and applies at most 50 successful cookie insertions or replacements from one response. When generating a request, it emits at most 150 matching `name=value` pairs and limits the complete `Cookie: ` header line to 8,190 bytes, including the field name and following space.

These limits follow the same practical shape as cURL's response to CVE-2022-32205. Both bound cookies accepted from one response, cookies added to one request, and generated header size. Guzzle's 8,190-byte incoming field limit is more generous than cURL's c

REFS:
- WEB https://github.com/guzzle/guzzle/security/advisories/GHSA-f283-ghqc-fg79
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-67353
- WEB https://github.com/guzzle/guzzle/pull/3901
- WEB https://github.com/guzzle/guzzle/commit/7b68220d6543f6f80fe62e633361fc9d4ead14d4
- PACKAGE https://github.com/guzzle/guzzle
- WEB https://github.com/guzzle/guzzle/releases/tag/7.15.1
- WEB https://www.vulncheck.com/advisories/guzzlehttp-guzzle-before-unbounded-cookie-denial-of-service

INTRO_LOG:
6e4dc82771ff4981153af4bb061f47af16c31f4d
Graham Campbell <GrahamCampbell@users.noreply.github.com>
2026-06-24T23:54:14+01:00
Support QUERY redirects (#3702)

Co-authored-by: codexofc <55830974+codexofc@users.noreply.github.com>


INTRO_STAT:
 CHANGELOG.md                     |   1 +
 docs/quickstart.md               |   2 +-
 docs/request-options.md          |   5 +-
 src/RedirectMiddleware.php       |   7 +-
 src/RequestOptions.php           |   4 +-
 tests/RedirectMiddlewareTest.php | 171 +++++++++++++++++++++++++++++++++++++++
 6 files changed, 184 insertions(+), 6 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/docs/quickstart.md b/docs/quickstart.md
index 9033d462..2692183c 100644
--- a/docs/quickstart.md
+++ b/docs/quickstart.md
@@ -436,7 +436,7 @@ Guzzle will automatically follow redirects unless you tell it not to. You can cu
 
 - Set to `true` to enable normal redirects with a maximum number of 5 redirects. This is the default setting.
 - Set to `false` to disable redirects.
-- Pass an associative array containing the 'max' key to specify the maximum number of redirects and optionally provide a 'strict' key value to specify whether or not to use strict RFC compliant redirects (meaning redirect POST requests with POST requests vs. doing what most browsers do which is redirect POST requests with GET requests).
+- Pass an associative array containing the 'max' key to specify the maximum number of redirects and optionally provide a 'strict' key value to specify whether or not to use strict RFC compliant redirects (meaning redirect POST requests with POST requests vs. doing what most browsers do which is redirect POST requests with GET requests). The QUERY method keeps its method and body across non-strict 301 and 302 redirects, and a 303 redirect is followed with GET.
 
 See the [`allow_redirects` option](request-options.md#allow_redirects) for cross-origin redirect credential behavior.
 
diff --git a/docs/request-options.md b/docs/request-options.md
index 1bca0562..bf27c4c2 100644
--- a/docs/request-options.md
+++ b/docs/request-options.md
@@ -52,7 +52,7 @@ You can also pass an associative array containing the following key value pairs:
 
 - max: (int, default=5) maximum number of allowed redirects.
 
-- strict: (bool, default=false) Set to true to use strict redirects. Strict RFC compliant redirects mean that POST redirect requests are sent as POST requests vs. doing what most browsers do which is redirect POST requests with GET requests.
+- strict: (bool, default=false) Set to true to use strict redirects. Strict RFC compliant redirects mean that POST redirect requests are sent as POST requests vs. doing what most browsers do which is redirect POST requests with GET requests. The RFC 10008 QUERY method keeps its method and body across non-strict 301 and 302 redirects, matching the 307 and 308 behavior that already applies to every method, and a 303 redirect is followed with a body-less GET.
 
 - referer: (bool, default=false) Set to true to enable adding the Referer header when redirecting.
 
@@ -115,6 +115,9 @@ Guzzle does not automatically remove other request options or headers solely bec
 
 If TLS client credentials are only trusted for the original origin, disable automatic redirects and handle redirect responses manually, or use separate clients and request options for trusted origins.
 
+> [!NOTE]
+> QUERY request bodies can carry sensitive query content. On cross-origin redirects Guzzle removes origin credentials such as the Authorization and Cookie headers, but it does not remove the request body. Disable automatic redirects or use on_redirect if a QUERY body must not be sent to another origin.
+
 ## auth
 
 Summary


FIX_LOG:
7b68220d6543f6f80fe62e633361fc9d4ead14d4
Graham Campbell <GrahamCampbell@users.noreply.github.com>
2026-07-18T12:22:33+01:00
Security fixes 7.15 (#3901)

* Exclude fragments from generated Referer headers

* Preserve host-only cookie scope

* Bound cookie admission and output

* Preserve equivalent-domain cookie deletion

* Add security advisory identifiers

* Update phpstan-baseline.neon


FIX_STAT:
 CHANGELOG.md                          |   9 ++
 docs/quickstart.md                    |   4 +
 docs/request-options.md               |   2 +-
 phpstan-baseline.neon                 |   6 --
 src/Cookie/CookieJar.php              |  72 +++++++++++++--
 src/Cookie/FileCookieJar.php          |  15 +++-
 src/Cookie/SessionCookieJar.php       |  13 ++-
 src/Cookie/SetCookie.php              |  52 ++++++++++-
 src/RedirectMiddleware.php            |   2 +-
 tests/Cookie/CookieJarTest.php        | 159 ++++++++++++++++++++++++++++++++++
 tests/Cookie/FileCookieJarTest.php    |  54 ++++++++++++
 tests/Cookie/SessionCookieJarTest.php |  24 +++++
 tests/Cookie/SetCookieTest.php        |  31 +++++++
 tests/RedirectMiddlewareTest.php      |   4 +-
 14 files changed, 421 insertions(+), 26 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/docs/quickstart.md b/docs/quickstart.md
index 9166fb84..4389e275 100644
--- a/docs/quickstart.md
+++ b/docs/quickstart.md
@@ -404,6 +404,10 @@ Different implementations exist for the `GuzzleHttp\Cookie\CookieJarInterface` :
 - The `GuzzleHttp\Cookie\FileCookieJar` class persists non-session cookies using a JSON formatted file.
 - The `GuzzleHttp\Cookie\SessionCookieJar` class persists cookies in the client session.
 
+The built-in persistent jars store an explicit boolean `HostOnly` marker for every cookie record. Nonempty data created by older versions without this marker is rejected and should be deleted, rotated, or annotated only when the cookie's original `Domain` semantics are known.
+
+The built-in `CookieJar` admits at most 50 cookies from one response and ignores any `Set-Cookie` field value longer than 8,190 bytes. A generated `Cookie` header contains at most 150 stored cookies, and its canonical line including `Cookie: ` is limited to 8,190 bytes. Later cookies are omitted after either output limit is reached.
+
 You can manually set cookies into a cookie jar with the named constructor `fromArray(array $cookies, $domain)`.
 
 ```php
diff --git a/docs/request-options.md b/docs/request-options.md
index 2c9ebf92..d78aee8e 100644
--- a/docs/request-options.md
+++ b/docs/request-options.md
@@ -54,7 +54,7 @@ You can also pass an associative array containing the following key value pairs:
 
 - strict: (bool, default=false) Set to true to use strict redirects. Strict RFC compliant redirects mean that POST redirect requests are sent as POST requests vs. doing what most browsers do which is redirect POST requests with GET requests. The RFC 10008 QUERY method keeps its method and body across non-strict 301 and 302 redirects, matching the 307 and 308 behavior that already applies to every method, and a 303 redirect is followed with a body-less GET. When redirect handling clears the body, it also removes `Content-Length` and `Transfer-Encoding`.
 
-- referer: (bool, default=false) Set to true to enable adding the Referer header when redirecting.
+- referer: (bool, default=false) Set to true to enable adding the Referer header when redirecting. Generated values exclude user information and fragments, and the header is omitted when the scheme changes.
 
 - protocols: (non-empty array of strings, default=`['http', 'https']`) Specifies which protocols are allowed for redirect requests. Redirect matching is case-sensitive; use `http` and `https`.
 


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []