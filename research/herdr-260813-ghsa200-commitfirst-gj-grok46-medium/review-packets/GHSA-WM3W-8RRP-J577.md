# GHSA-WM3W-8RRP-J577

repo: guzzle/guzzle

summary: Guzzle: Host-only cookie scope is not preserved

aliases: ['CVE-2026-67355']

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

In affected versions, `CookieJar` does not preserve whether a response cookie was set without a `Domain` attribute or with an empty one. A cookie without `Domain` is host-only and must be returned only to the exact host that set it. Under current cookie processing rules, an empty `Domain` value is also host-only. Guzzle instead stores the request host in the cookie's `Domain` field and later applies ordinary domain matching, as though the server had supplied a valid domain. For example, a host-only `sid=secret` cookie set by `example.com` can subsequently be sent to `child.example.com`. `FileCookieJar` and `SessionCookieJar` also persist the request host without recording the host-only state, so reloading a jar preserves the widened scope.

An attacker who controls or can observe a child host can therefore receive cookies that were intended only for its parent host. Depending on the cookie, this can disclose session identifiers, authorization tokens, or other sensitive state. Exploitation requires the application to enable Guzzle's cookie support, reuse the same built-in cookie jar, receive a host-only cookie from a parent host, and later make a matching request to a less-trusted child host. The cookie's other restrictions still apply. Its path must match, a `Secure` cookie is sent only over a secure connection, and an expired cookie is not sent.

Applications that do not use Guzzle's cookie support are not affected. Applications are also not affected by this disclosure if they use a separate jar for every host or trust boundary, never request a less-trusted subdomain with the same jar, or only store cookies carrying a valid, non-empty `Domain` attribute. The incorrect behavior occurs between an otherwise valid parent host and its subdomains.

### Patches

The issue is patched in `7.15.1` and later. Starting in that release, Guzzle records whether a response cookie is host-only and matches it only against the exact host. The host-only flag is part of cookie identity for replacement and response-driven deletion. Cookies carrying a valid, non-empty `Domain` attribute retain their existing domain-matching behavior. A host-only cookie can coexist with an explicit-domain cookie having the same name, domain string, and path.

The built-in persistent jars now write a boolean `HostOnly` marker for every stored cookie record. They reject records where that marker is missing or is not a boolean, and validate all records before changing the live jar. Pers

REFS:
- WEB https://github.com/guzzle/guzzle/security/advisories/GHSA-wm3w-8rrp-j577
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-67355
- WEB https://github.com/guzzle/guzzle/pull/3901
- WEB https://github.com/guzzle/guzzle/commit/7b68220d6543f6f80fe62e633361fc9d4ead14d4
- PACKAGE https://github.com/guzzle/guzzle
- WEB https://github.com/guzzle/guzzle/releases/tag/7.15.1
- WEB https://www.vulncheck.com/advisories/guzzlehttp-guzzle-before-host-only-cookie-scope

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