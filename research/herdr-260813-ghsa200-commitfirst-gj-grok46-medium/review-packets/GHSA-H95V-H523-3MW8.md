# GHSA-H95V-H523-3MW8

repo: guzzle/guzzle

summary: Guzzle: URI fragments disclosed in redirect Referer headers

aliases: ['CVE-2026-67354']

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

When the optional `referer` redirect setting is enabled, affected versions of `RedirectMiddleware` can copy the fragment from the referring request URI into a generated `Referer` header. A URI fragment is the part after `#`. It is handled locally by the client and is not part of the HTTP request target, so the server handling the original request does not receive it. A generated `Referer` tells the redirect destination which URI led to the request. Guzzle correctly removes user information from that value, but retains the fragment when it follows a redirect to the same scheme, such as HTTPS to HTTPS. For example, an initial URI ending in `#secret` is sent without the fragment, but the redirect destination can receive a `Referer` ending in `#secret`. This behavior affects both the cURL and stream handlers.

An attacker who controls the redirect destination can read the fragment from the incoming header, including through request logs or application code. If the fragment contains a one-time login secret, access token, state value, or other private client data, it is disclosed to a server that was never meant to receive it. Exploitation requires the application to enable `allow_redirects.referer`, make a request to a URI with a sensitive fragment, and follow a same-scheme redirect to a less-trusted destination.

The `referer` setting is disabled by default. Applications that leave it disabled, do not put sensitive data in URI fragments, do not follow redirects, or only redirect within the same trust boundary are not affected. Guzzle already omits the generated header when the scheme changes. This issue is limited to the fragment's inclusion. Reducing the path and query on cross-origin redirects is a separate privacy policy question.

### Patches

The issue is patched in `7.15.1` and later. Starting in that release, Guzzle removes both user information and the fragment before generating a redirect `Referer` value. Other redirect behavior does not change. Guzzle retains the referring path and query, and continues to omit the header when the scheme changes. Versions before `7.15.1` are affected when the optional `referer` setting is enabled.

### Workarounds

If you cannot upgrade immediately, leave automatic Referer generation disabled. It is off by default. If redirect options are configured explicitly, ensure that `referer` is `false`:

```php
$client->request('GET', $uri, [
    'allow_redirects' => ['referer' => false],
]);
```

Alternatively, di

REFS:
- WEB https://github.com/guzzle/guzzle/security/advisories/GHSA-h95v-h523-3mw8
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-67354
- WEB https://github.com/guzzle/guzzle/pull/3901
- WEB https://github.com/guzzle/guzzle/commit/7b68220d6543f6f80fe62e633361fc9d4ead14d4
- PACKAGE https://github.com/guzzle/guzzle
- WEB https://github.com/guzzle/guzzle/releases/tag/7.15.1
- WEB https://www.vulncheck.com/advisories/guzzlehttp-guzzle-before-uri-fragment-disclosure-via-referer

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