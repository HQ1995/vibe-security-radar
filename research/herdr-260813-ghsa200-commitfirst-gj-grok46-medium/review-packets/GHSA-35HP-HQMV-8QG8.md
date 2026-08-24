# GHSA-35HP-HQMV-8QG8

repo: gofiber/fiber

summary: Fiber's cache middleware default key generator ignores query string, causing response mix-up across distinct query parameters

aliases: ['CVE-2026-30246']

severity: MODERATE

evidence: blame blamed_lines=1 files=['middleware/cache/cache.go']

intro: 27d359e8d0d33738e15cbf0d74e6a0be3501aea4

intro_subject: 🐛 bug: address cache middleware review feedback

intro_date: 2026-04-21T02:00:48+00:00

fix: 9a0d12c07ed895b84c72987f9288b04137afe5de

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "github.com/gofiber/fiber/v3"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "3.2.0"
          }
        ]
      }
    ],
    "database_specific": {
      "last_known_affected_version_range": "<= 3.1.0"
    }
  }
]

DETAILS:
### Summary
Fiber cache middleware's default key generator uses only `c.Path()` and does not include the query string.
As a result, requests like `/?id=1` and `/?id=2` can map to the same cache key and share the same cached response.

This can cause response mix-up (cache poisoning-like behavior) for endpoints where response content depends on query parameters.

### Details
Default configuration in cache middleware:

- `KeyGenerator: func(c fiber.Ctx) string { return utils.CopyString(c.Path()) }`

References:
- https://github.com/gofiber/fiber/blob/main/middleware/cache/config.go#L90-L92
- https://github.com/gofiber/fiber/blob/main/middleware/cache/cache_test.go#L599-L621

The existing test demonstrates that when handler output depends on query parameter `id`, a second request with a different query still returns the first cached response (cache hit), confirming query is not part of the default cache key.

### PoC
Minimal PoC:

```go
package main

import (
    "log"

    "github.com/gofiber/fiber/v3"
    "github.com/gofiber/fiber/v3/middleware/cache"
)

func main() {
    app := fiber.New()
    app.Use(cache.New()) // default config

    app.Get("/", func(c fiber.Ctx) error {
        return c.SendString(c.Query("id", "1"))
    })

    log.Fatal(app.Listen(":3000"))
}
```

Reproduction:

1. `GET /?id=1`
   - Cache miss
   - Response body: `1`
2. `GET /?id=2`
   - Cache hit
   - Response body: `1` (expected `2`)

Local verification command used:

```bash
go test ./middleware/cache -run Test_Cache_WithNoCacheRequestDirective -count=1
```

Observed result: test passes, confirming this is current behavior.

### Impact
- Responses that should vary by query parameters can be mixed between requests.
- In real deployments, this may leak or corrupt user/tenant-specific content if query parameters influence context or data selection.
- This is deployment-dependent but security-relevant, and not safe-by-default for query-variant responses.

### Suggested remediation
- Change default cache key generation to include path + normalized query string (or canonicalized original URL).
- Keep ability for custom key generators.
- Add explicit documentation warning that path-only keying is unsafe for query-dependent responses.

REFS:
- WEB https://github.com/gofiber/fiber/security/advisories/GHSA-35hp-hqmv-8qg8
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-30246
- WEB https://github.com/gofiber/fiber/commit/050ff1ff18511c1475b8ec627460216aaecddd4e
- WEB https://github.com/gofiber/fiber/commit/9a0d12c07ed895b84c72987f9288b04137afe5de
- PACKAGE https://github.com/gofiber/fiber
- WEB https://github.com/gofiber/fiber/blob/main/middleware/cache/cache_test.go#L599-L621
- WEB https://github.com/gofiber/fiber/blob/main/middleware/cache/config.go#L90-L92

INTRO_LOG:
27d359e8d0d33738e15cbf0d74e6a0be3501aea4
copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
2026-04-21T02:00:48+00:00
🐛 bug: address cache middleware review feedback

Agent-Logs-Url: https://github.com/gofiber/fiber/sessions/4d59616d-e436-43a7-901e-b82f34511b2b

Co-authored-by: gaby <835733+gaby@users.noreply.github.com>



INTRO_STAT:
 docs/middleware/cache.md       |   6 +-
 middleware/cache/cache.go      |   4 +-
 middleware/cache/cache_test.go | 124 +++++++++++++++++++++++++++++++++--------
 middleware/cache/config.go     |  29 +++++++---
 4 files changed, 126 insertions(+), 37 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/middleware/cache/cache.go b/middleware/cache/cache.go
index 8c5f366c..4428c9e6 100644
--- a/middleware/cache/cache.go
+++ b/middleware/cache/cache.go
@@ -560,7 +560,7 @@ func New(config ...Config) fiber.Handler {
 			return nil
 		}
 
-		if hasPrivate || hasNoCache || (!cfg.DisableVaryHeaders && varyHasStar) {
+		if hasPrivate || hasNoCache || varyHasStar {
 			if e != nil {
 				if err := deleteKey(reqCtx, key); err != nil {
 					if cfg.Storage != nil {
@@ -1279,7 +1279,7 @@ func defaultKeyGenerator(c fiber.Ctx, cfg *Config) string {
 	}
 
 	buf := (*bufPtr)[:0]
-	buf = append(buf, c.Path()...)
+	buf = append(buf, boundKeySegment(c.Path())...)
 
 	if !cfg.DisableQueryKeys {
 		buf = append(buf, []byte("|q=")...)


FIX_LOG:
9a0d12c07ed895b84c72987f9288b04137afe5de
René <rene@gofiber.io>
2026-04-23T14:48:29+02:00
bug: harden cache middleware key generation and restore Methods config

- Restore configurable Methods field (default: GET, HEAD) to replace hardcoded method check, with uppercase normalization and nil vs empty-slice semantics (nil = default, [] = disable caching)
- Fix escapeKeyDelimiters fast-path bug: backslash was not checked, allowing collisions between literal "\p" and escaped "|"
- Fix path delimiter injection: escape pipe/colon/backslash in request path before boundKeySegment to prevent crafted paths from manipulating cache key structure
- Optimize canonicalQueryString: add single-param fast path (skips url.ParseQuery/sort) and use sync.Pool for output buffer
- Simplify string conversions: replace utils.CopyString(utils.UnsafeString(buf)) with string(buf) and utils.UnsafeBytes(boundKeySegment(...)) with direct string append
- Add comprehensive tests: Methods config (POST caching, bypass, empty-slice, lowercase normalization), escapeKeyDelimiters unit regression test with collision-pair verification
- Update docs: Methods field in config table, default config, and migration guide



FIX_STAT:
 docs/middleware/cache.md                |   4 +-
 docs/whats_new.md                       |   3 +-
 middleware/cache/cache.go               |  69 +++++++++++++-------
 middleware/cache/cache_security_test.go |  56 ++++++++++++++++
 middleware/cache/cache_test.go          | 112 ++++++++++++++++++++++++++++++++
 middleware/cache/config.go              |  20 ++++++
 6 files changed, 240 insertions(+), 24 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/middleware/cache/cache.go b/middleware/cache/cache.go
index 976dcfb3..08a77439 100644
--- a/middleware/cache/cache.go
+++ b/middleware/cache/cache.go
@@ -10,6 +10,7 @@ import (
 	"fmt"
 	"math"
 	"net/url"
+	"slices"
 	"sort"
 	"strings"
 	"sync"
@@ -253,8 +254,8 @@ func New(config ...Config) fiber.Handler {
 
 		requestMethod := c.Method()
 
-		// Cache only GET and HEAD requests.
-		if requestMethod != fiber.MethodGet && requestMethod != fiber.MethodHead {
+		// Only cache methods listed in cfg.Methods (default: GET, HEAD).
+		if !slices.Contains(cfg.Methods, requestMethod) {
 			c.Set(cfg.CacheHeader, cacheUnreachable)
 			return c.Next()
 		}
@@ -1284,7 +1285,8 @@ func defaultKeyGenerator(c fiber.Ctx, cfg *Config) string {
 	}
 
 	buf := (*bufPtr)[:0]
-	buf = append(buf, boundKeySegment(c.Path())...)
+	// Escape delimiters in path to prevent crafted paths from injecting key structure
+	buf = append(buf, boundKeySegment(escapeKeyDelimiters(c.Path()))...)
 
 	if !cfg.DisableQueryKeys {
 		buf = append(buf, '|', 'q', '=')
@@ -1301,7 +1303,7 @@ func defaultKeyGenerator(c fiber.Ctx, cfg *Config) string {
 		buf = append(buf, canonicalCookieSubset(c, cfg.KeyCookies)...)
 	}
 
-	result := utils.CopyString(utils.UnsafeString(buf))
+	result := string(buf)
 
 	// Reset buffer and return to pool, but discard if it grew too large
 	// to prevent pool from retaining oversized buffers
@@ -1314,17 +1316,24 @@ func defaultKeyGenerator(c fiber.Ctx, cfg *Config) string {
 }
 
 func canonicalQueryString(uri *fasthttp.URI) string {
-	query := utils.CopyString(utils.UnsafeString(uri.QueryString()))
-	if query == "" {
+	raw := uri.QueryString()
+	if len(raw) == 0 {
 		return ""
 	}
 
-	// Pre-scan query string to detect excessive parameters before expensive parsing
-	// This prevents DoS via url.ParseQuery allocating large maps/slices
+	query := utils.CopyString(utils.UnsafeString(raw))
+
+	// Pre-scan query string to detect excessive parameters before expensive parsing.
+	// This prevents DoS via url.ParseQuery allocating large maps/slices.
 	if len(query) > maxQueryBufferSize {
 		return boundKeySegment(query)
 	}
 
+	// Fast path: single key=value pair needs no parsing or sorting
+	if strings.IndexByte(query, '&') < 0 {
+		return boundKeySegment(query)
+	}
+
 	// Quick count of potential parameters (ampersands + 1)
 	paramCount := 1
 	for i := 0; i < len(query); i++ {
@@ -1357,10 +1366,15 @@ func canonicalQueryString(uri *fasthttp.URI) string {
 	}
 	sort.Strings(keys)
 
-	// Use a bounded buffer to prevent excessive memory allocation during URL escaping
-	// URL escaping can expand strings up to 3x (each byte -> %XX)
-	initialCap := min(len(query)*2, maxQueryBufferSize/2)
-	buf := make([]byte, 0, initialCap)
+	// Use pooled buffer to prevent excessive memory allocation during URL escaping.
+	// URL escaping can expand strings up to 3x (each byte -> %XX).
+	v := keyBufferPool.Get()
+	bufPtr, ok := v.(*[]byte)
+	if !ok || bufPtr == nil {
+		b := make([]byte, 0, defaultKeyBufferCap)
+		bufPtr = &b
+	}
+	buf := (*bufPtr)[:0]
 
 	for _, key := range keys {
 		values := parsed[key]
@@ -1370,12 +1384,15 @@ func canonicalQueryString(uri *fasthttp.URI) string {
 				buf = append(buf, '&')
 			}
 
-			// Check buffer size before appending to prevent unbounded growth
 			escapedKey := url.QueryEscape(key)
 			escapedValue := url.QueryEscape(value)
 
-			// If buffer would exceed safe limits, hash the entire query
+			// Check buffer size before appending to prevent unbounded growth
 			if len(buf)+len(escapedKey)+len(escapedValue)+2 > maxQueryBufferSize {
+				if cap(buf) <= defaultKeyBufferCap*4 {
+					*bufPtr = buf
+					keyBufferPool.Put(bufPtr)
+				}
 				return boundKeySegment(query)
 			}
 
@@ -1385,7 +1402,15 @@ func canonicalQueryString(uri *fasthttp.URI) string {
 		}
 	}
 
-	return boundKeySegment(utils.CopyString(utils.UnsafeString(buf)))
+	result := boundKeySegment(string(buf))
+
+	// Return buffer to pool if not oversized
+

intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []