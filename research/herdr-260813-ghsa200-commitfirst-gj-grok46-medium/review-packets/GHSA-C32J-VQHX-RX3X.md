# GHSA-C32J-VQHX-RX3X

repo: jwt/ruby-jwt

summary: ruby-jwt: Empty-key HMAC bypass; cross-language sibling of CVE-2026-44351

aliases: ['CVE-2026-45363']

severity: HIGH

evidence: blame blamed_lines=5 files=['CHANGELOG.md', 'lib/jwt/version.rb']

intro: 3a31a200a8af8aeaee5e113e54185838f51ddf46

intro_subject: Fix compatibility with ruby-head (#706)

intro_date: 2025-11-13T21:52:41+02:00

fix: db560b769a07bd9724e77ff505011ac01872106f

affected: [
  {
    "package": {
      "ecosystem": "RubyGems",
      "name": "jwt"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "3.0.0"
          },
          {
            "fixed": "3.2.0"
          }
        ]
      }
    ]
  },
  {
    "package": {
      "ecosystem": "RubyGems",
      "name": "jwt"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "2.10.3"
          }
        ]
      }
    ]
  }
]

DETAILS:
`JWT.decode(token, '', true, algorithm: 'HS256')` accepts an attacker-forged token.
`OpenSSL::HMAC.digest('SHA256', '', payload)` returns a valid digest under an empty key, and no `raise
  InvalidKeyError if key.empty?` precondition exists in the HMAC algorithm.

```
JWT.decode(token, "", true, algorithm: 'HS256')
  -> JWA::Hmac.verify(verification_key: "", ...)
  -> OpenSSL::HMAC.digest('SHA256', "", signing_input) == signature
```

The same path is reached when a keyfinder block or key_finder: argument returns "", nil, or an
array containing nil for an unknown key. JWT::Decode#find_key only rejects literal nil and empty
arrays, and JWT::JWA::Hmac silently coerces nil to "" (signing_key ||= '') before signing.

```
JWT.decode(token, nil, true, algorithms: ['HS256']) { |_h| "" }
  -> find_key returns ""               # "" && !Array("").empty? == true
  -> JWA::Hmac.verify(verification_key: "", ...)
  -> verifies
```
Common application patterns that produce the unsafe value: `redis.get("kid:#{kid}").to_s`, ORM string columns with `default: ''`, `ENV['SECRET'] || '', Hash.new('')` lookups, [primary, fallback] where fallback may be nil. Applications passing a non-empty static key:, or whose keyfinder returns nil / raises on miss, are not affected.

The existing `enforce_hmac_key_length` option would block this but defaults to false. On OpenSSL ≥ 3.5 the empty-key HMAC.digest call no longer raises, so the OpenSSL-3.0 rescue in JWA::Hmac#sign does not fire.

Affects HS256/HS384/HS512 via both JWT.decode (positional key and block keyfinder) and
`JWT::EncodedToken#verify_signature!(key_finder:)`

REFS:
- WEB https://github.com/jwt/ruby-jwt/security/advisories/GHSA-c32j-vqhx-rx3x
- WEB https://github.com/jwt/ruby-jwt/issues/724
- WEB https://github.com/jwt/ruby-jwt/commit/db560b769a07bd9724e77ff505011ac01872106f
- PACKAGE https://github.com/jwt/ruby-jwt
- WEB https://github.com/jwt/ruby-jwt/releases/tag/v2.10.3
- WEB https://github.com/jwt/ruby-jwt/releases/tag/v3.2.0
- WEB https://github.com/rubysec/ruby-advisory-db/blob/master/gems/jwt/CVE-2026-45363.yml
- WEB https://www.cve.org/CVERecord?id=CVE-2026-45363

INTRO_LOG:
3a31a200a8af8aeaee5e113e54185838f51ddf46
Joakim Antman <antmanj@gmail.com>
2025-11-13T21:52:41+02:00
Fix compatibility with ruby-head (#706)

* Fix compatibility with openssl

* Changelog and versions

* Update CHANGELOG.md

Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>

* Update CHANGELOG.md

Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>

---------

Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>


INTRO_STAT:
 CHANGELOG.md             | 13 +++++++++++++
 lib/jwt/jwk/rsa.rb       |  2 +-
 lib/jwt/version.rb       |  2 +-
 spec/jwt/jwk/rsa_spec.rb |  4 ++--
 4 files changed, 17 insertions(+), 4 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 87615ed..bb8b0ea 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -1,5 +1,18 @@
 # Changelog
 
+## [v3.1.3](https://github.com/jwt/ruby-jwt/tree/v3.1.3) (NEXT)
+
+[Full Changelog](https://github.com/jwt/ruby-jwt/compare/v3.1.2...v3.1.3)
+
+**Features:**
+
+- Your contribution here
+
+**Fixes and enhancements:**
+
+- Fix compatibility with the openssl 4.0 gem [#706](https://github.com/jwt/ruby-jwt/pull/706)
+- Your contribution here
+
 ## [v3.1.2](https://github.com/jwt/ruby-jwt/tree/v3.1.2) (2025-06-28)
 
 [Full Changelog](https://github.com/jwt/ruby-jwt/compare/v3.1.1...v3.1.2)
diff --git a/lib/jwt/version.rb b/lib/jwt/version.rb
index 34436db..4c1321c 100644
--- a/lib/jwt/version.rb
+++ b/lib/jwt/version.rb
@@ -16,7 +16,7 @@ module JWT
   module VERSION
     MAJOR = 3
     MINOR = 1
-    TINY  = 2
+    TINY  = 3
     PRE   = nil
 
     STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')


FIX_LOG:
db560b769a07bd9724e77ff505011ac01872106f
Joakim Antman <antmanj@gmail.com>
2026-05-13T22:32:09+03:00
Merge commit from fork

* Reject nil and empty HMAC keys when signing and verifying

* Version bump


FIX_STAT:
 CHANGELOG.md                             |  7 ++-
 lib/jwt/jwa/hmac.rb                      | 21 ++++----
 lib/jwt/version.rb                       | 12 +----
 spec/integration/readme_examples_spec.rb | 12 -----
 spec/jwt/jwa/hmac_spec.rb                | 82 +++++++++++++-------------------
 spec/jwt/jwt_spec.rb                     | 22 ---------
 6 files changed, 47 insertions(+), 109 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 84239f8..7229077 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -1,20 +1,19 @@
 # Changelog
 
-## [v3.1.3](https://github.com/jwt/ruby-jwt/tree/v3.1.3) (NEXT)
+## [v3.2.0](https://github.com/jwt/ruby-jwt/tree/v3.2.0) (2026-05-13)
 
-[Full Changelog](https://github.com/jwt/ruby-jwt/compare/v3.1.2...v3.1.3)
+[Full Changelog](https://github.com/jwt/ruby-jwt/compare/v3.1.2...v3.2.0)
 
 **Features:**
 
 - Add `enforce_hmac_key_length` configuration option [#716](https://github.com/jwt/ruby-jwt/pull/716) - ([@304](https://github.com/304))
-- Your contribution here
 
 **Fixes and enhancements:**
 
+- Reject `nil` and empty HMAC keys when signing and verifying ([CVE-2026-45363](https://www.cve.org/CVERecord?id=CVE-2026-45363) / [GHSA-c32j-vqhx-rx3x](https://github.com/jwt/ruby-jwt/security/advisories/GHSA-c32j-vqhx-rx3x))
 - Fix compatibility with the openssl 4.0 gem [#706](https://github.com/jwt/ruby-jwt/pull/706)
 - Test against Ruby 4.0 on CI [#707](https://github.com/jwt/ruby-jwt/pull/707)
 - Fix type error when header is not a JSON object [#715](https://github.com/jwt/ruby-jwt/pull/715) - ([@304](https://github.com/304))
-- Your contribution here
 
 ## [v3.1.2](https://github.com/jwt/ruby-jwt/tree/v3.1.2) (2025-06-28)
 
diff --git a/lib/jwt/version.rb b/lib/jwt/version.rb
index 4c1321c..535e11a 100644
--- a/lib/jwt/version.rb
+++ b/lib/jwt/version.rb
@@ -15,8 +15,8 @@ module JWT
   # Version constants
   module VERSION
     MAJOR = 3
-    MINOR = 1
-    TINY  = 3
+    MINOR = 2
+    TINY  = 0
     PRE   = nil
 
     STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')
@@ -32,14 +32,6 @@ module JWT
     true if 3 * 0x10000000 <= OpenSSL::OPENSSL_VERSION_NUMBER
   end
 
-  # Checks if there is an OpenSSL 3 HMAC empty key regression.
-  #
-  # @return [Boolean] true if there is an OpenSSL 3 HMAC empty key regression, false otherwise.
-  # @api private
-  def self.openssl_3_hmac_empty_key_regression?
-    openssl_3? && openssl_version <= ::Gem::Version.new('3.0.0')
-  end
-
   # Returns the OpenSSL version.
   #
   # @return [Gem::Version] the OpenSSL version.


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []