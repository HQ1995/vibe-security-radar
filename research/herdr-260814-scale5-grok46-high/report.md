# Direct-root slice 5: timeboxed adjudication

Lane is direct-root on `dr-slice-5.jsonl`. Worker proposal only; canonical ledgers were not edited. Blob diffs from the blobless sweep pool were not closed (promisor/lazy-fetch failures in collected stats), so product-file overlap rows keep hunk/but-for/reversal/release/uniqueness UNKNOWN. Lockfile- or test-only mismatches are FALSE_POSITIVE `wrong_edge` from commit subject plus overlap paths. No countable AI_DIRECT_ROOT proposal.

Gate order: identity / AI hunk / topology / but-for / fix reversal / release / uniqueness.

| Case | Verdict | Class | Gates | Decisive note |
|---|---|---|---|---|
| GHSA-7W99-5WM4-3G79 | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is oauth-provider token.ts/test, the authorization-code consume path. Ancestor message closes GHSA-392p (refresh-token CAS) and is the parent of the GHS |
| GHSA-4MXG-3P6V-XGQ3 | FALSE_POSITIVE | UNRELATED_DEPENDENCY_BUMP | F/F/P/F/U/U/U | AI ancestor is Dependabot bumping release-it in package.json/lock. Advisory is SAML signature verification (xml-crypto signedReferences). Overlap is only lockfi |
| GHSA-M837-G268-MMV7 | FALSE_POSITIVE | UNRELATED_DEPENDENCY_BUMP | F/F/P/F/U/U/U | Same Dependabot release-it bump as the paired Node-SAML advisory. Overlap remains package.json/lock, not the SAML parser. Authentication-bypass hunk is in the l |
| GHSA-5662-CV6M-63WH | FALSE_POSITIVE | UNRELATED_DEPENDENCY_BUMP | F/F/P/F/U/U/U | AI ancestor is Dependabot bumping cloud.google.com/go/storage (go.mod/go.sum). Advisory says world-writable SBOM mode 666 was introduced in 1b272db Persist work |
| GHSA-MWH4-6H8G-PG8W | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is aiohttp http_writer.py/_http_writer.pyx, the response-splitting surface. Ancestor is Reject null bytes in headers; fix is Restrict reason. Adjacent H |
| GHSA-XH69-987W-HRP8 | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is lib/resolv.rb plus DNS tests, the decompression surface. Ancestor is TCP fallback with multiple nameservers; fix limits decompressed name length. Sam |
| GHSA-8MVJ-3J78-4QMW | FALSE_POSITIVE | UNRELATED_DEPENDENCY_BUMP | F/F/P/F/U/U/U | AI ancestor upgrades @babel/runtime in package.json/lock (Snyk bot). Advisory is addImage PNG parser DoS. Overlap is only lockfiles; PNG parser replacement live |
| GHSA-FVMW-CJ7J-J39Q | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is remote.ts / remote-pattern tests, the isRemoteAllowed path. Ancestor rejects wildcard hostnames without dots; fix requires explicit data: URL authori |
| GHSA-FCXQ-V2R3-CC8H | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is PushSecret controller. Ancestor #5109 scopes SecretStore list to the PushSecret namespace; fix #5133 scopes Secret list. Looks like a prior partial r |
| GHSA-4J8X-X6V7-W9RQ | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is pythonCodeValidator.ts, not CSVAgent.ts. Ancestor is Flowise 591 homoglyph/validator hardening; fix removes CSVAgent/AirtableAgent. CSV data-URI inte |
| GHSA-52FH-8V99-63C2 | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | This advisory is the Unicode homoglyph validator bypass that ancestor #6476 claims to fix; final closure removes the agents. That is incomplete-remediation shap |
| GHSA-5XVG-PMGG-3MXR | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | CSV Agent prompt-injection RCE. Overlap is the later validator, not CSVAgent source. Ancestor is a prior validator patch; agent-removal is the named closure. Hu |
| GHSA-VMV7-4M6C-3CG5 | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | CSV Agent Pyodide interpolation RCE. Same ancestor/fix pair and validator overlap as the other Flowise rows. CSVAgent.ts interpolation hunk not in the compared  |
| GHSA-HJFH-P8F5-24WR | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap includes oauth_endpoints.py. Ancestor is a large merge-from-fork about rate limiting/nginx/redis that also annotates endpoints. Advisory is OAuth client |
| GHSA-RPW8-82V9-3Q87 | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap includes user_endpoints.py. Same rate-limit merge ancestor as the paired Fides advisory. Advisory is password-change session invalidation. User-endpoint |
| GHSA-5QFP-32CF-69JH | FALSE_POSITIVE | UNRELATED_DEPENDENCY_BUMP | F/F/P/F/U/U/U | AI ancestor is Update dependencies (#16) touching Cargo.toml/lock. Advisory is unauthenticated HTTP /rpc sessions enumeration/hijack. Overlap is only Cargo mani |
| GHSA-HHF6-3XPG-PGGX | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is web3-utils converters.ts. Ancestor fixes odd-length hex conversion; fix is nullish/prototype-pollution hygiene. Advisory names web3-core-subscription |
| GHSA-QJ3P-XC97-XW74 | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is package.json/yarn.lock and the advisory mechanism IS a malicious debug@4.4.2 lockfile pull. Ancestor Add New Analytics Client could have introduced d |
| GHSA-8X88-C5MF-7J5W | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is src/header.ts. Ancestor stops applying PAX fields to meta entries (Cursor-marked); fix refuses negative header size. Same tar header parser, differen |
| GHSA-83C4-FFJP-MXP9 | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is OIDC introspection/UserInfo Java. Ancestor is alg:none JWT NPE; fix is notBefore revocation. Adjacent token validation; realm vs client notBefore hun |
| GHSA-6PVW-G552-53C5 | FALSE_POSITIVE | UNRELATED_TEST_ONLY | F/F/P/F/U/U/U | AI ancestor only adds shell tests for pointer extension programs (t/t-checkout.sh, t/t-pull.sh). Advisory is git lfs checkout/pull writing through colliding sym |
| GHSA-7G3R-8C6V-HFMR | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is kvs_endpoint.go. Ancestor mitigates CVE-2025-11392 key-name validation; advisory/fix is CVE-2025-11374 Content-Length DoS. Same endpoint, different C |
| GHSA-HQ76-6GH2-5G4Q | FALSE_POSITIVE | UNRELATED_DEPENDENCY_BUMP | F/F/P/F/U/U/U | AI ancestor is renovate bump of k8s.io/kubernetes (go.mod/go.sum). Advisory is crafted LUKS2 volumes / OpenCryptDevice detached headers. Overlap is only Go mani |
| GHSA-HRHF-2VCR-GHCH | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is consensus/reactor.go. Ancestor rejects oversized proposals; fix adds BitArray ValidateBasic. Adjacent consensus reactor hardening; BitArray mismatch  |
| GHSA-5QJQ-93H5-HRGP | UNKNOWN | UNCLOSED_HUNK_COMPARISON | U/U/P/U/U/U/U | Overlap is pypdf image xobject code. Ancestor is MAINT rename of two variables; fix applies image-size limit. Rename in the vulnerable file could be innocent or |

## Per-row reasoning

### GHSA-7W99-5WM4-3G79

Repository: better-auth/better-auth. Fix `b4bc65a00778`. AI ancestor `c6918ecc9e3a` (`Merge commit from fork`). Overlap: packages/oauth-provider/src/token.test.ts, packages/oauth-provider/src/token.ts.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is oauth-provider token.ts/test, the authorization-code consume path. Ancestor message closes GHSA-392p (refresh-token CAS) and is the parent of the GHSA-7w99 fix, but blob diffs failed (promisor). Hunk identity vs the findOne+deleteOne race is unclosed.

Advisory: @better-auth/oauth-provider's OAuth authorization-code grant allows concurrent redemption when two token requests race the find-then-delete primitive

Ancestor excerpt: Merge commit from fork / The `authorization_code`-grant rotation in `createRefreshToken` and the explicit `revokeRefreshToken` path both updated the parent `oauthRefreshToken` row 

### GHSA-4MXG-3P6V-XGQ3

Repository: node-saml/node-saml. Fix `31ead9411ebc`. AI ancestor `37ee11ec4b0f` (`Bump release-it from 16.3.0 to 17.0.5 (#348)`). Overlap: package-lock.json, package.json.

Verdict `FALSE_POSITIVE` / `UNRELATED_DEPENDENCY_BUMP` / countable=False.

Gates: identity FAIL, hunk FAIL, topology PASS, but-for FAIL, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

AI ancestor is Dependabot bumping release-it in package.json/lock. Advisory is SAML signature verification (xml-crypto signedReferences). Overlap is only lockfiles; ancestor did not author the SAML assertion-loading hunk closed by 31ead941.

Advisory: Node-SAML SAML Signature Verification Vulnerability

Ancestor excerpt: Bump release-it from 16.3.0 to 17.0.5 (#348) / Bumps [release-it](https://github.com/release-it/release-it) from 16.3.0 to 17.0.5. / - [Release notes](https://github.com/release-it

### GHSA-M837-G268-MMV7

Repository: node-saml/node-saml. Fix `31ead9411ebc`. AI ancestor `37ee11ec4b0f` (`Bump release-it from 16.3.0 to 17.0.5 (#348)`). Overlap: package-lock.json, package.json.

Verdict `FALSE_POSITIVE` / `UNRELATED_DEPENDENCY_BUMP` / countable=False.

Gates: identity FAIL, hunk FAIL, topology PASS, but-for FAIL, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Same Dependabot release-it bump as the paired Node-SAML advisory. Overlap remains package.json/lock, not the SAML parser. Authentication-bypass hunk is in the later xml-crypto signedReferences fix, not this ancestor.

Advisory: Node-SAML SAML Authentication Bypass

Ancestor excerpt: Bump release-it from 16.3.0 to 17.0.5 (#348) / Bumps [release-it](https://github.com/release-it/release-it) from 16.3.0 to 17.0.5. / - [Release notes](https://github.com/release-it

### GHSA-5662-CV6M-63WH

Repository: chainguard-dev/melange. Fix `1b272db2a0bb`. AI ancestor `881f41bc274a` (`build(deps): bump cloud.google.com/go/storage from 1.50.0 to 1.51.0 (#1855)`). Overlap: go.mod, go.sum.

Verdict `FALSE_POSITIVE` / `UNRELATED_DEPENDENCY_BUMP` / countable=False.

Gates: identity FAIL, hunk FAIL, topology PASS, but-for FAIL, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

AI ancestor is Dependabot bumping cloud.google.com/go/storage (go.mod/go.sum). Advisory says world-writable SBOM mode 666 was introduced in 1b272db Persist workspace filesystem, which is listed as fix_ref here, not the ancestor. Ancestor did not author the SBOM permission hunk.

Advisory: melange's world-writable permissions expose SBOM files to potential image tampering

Ancestor excerpt: build(deps): bump cloud.google.com/go/storage from 1.50.0 to 1.51.0 (#1855) / Bumps [cloud.google.com/go/storage](https://github.com/googleapis/google-cloud-go) from 1.50.0 to 1.51

### GHSA-MWH4-6H8G-PG8W

Repository: aio-libs/aiohttp. Fix `53b35a2f8869`. AI ancestor `db560cfeab32` (`Reject null bytes in headers (#12210) (#12214)`). Overlap: aiohttp/_http_writer.pyx, aiohttp/http_writer.py.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is aiohttp http_writer.py/_http_writer.pyx, the response-splitting surface. Ancestor is Reject null bytes in headers; fix is Restrict reason. Adjacent HTTP-writer hardening, but blobs were not compared, so whether the ancestor rewrote the reason-phrase hunk stays UNKNOWN.

Advisory: AIOHTTP has HTTP response splitting via \r in reason phrase

Ancestor excerpt: Reject null bytes in headers (#12210) (#12214) / (cherry picked from commit bad4131d31a6d4ce71c3a7cc83b9fc01a70dfe55) / Co-authored-by: vmfunc <celeste@linux.com>

### GHSA-XH69-987W-HRP8

Repository: ruby/resolv. Fix `4c2f71b5e808`. AI ancestor `7d524df80eea` (`Fix TCP fallback with multiple nameservers`). Overlap: lib/resolv.rb, test/resolv/test_dns.rb.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is lib/resolv.rb plus DNS tests, the decompression surface. Ancestor is TCP fallback with multiple nameservers; fix limits decompressed name length. Same file, different stated bugs; hunk comparison unclosed without blobs.

Advisory: resolv vulnerable to DoS via insufficient DNS domain name length validation

Ancestor excerpt: Fix TCP fallback with multiple nameservers / Under the following conditions the exception / `Resolv::DNS::Requester::RequestError: host/port don't match` is raised: / - Multiple na

### GHSA-8MVJ-3J78-4QMW

Repository: parallax/jsPDF. Fix `4cf3ab619e56`. AI ancestor `d8bfc9f0af8a` (`fix: upgrade @babel/runtime from 7.26.7 to 7.26.9 (#3847)`). Overlap: package-lock.json, package.json.

Verdict `FALSE_POSITIVE` / `UNRELATED_DEPENDENCY_BUMP` / countable=False.

Gates: identity FAIL, hunk FAIL, topology PASS, but-for FAIL, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

AI ancestor upgrades @babel/runtime in package.json/lock (Snyk bot). Advisory is addImage PNG parser DoS. Overlap is only lockfiles; PNG parser replacement lives in 4cf3ab61, not this ancestor.

Advisory: jsPDF Denial of Service (DoS)

Ancestor excerpt: fix: upgrade @babel/runtime from 7.26.7 to 7.26.9 (#3847) / Snyk has created this PR to upgrade @babel/runtime from 7.26.7 to 7.26.9. / See this package in npm: / @babel/runtime / 

### GHSA-FVMW-CJ7J-J39Q

Repository: withastro/astro. Fix `9e9c528191b6`. AI ancestor `0f75f6bc637d` (`Fix wildcard hostname matching to reject hostnames without dots (#14787)`). Overlap: packages/astro/test/units/remote-pattern.test.js, packages/internal-helpers/src/remote.ts.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is remote.ts / remote-pattern tests, the isRemoteAllowed path. Ancestor rejects wildcard hostnames without dots; fix requires explicit data: URL authorization. Adjacent allowlist work; data: unconditional allow hunk was not compared.

Advisory: Astro Cloudflare adapter has Stored Cross-site Scripting vulnerability in /_image endpoint

Ancestor excerpt: Fix wildcard hostname matching to reject hostnames without dots (#14787) / * Fix wildcard hostname matching to reject hostnames without dots / * Update .changeset/fix-wildcard-host

### GHSA-FCXQ-V2R3-CC8H

Repository: external-secrets/external-secrets. Fix `39cdba586353`. AI ancestor `de40e8f4fa95` (`fix: select secretstores in same ns as pushsecret (#5109)`). Overlap: pkg/controllers/pushsecret/pushsecret_controller.go, pkg/controllers/pushsecret/pushsecret_controller_test.go.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is PushSecret controller. Ancestor #5109 scopes SecretStore list to the PushSecret namespace; fix #5133 scopes Secret list. Looks like a prior partial remediator, not an introducer, but controller hunks were not blob-compared, so identity stays UNKNOWN.

Advisory: External Secrets Operator's Missing Namespace Restriction Allows Unauthorized Secret Access

Ancestor excerpt: fix: select secretstores in same ns as pushsecret (#5109) / Signed-off-by: Grace Do <xgrace@gmail.com> / Co-authored-by: Gergely Brautigam <182850+Skarlso@users.noreply.github.com>

### GHSA-4J8X-X6V7-W9RQ

Repository: FlowiseAI/Flowise. Fix `f4e2794f6a57`. AI ancestor `42d593f8ca85` (`Fix Flowise 591 (#6476)`). Overlap: packages/components/src/pythonCodeValidator.test.ts, packages/components/src/pythonCodeValidator.ts.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is pythonCodeValidator.ts, not CSVAgent.ts. Ancestor is Flowise 591 homoglyph/validator hardening; fix removes CSVAgent/AirtableAgent. CSV data-URI interpolation hunk was not compared; validator-only overlap is insufficient to FAIL identity.

Advisory: Flowise: RCE via CSVAgent csvFile data URI base64 segment is interpolated into Python source without validation

Ancestor excerpt: Fix Flowise 591 (#6476) / * fix(flowise-591): Unicode homoglyph bypass / * Update packages/components/src/pythonCodeValidator.ts / Co-authored-by: gemini-code-assist[bot] <17696159

### GHSA-52FH-8V99-63C2

Repository: FlowiseAI/Flowise. Fix `f4e2794f6a57`. AI ancestor `42d593f8ca85` (`Fix Flowise 591 (#6476)`). Overlap: packages/components/src/pythonCodeValidator.test.ts, packages/components/src/pythonCodeValidator.ts.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

This advisory is the Unicode homoglyph validator bypass that ancestor #6476 claims to fix; final closure removes the agents. That is incomplete-remediation shaped, but DR identity requires proving the ancestor authored the still-vulnerable validator hunk. Blobs uncompared; leave UNKNOWN.

Advisory: Flowise: Pyodide validator Unicode homoglyph bypass leads to RCE

Ancestor excerpt: Fix Flowise 591 (#6476) / * fix(flowise-591): Unicode homoglyph bypass / * Update packages/components/src/pythonCodeValidator.ts / Co-authored-by: gemini-code-assist[bot] <17696159

### GHSA-5XVG-PMGG-3MXR

Repository: FlowiseAI/Flowise. Fix `f4e2794f6a57`. AI ancestor `42d593f8ca85` (`Fix Flowise 591 (#6476)`). Overlap: packages/components/src/pythonCodeValidator.test.ts, packages/components/src/pythonCodeValidator.ts.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

CSV Agent prompt-injection RCE. Overlap is the later validator, not CSVAgent source. Ancestor is a prior validator patch; agent-removal is the named closure. Hunk comparison unclosed.

Advisory: Flowise: CSV Agent Prompt Injection Remote Code Execution Vulnerability

Ancestor excerpt: Fix Flowise 591 (#6476) / * fix(flowise-591): Unicode homoglyph bypass / * Update packages/components/src/pythonCodeValidator.ts / Co-authored-by: gemini-code-assist[bot] <17696159

### GHSA-VMV7-4M6C-3CG5

Repository: FlowiseAI/Flowise. Fix `f4e2794f6a57`. AI ancestor `42d593f8ca85` (`Fix Flowise 591 (#6476)`). Overlap: packages/components/src/pythonCodeValidator.test.ts, packages/components/src/pythonCodeValidator.ts.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

CSV Agent Pyodide interpolation RCE. Same ancestor/fix pair and validator overlap as the other Flowise rows. CSVAgent.ts interpolation hunk not in the compared file list; stay UNKNOWN.

Advisory: Flowise: CSV Agent Remote Code Execution via Pyodide Code Injection — Root Shell Verified

Ancestor excerpt: Fix Flowise 591 (#6476) / * fix(flowise-591): Unicode homoglyph bypass / * Update packages/components/src/pythonCodeValidator.ts / Co-authored-by: gemini-code-assist[bot] <17696159

### GHSA-HJFH-P8F5-24WR

Repository: ethyca/fides. Fix `2ffd125e1089`. AI ancestor `59903c195e2f` (`Merge commit from fork`). Overlap: CHANGELOG.md, src/fides/api/api/v1/endpoints/oauth_endpoints.py.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap includes oauth_endpoints.py. Ancestor is a large merge-from-fork about rate limiting/nginx/redis that also annotates endpoints. Advisory is OAuth client scope privilege escalation. Endpoint hunk not blob-compared.

Advisory: Fides Webserver API is Vulnerable to OAuth Client Privilege Escalation

Ancestor excerpt: Merge commit from fork / * formatting / * slowapi to use same redis connection pool as app / * feat: temporary modification to spin up two local webservers / * adds connection_url_

### GHSA-RPW8-82V9-3Q87

Repository: ethyca/fides. Fix `8daec4f5ad3d`. AI ancestor `59903c195e2f` (`Merge commit from fork`). Overlap: CHANGELOG.md, src/fides/api/api/v1/endpoints/user_endpoints.py.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap includes user_endpoints.py. Same rate-limit merge ancestor as the paired Fides advisory. Advisory is password-change session invalidation. User-endpoint hunk not blob-compared.

Advisory: Fides' Admin UI User Password Change Does Not Invalidate Current Session

Ancestor excerpt: Merge commit from fork / * formatting / * slowapi to use same redis connection pool as app / * feat: temporary modification to spin up two local webservers / * adds connection_url_

### GHSA-5QFP-32CF-69JH

Repository: surrealdb/surrealdb. Fix `fd800fc7c55a`. AI ancestor `e9dc863530ca` (`Update dependencies (#16)`). Overlap: Cargo.lock, Cargo.toml.

Verdict `FALSE_POSITIVE` / `UNRELATED_DEPENDENCY_BUMP` / countable=False.

Gates: identity FAIL, hunk FAIL, topology PASS, but-for FAIL, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

AI ancestor is Update dependencies (#16) touching Cargo.toml/lock. Advisory is unauthenticated HTTP /rpc sessions enumeration/hijack. Overlap is only Cargo manifests; session-map auth lives in later Fix RPC session leak (#22).

Advisory: SurrealDB: HTTP /rpc `sessions` method leaks attached session UUIDs, enabling full session hijack by anonymous callers

Ancestor excerpt: Update dependencies (#16) / Co-authored-by: Stu Schwartz <stu.schwartz@surrealdb.com>

### GHSA-HHF6-3XPG-PGGX

Repository: web3/web3.js. Fix `d9660426c122`. AI ancestor `f60b9191a88c` (`Fix odd length hex string conversion (#5086)`). Overlap: packages/web3-utils/src/converters.ts, packages/web3-utils/test/fixtures/converters.ts.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is web3-utils converters.ts. Ancestor fixes odd-length hex conversion; fix is nullish/prototype-pollution hygiene. Advisory names web3-core-subscriptions attachToObject. Converter hunk vs subscriptions prototype pollution not compared.

Advisory: web3-core-subscriptions has a Prototype Pollution vulnerability

Ancestor excerpt: Fix odd length hex string conversion (#5086) / * Fix odd length hex string conversion / * Support not prefixed hex strings / * Support capital prefix / * Add unit tests / * Refacto

### GHSA-QJ3P-XC97-XW74

Repository: MetaMask/metamask-sdk. Fix `baa185c6cfa9`. AI ancestor `12479bef28ca` (`Add New Analytics Client (#1270)`). Overlap: package.json, yarn.lock.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is package.json/yarn.lock and the advisory mechanism IS a malicious debug@4.4.2 lockfile pull. Ancestor Add New Analytics Client could have introduced debug, but lockfile diffs were not inspected. Do not FAIL identity without that diff.

Advisory: MetaMask SDK indirectly exposed via malicious debug@4.4.2 dependency

Ancestor excerpt: Add New Analytics Client (#1270) / * add analytics client / * refactor + added tests / * tidy / * fix: integrate standard eslint rules and add tsup to export types, cjs version / *

### GHSA-8X88-C5MF-7J5W

Repository: isaacs/node-tar. Fix `9e78bf058b2c`. AI ancestor `21a822027658` (`do not apply PAX header fields to meta entries`). Overlap: src/header.ts, test/header.js.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is src/header.ts. Ancestor stops applying PAX fields to meta entries (Cursor-marked); fix refuses negative header size. Same tar header parser, different stated bugs. Negative-size hunk not compared.

Advisory: node-tar: Negative tar entry size causes infinite loop in archive replace

Ancestor excerpt: do not apply PAX header fields to meta entries / A PAX extended header (x/g) describes the *next file entry*, per POSIX / pax, not the GNU long-name (L) / long-link (K) or further 

### GHSA-83C4-FFJP-MXP9

Repository: keycloak/keycloak. Fix `b6cd645683f4`. AI ancestor `3bf29d5a6175` (`Unhandled NPE with alg:none JWT in Bearer Authentication`). Overlap: services/src/main/java/org/keycloak/protocol/oidc/AccessTokenIntrospectionProvider.java, services/src/main/java/org/keycloak/protocol/oidc/endpoints/UserInfoEndpoint.java.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is OIDC introspection/UserInfo Java. Ancestor is alg:none JWT NPE; fix is notBefore revocation. Adjacent token validation; realm vs client notBefore hunk not compared.

Advisory: Keycloak: Revoked Tokens Can Remain Active When Both Realm-Level and Client-Level `notBefore` Revocation Policies are Configured

Ancestor excerpt: Unhandled NPE with alg:none JWT in Bearer Authentication / * Unhandled NPE with alg:none JWT in Bearer Authentication / Closes #48744 / (cherry picked from commit 1e99746a68c0990f2

### GHSA-6PVW-G552-53C5

Repository: git-lfs/git-lfs. Fix `0cffe93176b8`. AI ancestor `4b25800ecc81` (`t: add shell tests with pointer extension program`). Overlap: t/t-checkout.sh, t/t-pull.sh.

Verdict `FALSE_POSITIVE` / `UNRELATED_TEST_ONLY` / countable=False.

Gates: identity FAIL, hunk FAIL, topology PASS, but-for FAIL, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

AI ancestor only adds shell tests for pointer extension programs (t/t-checkout.sh, t/t-pull.sh). Advisory is git lfs checkout/pull writing through colliding symlinks in product checkout code. Tests are not the working-tree write path closed by 0cffe931.

Advisory: Git LFS may write to arbitrary files via crafted symlinks

Ancestor excerpt: t: add shell tests with pointer extension program / In PR #486 we introduced support for Git LFS pointer extensions, along / with some related tests in our Go test suite and the t/

### GHSA-7G3R-8C6V-HFMR

Repository: hashicorp/consul. Fix `72a358cd0253`. AI ancestor `5259495ae77d` (`removed regex for kv keys and added validations to mitigate CVE-2025-11392 (#22850)`). Overlap: agent/kvs_endpoint.go, agent/kvs_endpoint_test.go.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is kvs_endpoint.go. Ancestor mitigates CVE-2025-11392 key-name validation; advisory/fix is CVE-2025-11374 Content-Length DoS. Same endpoint, different CVEs; Content-Length hunk not compared.

Advisory: Consul key/value endpoint is vulnerable to denial of service

Ancestor excerpt: removed regex for kv keys and added validations to mitigate CVE-2025-11392 (#22850) / * updated kvKeyPattern / * add changelog / * Update agent/kvs_endpoint.go to include ç in allo

### GHSA-HQ76-6GH2-5G4Q

Repository: edgelesssys/constellation. Fix `bb8d2c8a5c0a`. AI ancestor `23fa3bb36ea1` (`deps: update module k8s.io/kubernetes to v1.33.4 [SECURITY] (#3931)`). Overlap: go.mod, go.sum.

Verdict `FALSE_POSITIVE` / `UNRELATED_DEPENDENCY_BUMP` / countable=False.

Gates: identity FAIL, hunk FAIL, topology PASS, but-for FAIL, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

AI ancestor is renovate bump of k8s.io/kubernetes (go.mod/go.sum). Advisory is crafted LUKS2 volumes / OpenCryptDevice detached headers. Overlap is only Go manifests; cryptsetup change is bb8d2c8a, not this ancestor.

Advisory: Constellation has insecure LUKS2 persistent storage partitions which may be opened and used

Ancestor excerpt: deps: update module k8s.io/kubernetes to v1.33.4 [SECURITY] (#3931) / Co-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>

### GHSA-HRHF-2VCR-GHCH

Repository: cometbft/cometbft. Fix `be5677c3e58f`. AI ancestor `2cd5d91d9db3` (`fix(consensus/reactor): reject oversized proposals (backport #5324) (#5407)`). Overlap: CHANGELOG.md, consensus/reactor.go.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is consensus/reactor.go. Ancestor rejects oversized proposals; fix adds BitArray ValidateBasic. Adjacent consensus reactor hardening; BitArray mismatch hunk not compared.

Advisory: CometBFT's invalid BitArray handling can lead to network halt

Ancestor excerpt: fix(consensus/reactor): reject oversized proposals (backport #5324) (#5407) / --- / Updates the consensus reactor to validate that a received proposal will / not contain more parts

### GHSA-5QJQ-93H5-HRGP

Repository: py-pdf/pypdf. Fix `c64583be16b8`. AI ancestor `c11bf57bc22d` (`MAINT: Rename two variables (#3873)`). Overlap: pypdf/generic/_image_xobject.py, tests/generic/test_image_xobject.py.

Verdict `UNKNOWN` / `UNCLOSED_HUNK_COMPARISON` / countable=False.

Gates: identity UNKNOWN, hunk UNKNOWN, topology PASS, but-for UNKNOWN, reversal UNKNOWN, release UNKNOWN, uniqueness UNKNOWN.

Overlap is pypdf image xobject code. Ancestor is MAINT rename of two variables; fix applies image-size limit. Rename in the vulnerable file could be innocent or could have moved the size logic; blobs uncompared.

Advisory: pypdf: Possible large memory usage for wrong image dimensions

Ancestor excerpt: MAINT: Rename two variables (#3873) / Shorter names with same meaning for better readability. / --------- / Co-authored-by: Stefan <96178532+stefan6419846@users.noreply.github.com>

