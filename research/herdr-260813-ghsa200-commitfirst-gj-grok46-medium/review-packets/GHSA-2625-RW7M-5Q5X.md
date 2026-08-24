# GHSA-2625-RW7M-5Q5X

repo: hubuum/hubuum-client-rust

summary: Hubuum client library (Rust): Sensitive data may be exposed through default diagnostics

aliases: []

severity: LOW

evidence: file_history blamed_lines=0 files=['README.md']

intro: 5d7af9fd90feea302817e6aba939a3a69fe5b366

intro_subject: feat(client): adopt principal-centric identity, service accounts, remote targets

intro_date: 2026-06-28T21:02:26+02:00

fix: 5a5c275ffa45f342459b7d3e977926da643bde50

affected: [
  {
    "package": {
      "ecosystem": "crates.io",
      "name": "hubuum_client"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "0.6.1"
          }
        ]
      }
    ],
    "database_specific": {
      "last_known_affected_version_range": "<= 0.6.0"
    }
  }
]

DETAILS:
## Summary

`hubuum_client` diagnostics can expose sensitive request, response, import/export, task, delivery, or server-provided data when applications format or log errors and public models.

## Affected behavior

Native `reqwest::Error` values retain the full request URL. Converting those errors into `ApiError::Http`, or exhausting retries and storing the error text in `ApiError::RetryExhausted`, preserves query parameter values. Detailed HTTP and decoding errors can retain server-provided messages, response bodies, or payload details, including through error source chains.

Several public response and model types also derived or implemented diagnostics over untrusted or secret-adjacent fields. These include raw response bodies and cursors; rendered and JSON export payloads; import schemas and object data; task summaries, links, output URLs, events, and import-result details; event-delivery claims and errors; event sink configuration; subscription routing; and remote-call failure details. High-level backup and export runners additionally copied unsuccessful server task summaries into `ApiError::Api`.

Applications commonly log errors and response values, so credentials, tokens, cursors, filters, echoed request content, imported object data, schema defaults, task or delivery details, and other sensitive payloads can be written to logs even though normal request logging redacts query values.

## Remediation

The proposed fix redacts query values from embedded request URLs before storing native HTTP errors and applies the same sanitization to exhausted retries. Default error and model diagnostics now report safe metadata rather than server messages, payloads, cursors, links, configuration, or secret-adjacent details. JSON codec errors no longer appear in the standard source chain, and unsuccessful high-level backup/export operations use the structured `TaskUnsuccessful` variant without copying task summaries.

Explicit response, error, task, import, export, event, and delivery APIs continue to expose original values for applications that deliberately inspect them.

## Validation

Regression coverage exercises direct HTTP conversion, async and blocking retry exhaustion, response and decoding diagnostics, import/export/raw-response containers, unsuccessful async and blocking task runners, task/event/import-result models, and secret-bearing event and remote models. The workspace format, lint, documentation, test, feature-matrix, Rust 1.88 MSRV, OpenAPI valida

REFS:
- WEB https://github.com/hubuum/hubuum-client-rust/security/advisories/GHSA-2625-rw7m-5q5x
- WEB https://github.com/hubuum/hubuum-client-rust/commit/5a5c275ffa45f342459b7d3e977926da643bde50
- PACKAGE https://github.com/hubuum/hubuum-client-rust
- WEB https://github.com/hubuum/hubuum-client-rust/releases/tag/v0.6.1

INTRO_LOG:
5d7af9fd90feea302817e6aba939a3a69fe5b366
Terje Kvernes <terje@kvernes.no>
2026-06-28T21:02:26+02:00
feat(client): adopt principal-centric identity, service accounts, remote targets

Sync the client to the current backend (main + PR #94/#93/#95), accepting
breaking API changes. Version stays at 0.0.3 (unreleased).

Identity model (principal-centric, PR #94):
- User.username -> name; add proper_name; password write-only with set_password()
- login body {name,password}; Credentials::new(name, password)
- tokens moved to /iam/principals/{id}/tokens; UserToken -> PrincipalTokenMetadata;
  scoped tokens_create() (raw one-time token), token_revoke(), NewTokenRequest
- Group::add_user/remove_user -> add_member/remove_member; members() -> PrincipalMember
- Namespace::user_permissions* -> principal_permissions*
- logout endpoints corrected to POST; logout_token now sends a {token} body

New resources:
- service accounts: CRUD + disable() + token helpers (service_accounts())
- remote targets: CRUD + invoke() -> TaskResponse, tagged auth/subject unions
  (remote_targets())
- unauthenticated healthz()/readyz() probes

"me" endpoints (PR #95): me(), me_groups/_tokens/_permissions(+_request); adds
MeResponse, CurrentTokenMetadata, PrincipalNamespacePermissions, GroupGrant.

Enum/field growth: Permissions +5 remote-target variants; Permission(Result)
+5 booleans; TaskKind::RemoteCall.

select() resolves service accounts and remote targets via their by-id endpoints.
Tests updated across endpoint tables, parity contract, and httpmock suites; new
coverage for SA create/disable, scoped token minting, remote-target invoke, me,
and probes. Also fixes pre-existing ClassRelationPost alias-field breakage in the
feature-gated container suite.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>



INTRO_STAT:
 README.md                                      |  12 +
 hubuum_client_derive/src/lib.rs                |   1 -
 src/client/async.rs                            | 184 +++++++++++-
 src/client/mod.rs                              |  33 ++-
 src/client/shared.rs                           |  11 +
 src/client/sync.rs                             | 167 ++++++++++-
 src/client/tests.rs                            |   2 +-
 src/endpoints.rs                               | 100 +++++--
 src/lib.rs                                     |   9 +-
 src/resources/group.rs                         |  58 ++--
 src/resources/mod.rs                           | 137 ++++++++-
 src/resources/namespace.rs                     |  45 ++-
 src/resources/remote_target.rs                 | 117 ++++++++
 src/resources/service_account.rs               | 109 +++++++
 src/resources/user.rs                          | 239 +++++++++++++---
 src/types/auth.rs                              |  13 +-
 src/types/meta.rs                              |   6 +
 src/types/mod.rs                               |  16 +-
 src/types/params.rs                            |   3 +-
 src/types/remote.rs                            | 196 +++++++++++++
 src/types/task.rs                              |   1 +
 tests/client_behavior.rs                       | 378 +++++++++++++++++++++----
 tests/container_integration/library/async.rs   |  36 ++-
 tests/container_integration/library/sync.rs    |  36 ++-
 tests/container_integration/support/clie

INTRO_DIFF_OVERLAP:
diff --git a/README.md b/README.md
index a68fd6a..a84f46b 100644
--- a/README.md
+++ b/README.md
@@ -24,6 +24,18 @@ A Rust client library for interacting with the Hubuum API. The library is design
 
     Run server-side reports, manage stored report templates, and submit asynchronous imports with typed task polling helpers.
 
+- **Principal-Centric Identity**:
+
+    Users and service accounts are both *principals*. Manage users and service accounts (create, update, disable), group membership by principal id, scoped token minting/revocation, and per-principal effective permissions. The `me()` family exposes the caller's own identity, tokens, groups, and permissions.
+
+- **Remote Targets**:
+
+    Configure hardened outbound HTTP targets and invoke them against namespaces, classes, objects, or relations, returning an async task to poll.
+
+- **Health & Readiness Probes**:
+
+    Unauthenticated `healthz()` / `readyz()` probes for liveness and readiness checks.
+
 - **No Built-In Table Formatting**:
 
     Models no longer implement built-in table rendering traits. Consumers that want table support should wrap/newtype the exported models in their own crates.


FIX_LOG:
5a5c275ffa45f342459b7d3e977926da643bde50
Terje Kvernes <terjekv@users.noreply.github.com>
2026-07-23T09:58:34+02:00
Merge commit from fork

* Redact sensitive error diagnostics

* Prepare hubuum_client 0.6.1 release

* Redact unsuccessful task diagnostics

* Redact event delivery diagnostics

* Honor custom transports for every request

* Finalize hubuum_client 0.6.1 release

* Disable redirects for built-in HTTP clients

* Redact event configuration diagnostics

* Redact decode and retry diagnostics

* Redact raw and export diagnostics

* Redact import and task diagnostics

* Strengthen redirect credential regression


FIX_STAT:
 CHANGELOG.md                    |  32 ++++
 COMPATIBILITY.md                |   1 +
 Cargo.lock                      |   4 +-
 Cargo.toml                      |   4 +-
 README.md                       |   6 +-
 docs/advanced.md                |  31 +++-
 hubuum_client_derive/Cargo.toml |   2 +-
 src/client/async.rs             | 316 +++++++++++++++++++++++++-----------
 src/client/mod.rs               |   2 +-
 src/client/shared.rs            | 118 ++++++++++++--
 src/client/sync.rs              | 261 +++++++++++++++++++++---------
 src/client/tests.rs             |  24 ++-
 src/errors.rs                   | 126 +++++++++++++--
 src/lib.rs                      |   2 +-
 src/resources/user.rs           |   2 +-
 src/types/event.rs              | 253 ++++++++++++++++++++++++++++-
 src/types/export.rs             |  72 ++++++++-
 src/types/import.rs             | 115 +++++++++++++-
 src/types/remote.rs             |  32 +++-
 src/types/task.rs               | 192 +++++++++++++++++++++-
 tests/client_behavior.rs        |  72 ++++++++-
 tests/foundations.rs            | 343 +++++++++++++++++++++++++++++++++++++++-
 22 files changed, 1766 insertions(+), 244 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/README.md b/README.md
index 1c9a241..49024b4 100644
--- a/README.md
+++ b/README.md
@@ -2,7 +2,7 @@
 
 A Rust client library for the Hubuum API. It provides synchronous and asynchronous clients, type-state authentication, typed resource IDs, fluent query builders, and task helpers for long-running operations such as imports and exports.
 
-`hubuum_client` 0.6.0 targets Hubuum server v0.0.3. The exact tested image and
+`hubuum_client` 0.6.1 targets Hubuum server v0.0.3. The exact tested image and
 the history for earlier client releases are recorded in
 [COMPATIBILITY.md](COMPATIBILITY.md).
 
@@ -36,14 +36,14 @@ Add the dependency to your project's `Cargo.toml`:
 
 ```toml
 [dependencies]
-hubuum_client = "0.6.0"
+hubuum_client = "0.6.1"
 ```
 
 Async support is enabled by default. Blocking applications can opt into only the synchronous surface:
 
 ```toml
 [dependencies]
-hubuum_client = { version = "0.6.0", default-features = false, features = ["blocking"] }
+hubuum_client = { version = "0.6.1", default-features = false, features = ["blocking"] }
 ```
 
 If you need unreleased changes, point Cargo at the Git repository:


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []