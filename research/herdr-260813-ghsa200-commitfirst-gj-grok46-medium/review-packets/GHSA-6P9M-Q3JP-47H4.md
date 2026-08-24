# GHSA-6P9M-Q3JP-47H4

repo: gogs/gogs

summary: Gogs: LFS dedupe path leaks private repo content across tenants

aliases: ['CVE-2026-52812']

severity: HIGH

evidence: blame blamed_lines=5 files=['internal/lfsx/storage.go', 'internal/lfsx/storage_test.go']

intro: 81ee8836445ac888d99da8b652be7d5cbc5c4d5c

intro_subject: lfs: verify content hash and prevent object overwrite (#8166)

intro_date: 2026-02-08T17:14:12-05:00

fix: f35a767af74e05342bafc6fdda02c791816426f8

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
            "fixed": "0.14.3"
          }
        ]
      }
    ]
  }
]

DETAILS:
Summary

Git LFS storage is content-addressed by OID alone (`<LFS-root>/<oid[0]>/<oid[1]>/<oid>`) but per-repo authorization lives in the `lfs_object` table keyed `(repo_id, oid)`. `serveUpload` skips re-uploading when the OID file already exists on disk and inserts a new `(repo_id, oid)` row pointing at it **without verifying the request body hashes to the OID being claimed**. Any user with write access to one repo can bind their repo to an OID owned by a private repo and download the original bytes via their own download endpoint.

Details

Dedupe shortcut at `internal/lfsx/storage.go:79-82`:

```go
if fi, err := os.Stat(fpath); err == nil {
    _, _ = io.Copy(io.Discard, rc)
    return fi.Size(), nil          // ← returns success with no hash check
}
```

Hash verification at `internal/lfsx/storage.go:106-108` only runs in the *new-file* branch — the dedupe path returns earlier.

`serveUpload` (`internal/route/lfs/basic.go:78-114`) trusts that success and inserts the per-repo binding:

```go
_, err := h.store.GetLFSObjectByOID(c.Req.Context(), repo.ID, oid)   // per-repo
if err == nil { /* already linked, drain & return 200 */ }
written, err := s.Upload(oid, c.Req.Request.Body)
err = h.store.CreateLFSObject(c.Req.Context(), repo.ID, oid, written, s.Storage())
```

`CreateLFSObject` is an unconditional `INSERT` on `(repo_id, oid)` with no check that the OID is referenced by the requesting repo's git history.

`serveDownload` at `internal/route/lfs/basic.go:42-72` only consults the per-repo row, then streams from the shared content-addressed file.

Suggested fix

1. In `LocalStorage.Upload`, when `os.Stat(fpath) == nil`, hash the request body via `io.TeeReader` and `ErrOIDMismatch` on disagreement — same code path as the new-file branch already uses. The "client retries after partial failure" use case still works; the retry just has to send the correct content.
2. Optional second layer: in `serveUpload`, refuse `CreateLFSObject` unless the OID is referenced by an LFS pointer in the requesting repo's refs.

PoC

Tested against gogs at HEAD `d7571322` (also reproduces on `v0.14.2`, paths are `internal/lfsutil/storage.go` and identical logic).

### Reproduction prerequisites
- Running gogs ≥ 0.12.0 with `[lfs] ENABLED = true`.
- Two accounts: `alice` (private repo `secrets`) and `bob` (any repo `bob/scratch`); bob has no access to `alice/secrets`.
- An OID known to be present in `alice/secrets` — leaked LFS pointer file in any public ancestor commit, stale f

REFS:
- WEB https://github.com/gogs/gogs/security/advisories/GHSA-6p9m-q3jp-47h4
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-52812
- WEB https://github.com/gogs/gogs/pull/8333
- WEB https://github.com/gogs/gogs/commit/f35a767af74e05342bafc6fdda02c791816426f8
- PACKAGE https://github.com/gogs/gogs
- WEB https://github.com/gogs/gogs/releases/tag/v0.14.3

INTRO_LOG:
81ee8836445ac888d99da8b652be7d5cbc5c4d5c
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-02-08T17:14:12-05:00
lfs: verify content hash and prevent object overwrite (#8166)

Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
Co-authored-by: deepsource-autofix[bot] <62050782+deepsource-autofix[bot]@users.noreply.github.com>


INTRO_STAT:
 CHANGELOG.md                     |  4 +++
 conf/app.ini                     |  2 ++
 internal/conf/conf.go            |  1 +
 internal/conf/static.go          |  5 +--
 internal/database/repo.go        |  1 +
 internal/lfsutil/storage.go      | 58 ++++++++++++++++++++++---------
 internal/lfsutil/storage_test.go | 73 ++++++++++++++++++++++------------------
 internal/route/lfs/basic.go      |  6 ++--
 internal/route/lfs/route.go      |  2 +-
 9 files changed, 98 insertions(+), 54 deletions(-)


INTRO_DIFF_OVERLAP:


FIX_LOG:
f35a767af74e05342bafc6fdda02c791816426f8
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-06-06T23:03:53-04:00
security: verify content hash on LFS dedupe shortcut (#8333)




FIX_STAT:
 CHANGELOG.md                  |  1 +
 internal/lfsx/storage.go      | 14 +++++++++++---
 internal/lfsx/storage_test.go | 16 ++++++++++++++--
 3 files changed, 26 insertions(+), 5 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/internal/lfsx/storage.go b/internal/lfsx/storage.go
index c63610e3..94f569af 100644
--- a/internal/lfsx/storage.go
+++ b/internal/lfsx/storage.go
@@ -74,10 +74,18 @@ func (s *LocalStorage) Upload(oid OID, rc io.ReadCloser) (int64, error) {
 		return 0, errors.Wrap(err, "create directories")
 	}
 
-	// If the object file already exists, skip the upload and return the
-	// existing file's size.
+	// If the object file already exists, the client must still prove it has
+	// the original bytes by hashing the request body. Otherwise any caller
+	// with write access to one repository could bind an OID owned by another
+	// repository to their own and download the original content.
 	if fi, err := os.Stat(fpath); err == nil {
-		_, _ = io.Copy(io.Discard, rc)
+		hash := sha256.New()
+		if _, err := io.Copy(hash, rc); err != nil {
+			return 0, errors.Wrap(err, "read request body")
+		}
+		if computed := hex.EncodeToString(hash.Sum(nil)); computed != string(oid) {
+			return 0, ErrOIDMismatch
+		}
 		return fi.Size(), nil
 	}
 
diff --git a/internal/lfsx/storage_test.go b/internal/lfsx/storage_test.go
index e14836d0..f7b91031 100644
--- a/internal/lfsx/storage_test.go
+++ b/internal/lfsx/storage_test.go
@@ -79,8 +79,8 @@ func TestLocalStorage_Upload(t *testing.T) {
 		assert.False(t, osx.IsFile(s.storagePath(oid)))
 	})
 
-	t.Run("duplicate upload returns existing size", func(t *testing.T) {
-		written, err := s.Upload(helloWorldOID, io.NopCloser(strings.NewReader("should be ignored")))
+	t.Run("duplicate upload with matching content returns existing size", func(t *testing.T) {
+		written, err := s.Upload(helloWorldOID, io.NopCloser(strings.NewReader("Hello world!")))
 		require.NoError(t, err)
 		assert.Equal(t, int64(12), written)
 
@@ -90,6 +90,18 @@ func TestLocalStorage_Upload(t *testing.T) {
 		require.NoError(t, err)
 		assert.Equal(t, "Hello world!", buf.String())
 	})
+
+	t.Run("duplicate upload with mismatched content is rejected", func(t *testing.T) {
+		written, err := s.Upload(helloWorldOID, io.NopCloser(strings.NewReader("different bytes")))
+		assert.Equal(t, int64(0), written)
+		assert.Equal(t, ErrOIDMismatch, err)
+
+		// Verify original content is preserved.
+		var buf bytes.Buffer
+		err = s.Download(helloWorldOID, &buf)
+		require.NoError(t, err)
+		assert.Equal(t, "Hello world!", buf.String())
+	})
 }
 
 func TestLocalStorage_Download(t *testing.T) {


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []