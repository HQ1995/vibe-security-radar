# GHSA-89MR-XQFV-758M

repo: gogs/gogs

summary: Gogs: UploadRepoFiles writes outside repo working tree via committed parent sym

aliases: ['CVE-2026-52811']

severity: CRITICAL

evidence: blame blamed_lines=1 files=['internal/database/repo_editor.go']

intro: 36d56d5525972d9a87a136a490469a997efdcd66

intro_subject: all: rename packages ending with "util" to end with "x" (#8182)

intro_date: 2026-02-16T13:25:19-05:00

fix: 04cb8afbb01d855454e59977a1cdbf522ea1db31

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

`(*Repository).UploadRepoFiles` checks for symlinks only on the **leaf** of the upload target (`osx.IsSymlink(targetPath)`). The siblings `UpdateRepoFile`, `DeleteRepoFile`, and `GetDiffPreview` use `hasSymlinkInPath`, which lstats every component — `UploadRepoFiles` is the lone outlier. An attacker with repo-write access plus a multipart upload whose filename contains a literal backslash (preserved by `filepath.Base` on Linux, then converted to `/` by `pathx.Clean`) redirects the write through a previously-committed directory symlink. `iox.CopyFile` opens the destination with `os.Create` (no `O_NOFOLLOW`), so the kernel follows the parent symlink and writes attacker bytes anywhere the gogs UID can write — `~git/.ssh/authorized_keys` → SSH foothold, or `<repo>.git/hooks/post-receive` → next-push RCE.

Windows builds are unaffected: `filepath.Base` treats `\` as a separator (strips the multi-segment trick) and git defaults `core.symlinks=false` at checkout (committed mode-120000 entries become text files, not real symlinks).
Details

The asymmetric check at `internal/database/repo_editor.go:601-612`:

```go
targetPath := path.Join(dirPath, upload.Name)
if osx.IsSymlink(targetPath) {                       // ← LEAF-ONLY
    return errors.Newf("cannot overwrite symbolic link: %s", upload.Name)
}
if err = iox.CopyFile(tmpPath, targetPath); err != nil { ... }
```

vs. `UpdateRepoFile`'s correct walker at `internal/database/repo_editor.go:163`:

```go
if hasSymlinkInPath(localPath, opts.OldTreeName) || hasSymlinkInPath(localPath, opts.NewTreeName) {
    return errors.New("cannot update file with symbolic link in path")
}
```

`hasSymlinkInPath` (`internal/database/repo_editor.go:120-131`) lstats every component; `osx.IsSymlink` (`internal/osx/osx.go:35-41`) is `os.Lstat` mode-bit on the leaf — fine inside the loop, wrong as a single call.

Multi-segment `upload.Name` reaches the loop because: (1) `c.Req.FormFile("file")` returns `*multipart.FileHeader` whose `Filename` is `filepath.Base(filename)` — Linux only treats `/` as separator, so backslashes are preserved; (2) `NewUpload` calls `pathx.Clean` (`internal/pathx/pathx.go:13-16`) which does `strings.ReplaceAll(p, "\\", "/")` — converting backslashes to forward slashes; (3) `upload.Name = "evil/foo"` is persisted and joined into `path.Join(dirPath, upload.Name)`. `iox.CopyFile` at `internal/iox/iox.go:24` uses `os.Create(dst)` = `OpenFile(dst, O_RDWR|O_CREATE|O_TRUNC, ...)` — no `O_NOFOLLOW`, kernel f

REFS:
- WEB https://github.com/gogs/gogs/security/advisories/GHSA-89mr-xqfv-758m
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-52811
- WEB https://github.com/gogs/gogs/pull/8332
- WEB https://github.com/gogs/gogs/commit/04cb8afbb01d855454e59977a1cdbf522ea1db31
- PACKAGE https://github.com/gogs/gogs
- WEB https://github.com/gogs/gogs/releases/tag/v0.14.3

INTRO_LOG:
36d56d5525972d9a87a136a490469a997efdcd66
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-02-16T13:25:19-05:00
all: rename packages ending with "util" to end with "x" (#8182)

Co-authored-by: JSS <jss@unknwon.dev>
Co-authored-by: Claude Opus 4.6 <noreply@anthropic.com>


INTRO_STAT:
 cmd/gogs/backup.go                                 |   6 +-
 cmd/gogs/hook.go                                   |   8 +-
 cmd/gogs/import.go                                 |   8 +-
 cmd/gogs/restore.go                                |  20 +--
 cmd/gogs/web.go                                    |   6 +-
 internal/app/metrics.go                            |   4 +-
 internal/auth/auth.go                              |   6 +-
 internal/{authutil => authx}/basic.go              |   2 +-
 internal/{authutil => authx}/basic_test.go         |   2 +-
 internal/conf/computed_test.go                     |  14 +-
 internal/conf/conf.go                              |  10 +-
 internal/conf/conf_test.go                         |   4 +-
 internal/conf/utils.go                             |   4 +-
 internal/context/api.go                            |   4 +-
 internal/context/context.go                        |   4 +-
 internal/context/go_get.go                         |   4 +-
 internal/context/notice.go                         |   4 +-
 internal/context/repo.go                           |   4 +-
 internal/{cryptoutil => cryptox}/aes.go            |   2 +-
 internal/{cryptoutil => cryptox}/aes_test.go       |   2 +-
 internal/{cryptoutil => cryptox}/md5.go            |   2 +-
 internal/{cryptoutil => cryptox}/md5_test.go       |   2 +-
 internal/{cryptoutil => cryptox}/sha.go            |   2 +-
 internal/{cryptoutil => cryptox}/sha_test.go       |   2 +-
 internal/database/access_tokens.go

INTRO_DIFF_OVERLAP:
diff --git a/internal/database/repo_editor.go b/internal/database/repo_editor.go
index 7346f8e7..7a4c9e20 100644
--- a/internal/database/repo_editor.go
+++ b/internal/database/repo_editor.go
@@ -18,11 +18,11 @@ import (
 	"github.com/gogs/git-module"
 
 	"gogs.io/gogs/internal/conf"
-	"gogs.io/gogs/internal/cryptoutil"
-	"gogs.io/gogs/internal/gitutil"
-	"gogs.io/gogs/internal/ioutil"
-	"gogs.io/gogs/internal/osutil"
-	"gogs.io/gogs/internal/pathutil"
+	"gogs.io/gogs/internal/cryptox"
+	"gogs.io/gogs/internal/gitx"
+	"gogs.io/gogs/internal/iox"
+	"gogs.io/gogs/internal/osx"
+	"gogs.io/gogs/internal/pathx"
 	"gogs.io/gogs/internal/process"
 )
 
@@ -68,7 +68,7 @@ func ComposeHookEnvs(opts ComposeHookEnvsOptions) []string {
 		EnvAuthUserName + "=" + opts.AuthUser.Name,
 		EnvAuthUserEmail + "=" + opts.AuthUser.Email,
 		EnvRepoOwnerName + "=" + opts.OwnerName,
-		EnvRepoOwnerSaltMd5 + "=" + cryptoutil.MD5(opts.OwnerSalt),
+		EnvRepoOwnerSaltMd5 + "=" + cryptox.MD5(opts.OwnerSalt),
 		EnvRepoID + "=" + strconv.FormatInt(opts.RepoID, 10),
 		EnvRepoName + "=" + opts.RepoName,
 		EnvRepoCustomHooksPath + "=" + filepath.Join(opts.RepoPath, "custom_hooks"),
@@ -86,7 +86,7 @@ func ComposeHookEnvs(opts ComposeHookEnvsOptions) []string {
 // discardLocalRepoBranchChanges discards local commits/changes of
 // given branch to make sure it is even to remote branch.
 func discardLocalRepoBranchChanges(localPath, branch string) error {
-	if !osutil.Exist(localPath) {
+	if !osx.Exist(localPath) {
 		return nil
 	}
 
@@ -123,7 +123,7 @@ func hasSymlinkInPath(base, relPath string) bool {
 	parts := strings.Split(filepath.ToSlash(relPath), "/")
 	for i := range parts {
 		filePath := path.Join(append([]string{base}, parts[:i+1]...)...)
-		if osutil.IsSymlink(filePath) {
+		if osx.IsSymlink(filePath) {
 			return true
 		}
 	}
@@ -189,7 +189,7 @@ func (r *Repository) UpdateRepoFile(doer *User, opts UpdateRepoFileOptions) erro
 	newFilePath := path.Join(localPath, opts.NewTreeName)
 
 	// Prompt the user if the meant-to-be new file already exists.
-	if osutil.Exist(newFilePath) && opts.IsNewFile {
+	if osx.Exist(newFilePath) && opts.IsNewFile {
 		return ErrRepoFileAlreadyExist{newFilePath}
 	}
 
@@ -197,7 +197,7 @@ func (r *Repository) UpdateRepoFile(doer *User, opts UpdateRepoFileOptions) erro
 		return errors.Wrapf(err, "create parent directories of %q", newFilePath)
 	}
 
-	if osutil.IsFile(oldFilePath) && opts.OldTreeName != opts.NewTreeName {
+	if osx.IsFile(oldFilePath) && opts.OldTreeName != opts.NewTreeName {
 		if err := git.Move(localPath, opts.OldTreeName, opts.NewTreeName); err != nil {
 			return errors.Wrapf(err, "git mv %q %q", opts.OldTreeName, opts.NewTreeName)
 		}
@@ -244,7 +244,7 @@ func (r *Repository) UpdateRepoFile(doer *User, opts UpdateRepoFileOptions) erro
 }
 
 // GetDiffPreview produces and returns diff result of a file which is not yet committed.
-func (r *Repository) GetDiffPreview(branch, treePath, content string) (*gitutil.Diff, error) {
+func (r *Repository) GetDiffPreview(branch, treePath, content string) (*gitx.Diff, error) {
 	// 🚨 SECURITY: Prevent uploading files into the ".git" directory.
 	if isRepositoryGitPath(treePath) {
 		return nil, errors.Errorf("bad tree path %q", treePath)
@@ -291,7 +291,7 @@ func (r *Repository) GetDiffPreview(branch, treePath, content string) (*gitutil.
 	pid := process.Add(fmt.Sprintf("GetDiffPreview [repo_path: %s]", r.RepoPath()), cmd)
 	defer process.Remove(pid)
 
-	diff, err := gitutil.ParseDiff(stdout, conf.Git.MaxDiffFiles, conf.Git.MaxDiffLines, conf.Git.MaxDiffLineChars)
+	diff, err := gitx.ParseDiff(stdout, conf.Git.MaxDiffFiles, conf.Git.MaxDiffLines, conf.Git.MaxDiffLineChars)
 	if err != nil {
 		return nil, errors.Newf("parse diff: %v", err)
 	}
@@ -416,7 +416,7 @@ func (upload *Upload) LocalPath() string {
 // NewUpload creates a new upload object.
 func NewUpload(name string, buf []byte, file multipart.File) (_ *Upload, err error) {
 	// 🚨 SECURITY: Prevent path t

FIX_LOG:
04cb8afbb01d855454e59977a1cdbf522ea1db31
ᴊᴏᴇ ᴄʜᴇɴ <jc@unknwon.io>
2026-06-06T22:46:48-04:00
security: walk full upload path for symlinks (#8332)




FIX_STAT:
 CHANGELOG.md                     | 1 +
 internal/database/repo_editor.go | 6 +++---
 2 files changed, 4 insertions(+), 3 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/internal/database/repo_editor.go b/internal/database/repo_editor.go
index 7a4c9e20..ac289db2 100644
--- a/internal/database/repo_editor.go
+++ b/internal/database/repo_editor.go
@@ -601,9 +601,9 @@ func (r *Repository) UploadRepoFiles(doer *User, opts UploadRepoFileOptions) err
 
 		targetPath := path.Join(dirPath, upload.Name)
 
-		// 🚨 SECURITY: Prevent updating files in surprising place, check if the target
-		// is a symlink.
-		if osx.IsSymlink(targetPath) {
+		// 🚨 SECURITY: Prevent touching files in surprising places, reject operations
+		// that involve symlinks.
+		if hasSymlinkInPath(localPath, path.Join(opts.TreePath, upload.Name)) {
 			return errors.Newf("cannot overwrite symbolic link: %s", upload.Name)
 		}
 


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []