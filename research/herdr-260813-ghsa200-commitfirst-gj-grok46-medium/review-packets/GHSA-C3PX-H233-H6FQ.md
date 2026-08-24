# GHSA-C3PX-H233-H6FQ

repo: getarcaneapp/arcane

summary: Arcane Has an Authenticated Arbitrary Host File Read via Docker Compose Include Directives

aliases: ['CVE-2026-47179']

severity: HIGH

evidence: file_history blamed_lines=0 files=['backend/internal/services/project_service.go', 'backend/internal/services/project_service_test.go']

intro: 1174e527f5608b93152783057356058f0efde885

intro_subject: perf: add depth limit and skip list to project directory scanning (#2254)

intro_date: 2026-04-06T17:14:20-07:00

fix: b6cbffabf61dbc3f12a28d3b5830e3c6b7e67daf

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "github.com/getarcaneapp/arcane/backend"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "1.19.4"
          }
        ]
      }
    ],
    "database_specific": {
      "last_known_affected_version_range": "<= 1.19.3"
    }
  }
]

DETAILS:
## Summary

`ProjectService.GetProjectFileContent` returns the contents of any Docker Compose include directive declared in a project's compose file before any path-traversal validation runs. Because `ProjectService.CreateProject` writes attacker-supplied compose content to disk without validating include paths, an authenticated user can create a project whose compose file declares `include: ['../../../../etc/passwd']`, then read the include via the project file API. The result is arbitrary read of any file readable by the Arcane backend process, including `/app/data/arcane.db` (the SQLite database containing every user's password hash and API key), enabling escalation to admin and, via Arcane's Docker control plane, RCE on the host.

## Details

**Root cause #1 — `CreateProject` writes compose content without validation** (`backend/internal/services/project_service.go:1605-1644`):

```go
func (s *ProjectService) CreateProject(ctx context.Context, name, composeContent string, envContent *string, user models.User) (*models.Project, error) {
    // ... directory setup ...
    if err := projects.SaveOrUpdateProjectFiles(projectsDirectory, projectPath, composeContent, envContent); err != nil {
        _ = s.db.WithContext(ctx).Delete(proj).Error
        return nil, fmt.Errorf("failed to save project files: %w", err)
    }
    // ...
}
```

Compare with `UpdateProject` (project_service.go:2494, :2577), which calls `validateComposeContentForUpdate`. That validator (line 2599) loads the compose with `missingIncludeStubResourceLoaderInternal`, which calls `ValidateIncludePathForWrite` (includes.go:139) and rejects includes outside the project directory. `CreateProject` bypasses this entirely, so any malicious `include:` array survives to disk.

**Root cause #2 — `GetProjectFileContent` reads include files before path validation** (`backend/internal/services/project_service.go:831-872`):

```go
includes, parseErr := projects.ParseIncludes(composeFile, envMap, true)
if parseErr == nil {
    for _, inc := range includes {
        if inc.RelativePath == relativePath {
            return project.IncludeFile{
                Path:         inc.Path,
                RelativePath: inc.RelativePath,
                Content:      inc.Content,    // <-- arbitrary file content returned here
            }, nil
        }
    }
}

fullPath := filepath.Join(proj.Path, relativePath)
// ... IsSafeSubdirectory check at line 870 — never reached when include matches ...
```

**Root cau

REFS:
- WEB https://github.com/getarcaneapp/arcane/security/advisories/GHSA-c3px-h233-h6fq
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-47179
- WEB https://github.com/getarcaneapp/arcane/commit/b6cbffabf61dbc3f12a28d3b5830e3c6b7e67daf
- PACKAGE https://github.com/getarcaneapp/arcane

INTRO_LOG:
1174e527f5608b93152783057356058f0efde885
Michael Kaltner <michael@kaltner.net>
2026-04-07T00:14:20+00:00
perf: add depth limit and skip list to project directory scanning (#2254)

Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
Co-authored-by: Kyle Mendell <ksm@ofkm.us>


INTRO_STAT:
 backend/internal/bootstrap/services_bootstrap.go   |   2 +-
 backend/internal/config/config.go                  |   2 +
 backend/internal/configschema/schema_test.go       |   2 +
 .../internal/services/gitops_sync_service_test.go  |   3 +-
 backend/internal/services/project_service.go       |  83 +--------------
 backend/internal/services/project_service_test.go  |  79 +++++++--------
 backend/internal/services/updater_service_test.go  |   2 +-
 backend/pkg/projects/fs_util.go                    | 111 +++++++++++++++++++++
 backend/pkg/projects/fs_util_test.go               |  50 ++++++++++
 9 files changed, 214 insertions(+), 120 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/backend/internal/services/project_service.go b/backend/internal/services/project_service.go
index a514b757..c0d57ae1 100644
--- a/backend/internal/services/project_service.go
+++ b/backend/internal/services/project_service.go
@@ -10,7 +10,6 @@ import (
 	"maps"
 	"os"
 	"path/filepath"
-	"slices"
 	"strings"
 	"sync"
 	"time"
@@ -20,6 +19,7 @@ import (
 	composetypes "github.com/compose-spec/compose-go/v2/types"
 	"github.com/docker/compose/v5/pkg/api"
 	"github.com/getarcaneapp/arcane/backend/internal/common"
+	"github.com/getarcaneapp/arcane/backend/internal/config"
 	"github.com/getarcaneapp/arcane/backend/internal/database"
 	"github.com/getarcaneapp/arcane/backend/internal/models"
 	dockerutil "github.com/getarcaneapp/arcane/backend/pkg/dockerutil"
@@ -44,12 +44,13 @@ type ProjectService struct {
 	imageService    *ImageService
 	dockerService   *DockerClientService
 	buildService    *BuildService
+	config          *config.Config
 
 	composeNameCacheMu  sync.RWMutex
 	composeNameToProjID map[string]string
 }
 
-func NewProjectService(db *database.DB, settingsService *SettingsService, eventService *EventService, imageService *ImageService, dockerService *DockerClientService, buildService *BuildService) *ProjectService {
+func NewProjectService(db *database.DB, settingsService *SettingsService, eventService *EventService, imageService *ImageService, dockerService *DockerClientService, buildService *BuildService, cfg *config.Config) *ProjectService {
 	return &ProjectService{
 		db:              db,
 		settingsService: settingsService,
@@ -57,6 +58,7 @@ func NewProjectService(db *database.DB, settingsService *SettingsService, eventS
 		imageService:    imageService,
 		dockerService:   dockerService,
 		buildService:    buildService,
+		config:          cfg,
 	}
 }
 
@@ -716,18 +718,7 @@ func (s *ProjectService) enrichWithDirectoryFiles(ctx context.Context, projectPa
 		shownFiles[inc.RelativePath] = true
 	}
 
-	var dirFiles []project.IncludeFile
-
-	root, err := os.OpenRoot(projectPath)
-	if err != nil {
-		slog.WarnContext(ctx, "Failed to open project root for directory scan", "error", err, "path", projectPath)
-		resp.DirectoryFiles = dirFiles
-		return
-	}
-	defer func() { _ = root.Close() }()
-
-	err = s.collectDirectoryFiles(root, ".", projectPath, shownFiles, &dirFiles)
-
+	dirFiles, err := projects.ReadProjectDirectoryFiles(projectPath, shownFiles, s.config.ProjectScanMaxDepth, s.config.ProjectScanSkipDirs)
 	if err != nil {
 		slog.WarnContext(ctx, "Failed to scan project directory files", "error", err, "path", projectPath)
 	}
@@ -735,70 +726,6 @@ func (s *ProjectService) enrichWithDirectoryFiles(ctx context.Context, projectPa
 	resp.DirectoryFiles = dirFiles
 }
 
-func (s *ProjectService) collectDirectoryFiles(
-	root *os.Root,
-	relDir string,
-	projectPath string,
-	shownFiles map[string]bool,
-	dirFiles *[]project.IncludeFile,
-) error {
-	dir, err := root.Open(relDir)
-	if err != nil {
-		return err
-	}
-	defer func() { _ = dir.Close() }()
-
-	entries, err := dir.ReadDir(-1)
-	if err != nil {
-		return err
-	}
-
-	for _, entry := range entries {
-		relPath := entry.Name()
-		if relDir != "." {
-			relPath = filepath.Join(relDir, entry.Name())
-		}
-		if entry.Type()&os.ModeSymlink != 0 {
-			continue
-		}
-		if entry.IsDir() {
-			if entry.Name() == ".git" {
-				continue
-			}
-			if err := s.collectDirectoryFiles(root, relPath, projectPath, shownFiles, dirFiles); err != nil {
-				slog.Debug("Skipping unreadable project subdirectory", "relativePath", relPath, "error", err)
-			}
-			continue
-		}
-		if shownFiles[relPath] {
-			continue
-		}
-
-		info, err := entry.Info()
-		if err != nil || info.Size() > 1024*1024 {
-			continue
-		}
-
-		content, err := root.ReadFile(relPath)
-		if err != nil || isBinaryProjectFileContent(content) {
-			continue
-		}
-
-		*dirFiles = append(*dirFiles, project.IncludeFile{
-			Path:         filepath.Join(projectPath, relPath),
-			RelativePath: relPath,
-			Co

FIX_LOG:
b6cbffabf61dbc3f12a28d3b5830e3c6b7e67daf
Kyle Mendell <ksm@ofkm.us>
2026-05-17T13:32:54-05:00
fix: block unsafe compose include file reads (#2630)




FIX_STAT:
 backend/internal/services/project_service.go      |  91 +++++++++-
 backend/internal/services/project_service_test.go | 209 ++++++++++++++++++++++
 backend/pkg/projects/includes.go                  | 110 +++++++++---
 backend/pkg/projects/includes_test.go             |  26 +++
 4 files changed, 402 insertions(+), 34 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/backend/internal/services/project_service.go b/backend/internal/services/project_service.go
index bc1578c5..e83d1ec5 100644
--- a/backend/internal/services/project_service.go
+++ b/backend/internal/services/project_service.go
@@ -1039,16 +1039,16 @@ func (s *ProjectService) GetProjectFileContent(ctx context.Context, projectID, r
 		envLoader := projects.NewEnvLoader(projectsDirectory, filepath.Dir(composeFile), utils.BoolOrDefault(cfg.AutoInjectEnv.Value, false))
 		envMap, _, _ := envLoader.LoadEnvironment(ctx)
 
-		includes, parseErr := projects.ParseIncludes(composeFile, envMap, true)
+		includes, parseErr := projects.ParseIncludes(composeFile, envMap, false)
 		if parseErr == nil {
 			for _, inc := range includes {
-				if inc.RelativePath == relativePath {
-					return project.IncludeFile{
-						Path:         inc.Path,
-						RelativePath: inc.RelativePath,
-						Content:      inc.Content,
-					}, nil
+				if inc.RelativePath != relativePath {
+					continue
+				}
+				if !projects.IsSafeSubdirectory(proj.Path, inc.Path) {
+					return project.IncludeFile{}, &common.ProjectFileForbiddenError{Err: fmt.Errorf("file path is outside project directory")}
 				}
+				return readProjectIncludeFileContentInternal(proj.Path, inc)
 			}
 		}
 	}
@@ -1098,6 +1098,60 @@ func (s *ProjectService) GetProjectFileContent(ctx context.Context, projectID, r
 	}, nil
 }
 
+func readProjectIncludeFileContentInternal(projectPath string, inc projects.IncludeFile) (project.IncludeFile, error) {
+	validatedPath, err := projects.ValidateIncludePathForWrite(projectPath, inc.Path)
+	if err != nil {
+		return project.IncludeFile{}, &common.ProjectFileForbiddenError{Err: fmt.Errorf("file path is outside project directory")}
+	}
+
+	resolvedProjectPath, err := filepath.EvalSymlinks(projectPath)
+	if err != nil {
+		return project.IncludeFile{}, fmt.Errorf("failed to resolve project path: %w", err)
+	}
+	resolvedPath, err := filepath.EvalSymlinks(validatedPath)
+	if err != nil {
+		if os.IsNotExist(err) {
+			return project.IncludeFile{
+				Path:         validatedPath,
+				RelativePath: inc.RelativePath,
+				Content:      "# This file will be created when you save changes\nservices:\n",
+			}, nil
+		}
+		return project.IncludeFile{}, fmt.Errorf("failed to resolve include file: %w", err)
+	}
+	if !projects.IsSafeSubdirectory(resolvedProjectPath, resolvedPath) {
+		return project.IncludeFile{}, &common.ProjectFileForbiddenError{Err: fmt.Errorf("file path is outside project directory")}
+	}
+
+	info, err := os.Stat(resolvedPath)
+	if err != nil {
+		if os.IsNotExist(err) {
+			return project.IncludeFile{}, &common.ProjectFileNotFoundError{}
+		}
+		return project.IncludeFile{}, fmt.Errorf("failed to stat include file: %w", err)
+	}
+	if info.IsDir() {
+		return project.IncludeFile{}, &common.ProjectFileBadRequestError{Err: fmt.Errorf("path refers to a directory")}
+	}
+
+	content, err := os.ReadFile(resolvedPath)
+	if err != nil {
+		if os.IsNotExist(err) {
+			return project.IncludeFile{}, &common.ProjectFileNotFoundError{}
+		}
+		return project.IncludeFile{}, fmt.Errorf("failed to read include file: %w", err)
+	}
+	if projects.IsBinaryProjectFileContent(content) {
+		return project.IncludeFile{}, &common.ProjectFileBadRequestError{Err: fmt.Errorf("binary files are not supported")}
+	}
+
+	return project.IncludeFile{
+		Path:         resolvedPath,
+		RelativePath: inc.RelativePath,
+		Content:      string(content),
+	}, nil
+}
+
 func (s *ProjectService) enrichWithIncludeFiles(ctx context.Context, composeFile string, resp *project.Details) {
 	if strings.TrimSpace(composeFile) == "" {
 		return
@@ -1922,6 +1976,12 @@ func (s *ProjectService) CreateProject(ctx context.Context, name, composeContent
 		return nil, fmt.Errorf("failed to create project: %w", err)
 	}
 
+	if err := s.validateComposeContentForUpdate(ctx, projectsDirectory, projectPath, name, composeContent, envContent); err != nil {
+		_ = s.db.WithContext(ctx).Delete(proj)

intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []