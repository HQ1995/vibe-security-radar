# GHSA-FJ8V-HJWV-QM88

repo: go-gitea/gitea

summary: Gitea: Fork-PR Actions task can read a third private repository via the collaborative-owner branch (missing fork-PR guard)

aliases: ['CVE-2026-58416']

severity: MODERATE

evidence: blame blamed_lines=1 files=['models/perm/access/repo_permission.go']

intro: 45809c8f5479e167ac79221c7480b2d7b94ff03d

intro_subject: feat: Add configurable permissions for Actions automatic tokens (#36173)

intro_date: 2026-03-21T23:39:47+01:00

fix: 1d43b736b5a16c5f80cfdcd9a9448a9c983ddaa0

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "gitea.dev"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "1.27.0"
          }
        ]
      }
    ]
  }
]

DETAILS:
### Summary

`GetActionsUserRepoPermission` (`models/perm/access/repo_permission.go`) decides whether an Actions
task token may access a target repo. Its cross-repo branches each enforce a fork-PR discriminator —
**except the collaborative-owner branch**, which is missing the `!task.IsForkPullRequest` guard that
its sibling has. As a result, when a private repo **B** lists owner **A** as a collaborative owner, an
**attacker-controlled fork pull-request** workflow whose base repo is owned by A is granted code-read
on B — i.e. the fork's YAML can clone a third private repository it has no rights to.

### Details

```go
// models/perm/access/repo_permission.go (v1.26.2), in GetActionsUserRepoPermission
if checkSameOwnerCrossRepoAccess(ctx, taskRepo, repo, task.IsForkPullRequest) { // passes isForkPR -> denies forks
    return maxPerm, nil
}
...
if taskRepo.IsPrivate {                                   // <-- NO IsForkPullRequest check here
    actionsUnit := repo.MustGetUnit(ctx, unit.TypeActions)
    if actionsUnit.ActionsConfig().IsCollaborativeOwner(taskRepo.OwnerID) {
        return maxPerm, nil                              // grants code-read to target repo B
    }
}
```

The sibling same-owner path correctly denies fork PRs:

```go
func checkSameOwnerCrossRepoAccess(ctx, taskRepo, targetRepo, isForkPR bool) bool {
    if isForkPR {
        return false // Fork PRs are never allowed cross-repo access to other private repositories.
    }
    ...
}
```

`taskRepo` = the repo whose workflow is running (the PR's base repo A); `repo` = the target being
cloned (B). `IsCollaborativeOwner(taskRepo.OwnerID)` asks "does target B's Actions config trust A's
owner for cross-repo read?" When B trusts ownerA, the branch returns `maxPerm` (code-read) **even when
`task.IsForkPullRequest` is true** — i.e. when the executing YAML is the fork's, not A's.

Every sibling enforces the fork-PR discriminator; except for this branch:
`checkSameOwnerCrossRepoAccess` denies forks; `ComputeTaskTokenPermissions`
(`models/actions/token_permissions.go`) only clamps the token *ceiling* to read-only for fork/cross-repo
(its own comment notes the access *decision* is in `GetActionsUserRepoPermission`, so it does not
neutralize the gap — it just makes the leak read-only); secrets (`models/secret/secret.go`) and the
approval gate (`services/actions/notifier_helper.go`) both correctly key on `IsForkPullRequest`.

**Reachability** — the runner clones target repo B over git-HTTP with the task 

REFS:
- WEB https://github.com/go-gitea/gitea/security/advisories/GHSA-fj8v-hjwv-qm88
- WEB https://github.com/go-gitea/gitea/pull/38214
- WEB https://github.com/go-gitea/gitea/commit/1d43b736b5a16c5f80cfdcd9a9448a9c983ddaa0
- PACKAGE https://github.com/go-gitea/gitea
- WEB https://github.com/go-gitea/gitea/releases/tag/v1.27.0

INTRO_LOG:
45809c8f5479e167ac79221c7480b2d7b94ff03d
Excellencedev <ademiluyisuccessandexcellence@gmail.com>
2026-03-21T15:39:47-07:00
feat: Add configurable permissions for Actions automatic tokens (#36173)

## Overview

This PR introduces granular permission controls for Gitea Actions tokens
(`GITEA_TOKEN`), aligning Gitea's security model with GitHub Actions
standards while maintaining compatibility with Gitea's unique repository
unit system.

It addresses the need for finer access control by allowing
administrators and repository owners to define default token
permissions, set maximum permission ceilings, and control
cross-repository access within organizations.

## Key Features

### 1. Granular Token Permissions

- **Standard Keyword Support**: Implements support for the
`permissions:` keyword in workflow and job YAML files (e.g., `contents:
read`, `issues: write`).
- **Permission Modes**:
- **Permissive**: Default write access for most units (backwards
compatible).
- **Restricted**: Default read-only access for `contents` and
`packages`, with no access to other units.
- ~~**Custom**: Allows defining specific default levels for each unit
type (Code, Issues, PRs, Packages, etc.).~~**EDIT removed UI was
confusing**
- **Clamping Logic**: Workflow-defined permissions are automatically
"clamped" by repository or organization-level maximum settings.
Workflows cannot escalate their own permissions beyond these limits.

### 2. Organization & Repository Settings

- **Settings UI**: Added new settings pages at both Organization and
Repository levels to manage Actions token defaults and maximums.
- **Inheritance**: Repositories can be configured to "Follow
organization-level configuration," simplifying management across large
organizations.
- **Cross-Repository Access**: Added a policy to control whether Actions
workflows can access other repositories or packages within the same
organization. This can be set to "None," "All," or restricted to a
"Selected" list of repositories.

### 3. Security Hardening

- **Fork Pull Request Protection**: Tokens for workflows triggered by
pull requests from forks are strictly enforced as read-only, regardless
of repository settings.
- ~~**Package Access**: Actions tokens can now only access packages
explicitly linked to a repository, with cross-repo access governed by
the organization's security policy.~~ **EDIT removed
https://github.com/go-gitea/gitea/pull/36173#issuecomment-3873675346**
- **Git Hook Integration**: Propagates Actions Tas

INTRO_STAT:
 cmd/hook.go                                        |   4 +-
 models/actions/config.go                           |  74 ++++
 models/actions/run_job.go                          |   5 +
 models/actions/token_permissions.go                |  60 +++
 models/migrations/migrations.go                    |   1 +
 models/migrations/v1_26/v328.go                    |  16 +
 models/perm/access/actions_repo_permission_test.go | 155 ++++++++
 models/perm/access/repo_permission.go              | 115 +++++-
 models/repo/pull_request_default_test.go           |   2 +-
 models/repo/repo_list.go                           |   8 +
 models/repo/repo_unit.go                           |  67 +---
 models/repo/repo_unit_actions.go                   | 153 ++++++++
 models/repo/repo_unit_test.go                      |  76 +++-
 models/user/setting.go                             |  43 ++
 models/user/setting_options.go                     |   2 +
 modules/private/hook.go                            |   2 +-
 modules/repository/env.go                          |  70 ++--
 modules/util/util.go                               |  15 +
 options/locale/locale_en-US.json                   |  22 +-
 routers/private/hook_pre_receive.go                |  21 +-
 routers/web/admin/runners.go                       |  13 -
 routers/web/misc/misc.go                           |   6 +
 routers/web/org/setting/runners.go                 |  12 -
 routers/web/repo/actions/view.go                   |   2 +-
 routers/web/repo/gi

INTRO_DIFF_OVERLAP:
diff --git a/models/perm/access/repo_permission.go b/models/perm/access/repo_permission.go
index 3235d8320..622fa5d99 100644
--- a/models/perm/access/repo_permission.go
+++ b/models/perm/access/repo_permission.go
@@ -7,6 +7,7 @@ import (
 	"context"
 	"errors"
 	"fmt"
+	"maps"
 	"slices"
 	"strings"
 
@@ -258,6 +259,23 @@ func finalProcessRepoUnitPermission(user *user_model.User, perm *Permission) {
 	}
 }
 
+func checkSameOwnerCrossRepoAccess(ctx context.Context, taskRepo, targetRepo *repo_model.Repository, isForkPR bool) bool {
+	if isForkPR {
+		// Fork PRs are never allowed cross-repo access to other private repositories of the owner.
+		return false
+	}
+	if taskRepo.OwnerID != targetRepo.OwnerID {
+		return false
+	}
+	ownerCfg, err := actions_model.GetOwnerActionsConfig(ctx, targetRepo.OwnerID)
+	if err != nil {
+		log.Error("GetOwnerActionsConfig: %v", err)
+		return false
+	}
+
+	return slices.Contains(ownerCfg.AllowedCrossRepoIDs, targetRepo.ID)
+}
+
 // GetActionsUserRepoPermission returns the actions user permissions to the repository
 func GetActionsUserRepoPermission(ctx context.Context, repo *repo_model.Repository, actionsUser *user_model.User, taskID int64) (perm Permission, err error) {
 	if actionsUser.ID != user_model.ActionsUserID {
@@ -268,37 +286,96 @@ func GetActionsUserRepoPermission(ctx context.Context, repo *repo_model.Reposito
 		return perm, err
 	}
 
-	var accessMode perm_model.AccessMode
+	if err := task.LoadJob(ctx); err != nil {
+		return perm, err
+	}
+
+	var taskRepo *repo_model.Repository
 	if task.RepoID != repo.ID {
-		taskRepo, exist, err := db.GetByID[repo_model.Repository](ctx, task.RepoID)
-		if err != nil || !exist {
+		if err := task.Job.LoadRepo(ctx); err != nil {
 			return perm, err
 		}
-		actionsCfg := repo.MustGetUnit(ctx, unit.TypeActions).ActionsConfig()
-		if !actionsCfg.IsCollaborativeOwner(taskRepo.OwnerID) || !taskRepo.IsPrivate {
-			// The task repo can access the current repo only if the task repo is private and
-			// the owner of the task repo is a collaborative owner of the current repo.
-			// FIXME should owner's visibility also be considered here?
-
-			// check permission like simple user but limit to read-only
-			perm, err = GetUserRepoPermission(ctx, repo, user_model.NewActionsUser())
+		taskRepo = task.Job.Repo
+	} else {
+		taskRepo = repo
+	}
+
+	// Compute effective permissions for this task against the target repo
+	effectivePerms, err := actions_model.ComputeTaskTokenPermissions(ctx, task, repo)
+	if err != nil {
+		return perm, err
+	}
+	if task.RepoID != repo.ID {
+		// Cross-repo access must also respect the target repo's permission ceiling.
+		targetRepoActionsCfg := repo.MustGetUnit(ctx, unit.TypeActions).ActionsConfig()
+		if targetRepoActionsCfg.OverrideOwnerConfig {
+			effectivePerms = targetRepoActionsCfg.ClampPermissions(effectivePerms)
+		} else {
+			targetRepoOwnerActionsCfg, err := actions_model.GetOwnerActionsConfig(ctx, repo.OwnerID)
 			if err != nil {
 				return perm, err
 			}
-			perm.AccessMode = min(perm.AccessMode, perm_model.AccessModeRead)
-			return perm, nil
+			effectivePerms = targetRepoOwnerActionsCfg.ClampPermissions(effectivePerms)
 		}
-		accessMode = perm_model.AccessModeRead
-	} else if task.IsForkPullRequest {
-		accessMode = perm_model.AccessModeRead
-	} else {
-		accessMode = perm_model.AccessModeWrite
 	}
 
 	if err := repo.LoadUnits(ctx); err != nil {
 		return perm, err
 	}
-	perm.SetUnitsWithDefaultAccessMode(repo.Units, accessMode)
+
+	var maxPerm Permission
+
+	// Set up per-unit access modes based on configured permissions
+	maxPerm.units = repo.Units
+	maxPerm.unitsMode = maps.Clone(effectivePerms.UnitAccessModes)
+
+	// Check permission like simple user but limit to read-only (PR #36095)
+	// Enhanced to also grant read-only access if isSameRepo is true and target repository is public
+	botPerm, err := GetUserRepoPermission(ctx, repo, user_model.NewActionsUser())
+	if err != nil {
+		return perm, err
+	}
+

FIX_LOG:
1d43b736b5a16c5f80cfdcd9a9448a9c983ddaa0
bircni <bircni@icloud.com>
2026-06-28T10:25:56+00:00
fix(actions): deny fork-PR cross-repo access via collaborative owner (#38214)

### What

`GetActionsUserRepoPermission` (`models/perm/access/repo_permission.go`)
decides whether an Actions task token may access a target repo. Its
cross-repo branches each enforce a fork-PR discriminator — except the
collaborative-owner branch, which was missing the
`!task.IsForkPullRequest` guard that its sibling
`checkSameOwnerCrossRepoAccess` has.

As a result, when a private repo **B** lists owner **A** as a
collaborative owner, an attacker-controlled fork pull-request workflow
whose base repo is owned by A was granted code-read on B — i.e. the
fork's workflow could clone a third private repository it has no rights
to (read-only confidentiality breach).

### Fix

Add the same fork-PR guard the sibling path already enforces:

```go
if taskRepo.IsPrivate && !task.IsForkPullRequest {
    actionsUnit := repo.MustGetUnit(ctx, unit.TypeActions)
    if actionsUnit.ActionsConfig().IsCollaborativeOwner(taskRepo.OwnerID) {
        return maxPerm, nil
    }
}
```


FIX_STAT:
 models/perm/access/actions_repo_permission_test.go | 34 ++++++++++++++++++++++
 models/perm/access/repo_permission.go              |  4 ++-
 2 files changed, 37 insertions(+), 1 deletion(-)


FIX_DIFF_OVERLAP:
diff --git a/models/perm/access/repo_permission.go b/models/perm/access/repo_permission.go
index 2d53b0699..69d54b902 100644
--- a/models/perm/access/repo_permission.go
+++ b/models/perm/access/repo_permission.go
@@ -369,7 +369,9 @@ func GetActionsUserRepoPermission(ctx context.Context, repo *repo_model.Reposito
 	// 2. The Actions Bot user has been explicitly granted access and repository is private
 	// 3. The repository is public (handled by botPerm above)
 
-	if taskRepo.IsPrivate {
+	// Fork PRs are never allowed cross-repo access to other private repositories,
+	// matching the discriminator enforced by checkSameOwnerCrossRepoAccess above.
+	if taskRepo.IsPrivate && !task.IsForkPullRequest {
 		actionsUnit := repo.MustGetUnit(ctx, unit.TypeActions)
 		if actionsUnit.ActionsConfig().IsCollaborativeOwner(taskRepo.OwnerID) {
 			return maxPerm, nil


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []