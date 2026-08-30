# GHSA-4FXP-2M36-QV64 original-introducer re-review

## Result

The missing `ir_chain.original_sha` can be closed. The atomic bug-introducing
commit is:

| Field | Result |
|---|---|
| Repository | `roskus/prospero-flow-crm` |
| Advisory | `GHSA-4FXP-2M36-QV64` / `CVE-2026-59233` |
| Atomic original SHA | `b0fa7751b112038cb01a0fac3b2ab841f2f7f7cc` |
| Immediate parent | `3a2916b5724679e3c1fac3b77c59c780b2e6ff74` |
| Parent absence | **Verified** |
| Mainline squash carrier | `ac1919b745e0fd22973853954e8c92b1393f0920` |
| Author | `Antonio <elguitarraverde@hotmail.com>` |
| Committer | `Antonio <elguitarraverde@hotmail.com>` |
| Original author kind | `HUMAN` |
| AI marker on atomic BIC | **Absent** |
| Confidence | **HIGH** |
| Remaining gap | None for original SHA, parent, or authorship |

This refines, rather than contradicts, the CNA's mainline attribution. The CNA
names squash commit `ac1919b7` as the endpoint's introduction. GitHub still
exposes the two commits from PR #169, so the squash can be decomposed. The first
PR member, `b0fa7751`, writes the vulnerable route and sink; the second,
`e6c0016d`, is a formatter commit and does not change either relevant file.

Primary sources:

- [GitHub advisory](https://github.com/advisories/GHSA-4FXP-2M36-QV64)
- [Secur0 CNA record](https://secur0.com/en/cna/cve-list/cve-2026-59233-missing-authorization-in-prospero-flow-crm-permission-endpoint)
- [PR #169](https://github.com/Roskus/prospero-flow-crm/pull/169)
- [Atomic BIC `b0fa7751`](https://github.com/Roskus/prospero-flow-crm/commit/b0fa7751b112038cb01a0fac3b2ab841f2f7f7cc)
- [Mainline squash `ac1919b7`](https://github.com/Roskus/prospero-flow-crm/commit/ac1919b745e0fd22973853954e8c92b1393f0920)
- [Attempted remediation `52e5e193`](https://github.com/Roskus/prospero-flow-crm/commit/52e5e1938ba7db9191ab75fc6f81d92cf667dd4d)
- [Direct fix `86a7d655`](https://github.com/Roskus/prospero-flow-crm/commit/86a7d6557bd111518a221f4575ad6e36087e19d3)

## Vulnerability mechanism and sink

The CNA record identifies `POST /permission` and
`PermissionSaveController::save()` as the affected path. User-controlled
`roles[<role_id>][]` data reaches
`Role::findById($role_id)->syncPermissions($permissions)` without a role or
permission authorization decision. This lets a low-privileged authenticated
user rewrite any role's permissions, including their own.

The atomic BIC creates the controller at
`app/Http/Controllers/Permission/PermissionSaveController.php`:

```php
12 class PermissionSaveController extends Controller
14     public function save(Request $request): RedirectResponse
16         $roles = $request->roles;
18         foreach ($roles as $role_id => $permissions) {
19             Role::findById($role_id)->syncPermissions($permissions);
```

It simultaneously exposes the sink in `routes/web.php`:

```php
181 Route::get('/permission', [PermissionIndexController::class, 'index']);
182 Route::post('/permission', [PermissionSaveController::class, 'save']);
```

Neither route has `can`, `permission`, or `auth` middleware. The new controller
extends the bare `Controller`; that base class registers no middleware. At this
revision the global `web` group contains cookies, session, CSRF, bindings, and
localization, but not `auth`. `MainController`, by contrast, registers
`$this->middleware('auth')`. Thus the original endpoint lacked authentication
as well as authorization. Hiding the dashboard link behind `@role('SuperAdmin')`
did not protect the directly callable route.

## Atomic BIC and immediate-parent absence

The complete local clone was refreshed from the first-party remote and the
deleted PR head was fetched through GitHub's retained pull ref:

```text
$ git rev-parse --is-shallow-repository
false
$ git fetch origin refs/pull/169/head:refs/research/pr-169-head
$ git fsck --connectivity-only --no-dangling
# exit 0
```

Pickaxe on the PR lineage returns only the feature commit for the sink:

```text
$ git log -S'syncPermissions' refs/research/pr-169-head -- \
    app/Http/Controllers/Permission/PermissionSaveController.php
b0fa7751b112038cb01a0fac3b2ab841f2f7f7cc ... feat(permission): add permissions dashboard
```

The raw BIC object has exactly one parent:

```text
commit: b0fa7751b112038cb01a0fac3b2ab841f2f7f7cc
parent: 3a2916b5724679e3c1fac3b77c59c780b2e6ff74
tree:   65be5764402d52bb17a960de19a572058df009cd
```

Direct parent-tree checks establish absence:

```text
$ git diff --name-status 3a2916b5724679e3c1fac3b77c59c780b2e6ff74 \
    b0fa7751b112038cb01a0fac3b2ab841f2f7f7cc -- \
    app/Http/Controllers/Permission/PermissionSaveController.php routes/web.php
A  app/Http/Controllers/Permission/PermissionSaveController.php
M  routes/web.php

$ git ls-tree -r --name-only 3a2916b5724679e3c1fac3b77c59c780b2e6ff74 -- \
    app/Http/Controllers/Permission/PermissionSaveController.php
# no output

$ git grep -n -E 'PermissionSaveController|syncPermissions|Route::post\(.?/permission' \
    3a2916b5724679e3c1fac3b77c59c780b2e6ff74 -- routes app/Http/Controllers
# no output
```

Therefore the handler, public POST route, and dangerous synchronization sink
are all absent in the immediate parent and first appear together in
`b0fa7751`.

## Squash decomposition

[PR #169](https://github.com/Roskus/prospero-flow-crm/pull/169) records two
public member commits before GitHub merged squash `ac1919b7`:

1. `b0fa7751b112038cb01a0fac3b2ab841f2f7f7cc` — creates the permission
   dashboard, route, controller, and vulnerable sink.
2. `e6c0016d94c9775defeac4acfe5fa44c0ffc4fb5` — `PHP Linting (Pint)`.

`git diff b0fa7751 e6c0016d --` over the controller and route is empty. The PR
head and mainline squash have the same complete tree:

```text
e6c0016d^{tree} = b5413915c08612442d106664734608e7f495e461
ac1919b7^{tree} = b5413915c08612442d106664734608e7f495e461
```

Consequently `ac1919b7` is the mainline carrier, not the smallest available
public BIC. The causal reconstruction is:

```text
b0fa7751 (atomic first write)
  -> e6c0016d (formatting only)
  -> ac1919b7 (tree-equivalent mainline squash carrier)
  -> 52e5e193 (adds authentication, leaves authorization bypass)
  -> 86a7d655 (requires SuperAdmin and validates role/permission input)
```

## Authorship and AI marker

`git cat-file -p b0fa7751...` gives:

```text
author Antonio <elguitarraverde@hotmail.com> 1679689073 +0100
committer Antonio <elguitarraverde@hotmail.com> 1679689073 +0100

feat(permission): add permissions dashboard
```

The atomic BIC has a human author and committer, a plain one-line message, no
`Co-Authored-By` trailer, no AI-generator trailer, and no bot identity. The AI
marker is therefore `absent`, and the original author kind is `HUMAN`. The
`github-actions[bot]` committer on the later Pint-only commit is not causal and
must not be attributed to the vulnerable lines. Likewise, Claude trailers on
the 2026 attempted remediation/fix do not change original-BIC attribution.

## Advisory, fix, and release cross-check

The GitHub advisory and CNA record describe the same authorization bypass and
identify `86a7d655` as the direct fix. That commit replaces generic `Request`
with `PermissionSaveRequest`; its `authorize()` permits only `SuperAdmin`, and
the controller consumes validated role/permission data.

Mainline carrier `ac1919b7` is an ancestor of attempted remediation `52e5e193`,
which is in turn an ancestor of the direct fix. `version.php` is `2.2.11` in
both the atomic PR tree and the squash tree, `4.4.0` at the attempted
remediation, and `5.2.1` at the direct fix. Mainline carrier `ac1919b7` is
contained by tags `v1.0.0`, `v2.0.1`, and `v4.6.0`, confirming that the flaw
shipped. As the CNA notes, no `v5.2.1` tag exists; the earliest repository tag
containing the fix is `v5.5.3`.

## Recommended `ir_chain` correction

```json
{
  "original_sha": "b0fa7751b112038cb01a0fac3b2ab841f2f7f7cc",
  "original_author_kind": "HUMAN",
  "original_author_name": "Antonio (elguitarraverde)"
}
```

For provenance-capable storage, also retain:

```json
{
  "original_parent": "3a2916b5724679e3c1fac3b77c59c780b2e6ff74",
  "original_parent_absent": true,
  "original_squash_decomposed": true,
  "original_mainline_carrier": "ac1919b745e0fd22973853954e8c92b1393f0920",
  "original_decomposed_shas": [
    "b0fa7751b112038cb01a0fac3b2ab841f2f7f7cc"
  ],
  "original_ai_marker": "absent"
}
```

## Evidence boundary

This closes the repository-history question and supports a human attribution
under the audit protocol's commit-object rule. It does not claim access to the
author's private development environment or prove that no unrecorded tool was
ever used; it establishes that the causal public BIC is human-identified and
contains no explicit AI/bot provenance marker. No canonical ledger or
publication artifact was modified in this re-review.
