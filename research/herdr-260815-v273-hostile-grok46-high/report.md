# Hostile review: GHSA-V273-448J-V4QJ

**REJECT.** Countable PASS remains 0. Packet delta 0. Canonical94 stays **94 HOLD**.

This is an independent hostile review of the hypothesis that atomic commit
`529dd67eeb6b125637623d6a723601f0938d3613` (`Made-with: Cursor`) introduced or
materially scoped-contributed to the `LookupType.Root` path-traversal skip later
closed by `f41c1fc02fe901598f3328118b42b13bc6bc9b04`. The unrecognized-marker
routing packet is a locator only and is not evidence. Worker PASS is proposal
only; this packet emits none. A FAIL in `ai_hunk`, `but_for`, or `fix_reversal`
is terminal REJECT, not ROUTE.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

Network evidence used anonymous public git, GitHub HTML, and npm registry access
only. Credential-bearing environment variables were unset before network
commands and were never printed. No clone was retained.

## Identity (first-party)

GitHub-reviewed GHSA-v273-448j-v4qj on harttle/liquidjs is published, not
withdrawn, CWE-22. Formal alias CVE-2026-39859 is not a second case. Summary:
`renderFile()` / `parseFile()` bypass configured `root` and allow arbitrary
file read. npm `liquidjs` last known affected `<= 10.25.4`, fixed `10.25.5`.
The reporter reproduced on published `liquidjs@10.25.0`. Root cause quotes
`src/parser/parser.ts` calling `loader.lookup(file, LookupType.Root, ...)` and
`src/fs/loader.ts` passing `type !== LookupType.Root` into `candidates()`, so
`LookupType.Root` sets `enforceRoot` false and skips `contains()`. The same
text calls this adjacent to the March 2026 CVE-2026-30952 hardening of
`include` / `render` / `layout`, not a residual of April PR #867. First-party
repo advisory HTML names the same skip form. github-reviewed JSON SHA256
`023dc373f50b6f30503202755c1283426a94a3d6579e719f5880833f7658b9a3`.

identity_gate: PASS.

## Topology and AI marker

`529dd67e` is a single-parent GitHub squash of PR #867 onto
`abc058be0f33d6372cd2216f4945183167abeb25`. Author Yang Jun; committer GitHub.
Subject `fix: use realpath for fs.contains (#867)`. Trailer `Made-with: Cursor`
appears in the squash body because later PR members carried that line. Tree
`1c07d2741651bcf021038890a0e349d28a4cea81` equals `refs/pull/867/head`
`3538864119abdc7e2b82705950c9f3235c5c2235`. Not a merge carrier. Candidate is
a first-parent ancestor of closer `f41c1fc0` and of tags `v10.25.3`,
`v10.25.4`, and `v10.25.5`.

Peeled members, same parent `abc058be`:

1. `cca3da6147fbc59a5a78875015295327a9ee59e9` unmarked `fix: use realpath for
   fs.contains`. Relocates the skip to `const enforceRoot = type !==
   LookupType.Root` and rewrites `fs.contains` to `realpath`. No `Made-with`
   trailer.
2. `b181b08543ed69b081c72fc3ba59f6b5159d9fe9` `Made-with: Cursor`. File-mode
   reset only. `loader.ts` blob unchanged from member 1.
3. `35388641` `Made-with: Cursor`. Swaps `toLiquidAsync` argument order. Does
   not add or remove the skip predicate.

Closer `f41c1fc0` is a single-parent GitHub squash of PR #870 onto `v10.25.4`
peel `db4348507e6aa205ab2ba5e3fa273c40767e6764`. Tree equals
`refs/pull/870/head` `484ba7f07863735af65fc2eed8e51c311298bdba`. The closer
also carries `Made-with: Cursor`. AI-on-fix is not origin.

The 2021 commit `822ba0be0f1cfbedd50376aff8ac49eee71bd48c` (`fix: skip root
check for renderFile()`, Harttle, 2021-10-06) is the first-parent pickaxe hit
that introduced `type !== LookupType.Root`. The closer is the matching removal
hit. The candidate does not appear in that pickaxe.

topology_gate: PASS. Members peeled. Squash tree equals PR head. Authorship is
not transferred from unmarked member 1 onto the squash trailer, and Cursor
member 3 is not treated as skip origin.

## Why the hypothesized pairing fails

Parent `abc058be` already passed `type !== LookupType.Root` into
`candidates()`. Tag `v10.25.0` peel `93c38c7c6d1f3e4a3c64fc5f205cf6bff4be46a6`
uses that same call, loader blob `62c061a1a6b4ccc78ba93eb86657eaf9d8ae01f6`.
npm `liquidjs@10.25.0` tarball SHA256
`0f8859d7cfc72f0daa3da2862c9d9a9ad6889140dec90c7bbe2d7407a7f40c8f` compiles to
`this.candidates(file, dirs, currentFile, type !== LookupType.Root)` with zero
`realpath`. The advisory-tested artifact therefore already has the named skip
and does not contain `529dd67e`.

The squash relocates the same predicate to `const enforceRoot = type !==
LookupType.Root` inside `lookup()` while moving `contains()` onto realpath.
That is a sibling rewrite of the include/layout containment helper, not the
birth of the Root bypass. Reverting `529dd67e` restores the parent skip. The
GHSA path remains.

March first-parent `3cd024d652dc883c46307581e979fe32302adbac` (`fix: path
traversal vulnerability, #851 (#855)`, 2026-03-08) is the adjacent
include/render/layout hardening named by the advisory (CVE-2026-30952). It
keeps `if (!enforceRoot) return true`. It is not PR #867.

Closer `f41c1fc0` deletes `const enforceRoot = type !== LookupType.Root` and
always runs `contains()`. It does not reverse realpath `contains()`. It
reverses the 2021 skip, not an AI-introduced hole. Fix parent `v10.25.4` still
has candidate loader blob `b0e471e1147021a16dc85e423b84454574bf5457`. Tag
`v10.25.5` peel `4af7be695cb715bf227113729d36396d45ee922a` matches fix loader
blob `bf2fc8261f7d39991689bacb1c58814c3a534e9b`.

`AI_INCOMPLETE_REMEDIATION` also fails. The GHSA explicitly covers the
untouched Root sibling, not a residual of the realpath guard. Contract:
a fix to surface A followed by a later fix to pre-existing surface B is not
incomplete-remediation causality. The realpath rewrite itself is unmarked
member 1, not the Cursor trailer members.

ai_hunk_gate: FAIL (relevant skip is 2021; Cursor members do not author it;
same-file realpath overlap is not the GHSA hunk).
but_for_gate: FAIL (revert leaves the skip; `v10.25.0` already vulnerable).
fix_reversal_gate: FAIL (closer removes the 2021 skip, not an AI-introduced
invariant).

## Release

Git tags: `v10.25.4` contains the squash and not the closer. `v10.25.5`
contains the closer. GitHub `/releases/tag/v10.25.4` and `v10.25.5` return
HTTP 200. npm `liquidjs@10.25.4` SHA256
`1f1b47d7b1c99ca90eb26269434ae043ab15153819c42c233ef33ddfa635e9d9` still has
`const enforceRoot = type !== LookupType.Root` plus realpath. npm
`liquidjs@10.25.5` SHA256
`312633854786a9dc3d26a966986fc133ba3461e00f73c6d2db7ef1dc4ef13a2d` has
realpath and does not have `type !== LookupType.Root`. Containment of the two
SHAs is real. It does not make the squash the origin of the skip. Advisory
range `introduced: 0` is not causal proof.

release_gate: PASS for git+npm containment of squash versus closer. Causal
gates still fail.

## Uniqueness

GHSA-V273 is absent from canonical94 strict 94. Same-repo GHSA-4RC3-7J7W-M548
is circular `{% layout %}` / `{% block %}` DoS (`src/tags/block.ts`, alias
CVE-2026-41311) and is also uncounted. Shared SHA `529dd67e` is not identity
dedupe. CVE-2026-39859 is not a second case.

uniqueness_gate: PASS.

## Gates

1. identity_gate: PASS
2. ai_hunk_gate: FAIL
3. topology_gate: PASS
4. but_for_gate: FAIL
5. fix_reversal_gate: FAIL
6. release_gate: PASS
7. uniqueness_gate: PASS

seven_gates_exact_pass: false. Terminal REJECT.

## Claim boundary

No red-team REJECT changes the count. Only leader-reviewed rows with all seven
gates PASS enter the strict released lower bound. This packet does not rebuild
canonical94. Publication and more-than-200 stay HOLD.
