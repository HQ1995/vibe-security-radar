# GHSA-H2V8-4C3F-VQGV independent release closure

Verdict first: **UNKNOWN**. PASS_PROPOSAL=0. Countable PASS=0.
Assigned 1. Reviewed 1. Unreviewed 0. Equation 1=1+0.
Canonical88 stays 88. Publication and more-than-200 stay HOLD.

CF4-b2 UNKNOWN was not copied. This packet rebuilt the seven gates from the unreviewed GHSA object, the local clone, npm registry tarballs, GitHub releases/tags, and NVD/ZDI pages.

## Gates

1. identity_gate PASS. Unreviewed GHSA-h2v8-4c3f-vqgv aliases CVE-2025-12489, names evernote-mcp-server openBrowser command injection, and references first-party commit 1e66c78c on brentmid/evernote-mcp-server. ZDI-25-983 and NVD bind that same commit. Not withdrawn. No github-reviewed collision.

2. ai_hunk_gate PASS. Candidate e08547bcdb42aaa86190c6e2dfc64159fcd3a146 is atomic (parent 9f7c1b36d698845ea8bd968ad7446550995a2a3d). Parent has no auth.js. Candidate adds `exec(\`${command} "${url}"\`)`. Marker: Generated with Claude Code and Co-Authored-By: Claude <noreply@anthropic.com>. The GHSA sink is this hunk, not a megapatch sibling.

3. topology_gate PASS. n_parents=1. Blame at the fix parent still attributes the exec interpolation to e08547bc. Later auth.js commits do not rewrite the sink. Closer 1e66c78c is also Claude-marked and is the reversal.

4. but_for_gate PASS. Removing the candidate removes auth.js. Reachable path: authenticate -> getRequestToken HTTPS oauth_token -> redirectToAuthorization concatenates `?oauth_token=` with no encoding -> openBrowser -> exec shell text. The closer documents oauth_token="; touch /tmp/pwned #. CF4-b2 NARROW is not inherited.

5. fix_reversal_gate PASS. 1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579 rewrites openBrowser from exec interpolation to spawn(command, args). Tests follow. Exact reverse.

6. release_gate UNKNOWN. No local tags and no origin tags. GitHub has no releases. npm evernote-mcp-server is yasuhiroki 0.0.2/0.0.3 (gitHead 406e50aa / 78ebf186; tarballs have src/*.mjs and no auth.js). Scoped npm, Docker Hub, GHCR, and PyPI 404. package.json 1.0.0/2.1.3/2.2.0 are not artifacts. Codeload SHA tarballs are git snapshots, not product releases. No immutable first-party vulnerable or fixed artifact, so the gate stays UNKNOWN.

7. uniqueness_gate PASS. Absent from canonical88 strict 88 and from current PASS_PROPOSAL lists. Distinct from CF4-b2 UNKNOWN.

## Claim boundary

Worker PASS is proposal only. This packet proposes none. Prefer no PASS over treating version strings or foreign npm name collisions as containment.
