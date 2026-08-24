# Third-review: upgrade-a ordinals 1, 20, 92, 93 - report

Date: 2026-08-13
Lane: `autoresearch/herdr-260813-ghsa200-third-review-upgrade-a/`
Clones: `/home/hanqing/.cache/ghsa200-worker-clones/third-review-upgrade-a/clones/`
Role: independent third review. Proposer and red-team labels are treated as
hypotheses, never evidence. This lane emits no admission into any ledger.

## Verdicts

| ordinal | GHSA | CVE | verdict | causal class |
|---|---|---|---|---|
| 1 | GHSA-FMFG-9G7C-3VQ7 | CVE-2026-32111 | **ACCEPT** | AI_DIRECT_ROOT (consent-form scope) |
| 20 | GHSA-XW8C-RRVX-F7XQ | CVE-2026-44219 | **ACCEPT** | AI_DIRECT_ROOT (two-client composite) |
| 92 | GHSA-WV46-V6XC-2QHF | CVE-2026-35670 | **ACCEPT** | AI_DIRECT_ROOT |
| 93 | GHSA-RG8M-3943-VM6Q | CVE-2026-41376 | **ACCEPT** | AI_NEW_SURFACE_CONTRIBUTOR (thread-root scope) |

All four pass identity, ai-hunk, topology, but-for, fix-reversal, release, and
uniqueness with first-party evidence. Ordinal 93 is normalized away from
AI_DIRECT_ROOT because the same advisory names a later human-origin sibling
surface (reply-context).

## Scope-rule application

The leader scope rule is applied: a GHSA may count as a contributor even when
the advisory names additional sibling surfaces, provided the counted surface is
named by the advisory, the AI delta is but-for, scope is stated, the fix
reverses that surface, release containment holds, and the GHSA is counted once.

- **Ordinal 1** - advisory names three code paths (consent form; REST tool
  calls; WebSocket tool calls). The counted surface is code path 1 (consent
  form), authored by AI squash `39806871` ("Generated with Claude Code"). The
  sibling REST/WebSocket paths originate from `1399f5a`, human-authored (Julien
  Larocque-Dupont) with a Claude Sonnet 4.5 co-author, and are explicitly out of
  scope. The consent form is the reported primary surface and is pure AI, so
  AI_DIRECT_ROOT at that scope holds.
- **Ordinal 20** - advisory names both SCA clients (osv.py + endoflife.py);
  both are AI-authored (`d42195e1`, `f08e6549`, each "Co-Authored-By: Claude
  Opus 4.7"). Composite two-candidate representation is the correct official
  mechanism. AI_DIRECT_ROOT holds.
- **Ordinal 92** - advisory names the reply-rebinding mechanism, entirely the
  AI-added `resolveChatUserId` matcher (`9a3800d8`). No human sibling surface.
  AI_DIRECT_ROOT holds.
- **Ordinal 93** - advisory names "thread root AND reply context". Thread-root
  is AI (`49c60e90`, Claude Opus 4.5); reply-context is later human
  (`c7fbd518`, alberthild + gumadeiras, no AI marker). Normalized to
  AI_NEW_SURFACE_CONTRIBUTOR with thread-root-only scope; the same fix
  `8a563d60` reverses both surfaces.

## Independent git verification (fresh clones)

| check | ord 1 | ord 20 | ord 92 | ord 93 |
|---|---|---|---|---|
| candidate carries AI marker | yes (Claude Code) | yes (Opus 4.7 x2) | yes (Opus 4.6) | yes (Opus 4.5) |
| candidate in vulnerable tag | yes (v6.7.2) | yes (v0.8.1 both) | yes (v2026.3.2) | yes (v2026.2.12) |
| fix in fixed tag | yes (v7.0.0) | yes (v0.8.2) | yes (v2026.3.22) | yes (v2026.3.31) |
| fix in vulnerable tag | no | no | no | no |
| fix reverses named surface | removes ha_url | caps both reads | gates name matching | filters sender allowlist |

Affected ranges (first-party advisory) all contain the reviewed vulnerable tag
and precede the fixed tag: ord 1 `<7.0.0` / fixed 7.0.0; ord 20 `>=0.6.0,<=0.8.1`
/ fixed 0.8.2; ord 92 `<2026.3.22` / fixed 2026.3.22; ord 93 `<=2026.3.28` /
fixed 2026.3.31.

Note: for ordinal 1 the first tag containing the consent form is v6.3.0; the
reviewed vulnerable tag v6.7.2 is the last vulnerable release. Both satisfy the
release gate; the gate does not require the first tag.

## Uniqueness / dedupe

The deterministic checker (`herdr-260813-ghsa200-cross-dedupe/dedupe_checker.py`,
unchanged) was run with all four proposals against the 216-row canonical
overlay. Result:

- Each proposal collides with exactly one canonical row - its own case_id
  (identity SAME_ID), verdict ALIAS_SAME_COMPONENT (same advisory, overlapping
  mechanism). No proposal collides with any other GHSA.
- Zero cross-GHSA DUPLICATE or CONFLICT verdicts.
- Each of the four mechanism_keys occurs in exactly one canonical row.
- No proposal candidate/fix SHA appears in any other canonical row, so shared
  SHA is not a factor in any verdict.

Negative controls (self-test, 7/7 pass) re-confirm the dedupe policy: shared
candidate+fix SHA alone is DISTINCT (nc1) or CONFLICT when the mechanism
matches without identity (nc2); a pre-existing mechanism_key alone is CONFLICT
(nc3); DUPLICATE requires exact source/sink/invariant + first-party identity
(nc4/nc5).

## Umbrella-fix check

- Ordinal 20: fix `17a119fe` is a pentest umbrella commit (also touches
  Dockerfile, discovery.py, web headers). The same commit still replaces both
  unbounded `resp.read().decode()` calls with `MAX_RESPONSE_BYTES` + overflow
  check, so the named SCA invariant is reversed; extra hunks do not block.
- Ordinal 93: fix `8a563d60` touches handler.ts + thread-context.ts +
  reply-context.ts. It reverses both the AI thread-root surface and the human
  reply-context surface; the thread-root reversal is present.

## Boundary

- All four are third-review verdicts only; nothing is promoted or written to a
  canonical/publication file.
- Ordinal 93 is counted as a contributor surface, not a whole-advisory AI root.
