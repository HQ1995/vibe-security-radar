# Strict 150 completion v3: first-party public IDs and atomic causal edges

Date: 2026-08-11

## Decision

The precision-first target is met under the repository's explicit **public-ID**
counting contract:

- **190 unique published public identifiers**: 98 CVEs and 92 GHSAs;
- **107 deduplicated semantic vulnerability components**;
- **117 accepted causal edge occurrences**, representing 116 unique
  `(candidate, fix)` pairs;
- **81 direct commits, 29 squash members, and 7 upstream atomic origins**;
- **76 direct-root/reintroduction components and 31 new-surface contributor
  components**;
- **11 components and 17 edge occurrences rejected** from the frozen source.

The 190 identifiers are not 190 independent vulnerabilities. CVE/GHSA aliases
and same-mechanism duplicate publications collapse to 107 semantic components.
The result therefore clears the requested 150-public-ID threshold, but it does
not claim 150 independent vulnerability mechanisms.

The accepted ledger is:

`autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/ledger.jsonl`

Every row contains its complete public-ID set and accepted atomic edge evidence.

## What was improved

The frozen source had 134 candidate edge occurrences. The causal v2 pass removed
17 occurrences rather than preserving them to reach the threshold:

| Rejection reason | Edge occurrences | Why it is not publishable |
|---|---:|---|
| incomplete hardening | 12 | Candidate reduced an older/broader vulnerability; removing it makes the parent less safe, not non-vulnerable. |
| wrong edge | 2 | Advisory-specific dangerous code came from another commit. |
| refactor preservation | 2 | Candidate moved or rewrote an already vulnerable path without adding reachability or risk. |
| insufficient fix reversal | 1 | Candidate was a real precursor, but the paired single fix did not close the complete mechanism. |

This leaves 117/134 source occurrences. That ratio is a source-cleaning yield,
not a statistical estimate that the remaining set is infallible. The accepted
set has no unresolved `NEEDS_REVIEW` edge, and every retained edge passed the
documented parent-delta, AI-attribution, advisory-mechanism, and fix-reversal
review.

The exhaustive causal adjudication and all negative controls are recorded in:

`docs/RESEARCH-CAUSAL-LEDGER-V2-2026-08-11.md`

## First-party public-ID closure

OSV was not used as proof.

The current ledger has 190 globally unique IDs. A fresh local-object pass found:

- 95/98 CVEs as exact `PUBLISHED` CVEList v5 objects with `datePublished`;
- 65/92 GHSAs as exact GitHub Advisory Database objects with `published` and no
  withdrawal;
- 160/190 IDs therefore closed directly from the pinned local first-party
  snapshots;
- 30 IDs absent only because the local snapshots lag the current official
  services; none had a malformed or rejected local object.

Those 30 missing objects plus the one non-formal `GHSA-7JM2-G593-4QRC`
same-component relationship were independently checked live against CVE
Services/CNA, GitHub advisory APIs/pages, repository advisories, first-party
issues/PRs, and exact repository fixes. Result: **31 PASS, 0 FAIL, 0
NEEDS_REVIEW**. This closes all 190 current ledger IDs.

The per-ID evidence is in:

`docs/RESEARCH-PUBLIC-ID-FIRST-PARTY-CLOSURE-2026-08-11.md`

Important precision boundaries:

- 23 of the newly fetched GHSAs are GitHub `unreviewed`. They remain labeled
  unreviewed; their publication, repository/mechanism, and repair mapping were
  corroborated, but their status is not upgraded.
- `GHSA-7JM2-G593-4QRC` and `GHSA-9FC9-8V4X-F5CP` / `CVE-2026-45001` share an
  official cross-reference, exact fix, and mechanism. They are one semantic
  component, but `7JM2` is not falsely described as a formal CVE alias.
- The valid repository advisory `GHSA-8JQH-598V-RFXC` for
  `CVE-2026-67530` is a known additive alias. It is not counted in the frozen
  190-ID result, so the threshold does not depend on adding it.
- `GHSA-H3X4-HC5V-V2GM` has a same-mechanism repository advisory, but its
  GitHub global object is polluted by a link to unrelated
  `CVE-2026-34426`. Neither that GHSA nor the unrelated CVE is added merely to
  increase the count.

## Squash and upstream atomic closure

All **29/29 accepted squash occurrences** were replayed from local Git objects:

- 13 base-ledger squash members and 16 supplemental squash members;
- every candidate is a real non-merge atomic commit with its own explicit AI
  author/trailer/tool marker;
- candidate, carrier, and fix are full 40-character commit objects;
- the atomic member is not a mainline ancestor of its carrier, as expected for
  a squashed PR member;
- the carrier is an ancestor of the fix;
- the member's production additions are present in the carrier delta, and the
  advisory-specific path is reversed or guarded by the fix;
- attribution remains on the member, never inherited from the carrier.

One member/carrier pair has an exact whole-patch ID match; the others are
multi-member squash landings, so their proof uses the atomic parent delta plus
carried production hunks instead of incorrectly requiring the entire member and
entire squash patches to be identical.

All **7/7 upstream atomic occurrences** retain the upstream candidate and the
OpenClaw import only as a carrier. The upstream objects have their own Claude
co-author markers; the vulnerable functions are carried into the target tree;
the target fixes reverse the imported mechanisms. The root upstream commit is
correctly allowed to have no parent.

## Reproducible build and checks

The current artifact was rebuilt into a fresh temporary directory with:

```zsh
audit_tmp=$(mktemp -d)
uv run --project cve-analyzer python \
  scripts/apply_strict_causal_adjudications.py \
  --adjudications \
  autoresearch/orchestrator-260811-atomic150/strict-causal-v2/adjudications.json \
  --output-dir "$audit_tmp"
cmp -s "$audit_tmp/ledger.jsonl" \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/ledger.jsonl
cmp -s "$audit_tmp/rejected_edges.jsonl" \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/rejected_edges.jsonl
cmp -s "$audit_tmp/summary.json" \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/summary.json
```

All three comparisons returned zero. The emitted census was exactly 107
components, 190 IDs, 117 accepted occurrences, 17 rejected occurrences, and
`minimum_met=true`.

Checks rerun on the current worktree:

```text
pytest: 10 passed
ruff: All checks passed!
git diff --check: PASS
new report whitespace check: PASS
```

The focused tests cover the atomic ledger builder, causal adjudication/filter,
supplement contribution boundary, and squash relation closure CLI.

## Current artifact hashes

| Artifact | SHA-256 |
|---|---|
| accepted ledger | `282d2975d0ee24e9949cc4d108ad5a1ffd9b045ad8548cc6b1661aaf2c18392e` |
| rejected components | `6264f79e1c74ed8b0511c772ded43fdf9b377b9591bdc3d065011a0e631aa4be` |
| rejected edges | `139eaa96fc6be47bdb57b6c9d43660580ef4b883709a6dbafb28ba8324af47e6` |
| summary | `3b2132589fe01f16d94e24313c99c4a44feab113aa4fc4385e861439b439201b` |
| causal adjudications | `88e4217315a921bf7f9e9a41531e492e1d1b1c6b1175b1c63d0960bcc4809653` |
| causal v2 report | `8372522ac34e865eed02d264f3f2c5e5687cf829adf43a12d999b6ae48eee812` |
| first-party closure report | `2492294dea07939a0129db690a25eb438755eead3fdfa4edfc7c12f568535112` |

The four raw output digests printed at the tail of the earlier causal-v2 report
were from its pre-reference replay. The final ledger embeds that report's hash,
so the report had to be frozen before the final output could be generated. The
current hashes in this section supersede those preliminary values; the fresh
byte-for-byte rebuild above verifies them.

## Final claim boundary

The deliverable supports this claim:

> The ledger contains 190 real, published CVE/GHSA identifiers grouped into 107
> semantic vulnerability components. Each retained component has at least one
> explicit AI-attributed atomic commit that either creates/reintroduces the
> advisory mechanism or adds a real affected surface, and every squash origin is
> attributed to the smallest verified member rather than its carrier.

It does not claim that aliases are independent vulnerabilities, that GitHub
unreviewed advisories are GitHub-reviewed, that an AI wrote the entire affected
project, or that manual causal adjudication is a mathematical proof with zero
residual error.
