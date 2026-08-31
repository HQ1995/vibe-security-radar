# Three release-gap re-review

Date: 2026-08-30. Scope is limited to the release gate and release metadata for
`GHSA-W9RM-VVQP-QQ3H`, `CVE-2026-42278`, and
`GHSA-8G98-M4J9-QWW5`. This report follows `docs/AUDIT-PROTOCOL.md`: advisory
metadata is a lead, while Git/tag/package containment is the release proof.
No database apply, publisher run, generated-data edit, web edit, or commit was
performed.

## Decisions

| Class | Release gate | `vulnerable_release` | `fixed_release` | Publication boundary |
|---|---|---|---|---|
| `alias-d019f5b5ca91c8bb1d8b320d` | `NARROW` | `null` | `null` | Development-only interval; no released vulnerable artifact. |
| `alias-3695e775e541b8d8f707ccde` | `NARROW` | `null` | `null` | Development-only interval; no tagged vulnerable artifact and no patched release named by the first-party advisory. |
| `alias-a57df415a930e4db1ef3b6f7` | `UNKNOWN` | `null` | `null` | Keep the causal case publishable as qualified/provisional, but do not claim release containment. |

`NARROW` is not an unresolved release guess: it records a proven commit-only
vulnerable interval. `UNKNOWN` is preserved for `8G98`; absence of recoverable
7.0.x artifacts is not a `FAIL` and does not negate its six closed causal gates.

## GHSA-W9RM-VVQP-QQ3H / CVE-2026-9806

Primary metadata and complete Git history agree that no released version was
vulnerable:

- The [GitHub advisory](https://github.com/advisories/GHSA-w9rm-vvqp-qq3h)
  lists affected and patched versions as unknown and explicitly says the flaw
  existed only on a development branch.
- The [CVE JSON record](https://cveawg.mitre.org/api/cve/CVE-2026-9806)
  marks versions `1.0` through `1.3.0` as **unaffected**, with default status
  `unaffected`. Therefore `<=1.3` is not a vulnerable range.
- A fresh full clone of `https://github.com/MISP/cti-transmute.git` passed
  `git fsck --full --no-dangling`. Tags `v1.0`, `v1.1`, and `v1.2` contain
  neither the BIC nor the fix. Tag `v1.3` at
  `ecd04d494b0fda2ab39fb56472785388c2d5872e` contains both
  `5a4344884f93337a52d0abee1014edade3ed96e6` and
  `cf42409badc27b13d9bb644b9175aa7f27e11259`; later `v1.4` and `v1.5`
  contain both as well.
- The [BIC](https://github.com/MISP/cti-transmute/commit/5a4344884f93337a52d0abee1014edade3ed96e6)
  is dated 2026-05-14, directly after parent
  `4bf6b9b90e20fbf9d9c3ebf4d7bcfb9534171858`, and writes the
  `n.message` interpolation into `innerHTML`. The
  [fix](https://github.com/MISP/cti-transmute/commit/cf42409badc27b13d9bb644b9175aa7f27e11259)
  is dated 2026-05-18 and changes the message assignment to `textContent`.

Canonical consequence: retain `release=NARROW`, keep both release fields
explicitly null, and record `v1.2` as the last release before the origin and
`v1.3` only as the first release containing the fix. The static
`scripts/first-party-advisory-releases.json` entry (`<=1.3` / `1.4`) conflicts
with the primary CVE status and must never override this canonical row.

## CVE-2026-42278 / GHSA-9CHC-GJFR-6HRQ

This is also a development-only interval, not an affected-to-fixed release
pair:

- The first-party
  [repository advisory](https://github.com/UltraDAGcom/core/security/advisories/GHSA-9chc-gjfr-6hrq)
  states `Affected versions: latest codebase at time of reporting`, lists no
  package, and states `Patched versions: None`.
- The [CVE JSON record](https://cveawg.mitre.org/api/cve/CVE-2026-42278)
  describes the affected boundary as the Git interval
  `< fb6ef59d6c1385400e7acea7ae31fc6a473c3051`; that SHA is a commit, not
  a release version.
- The deleted upstream's local history at
  `.ai-slop/state/legacy87/clones/UltraDAGcom_core` contains the complete
  relevant objects. A fresh full clone of the reporter's public mirror
  `https://github.com/sumitshahorg/core.git`, followed by an exact-SHA fetch of
  `fb6ef59d6c1385400e7acea7ae31fc6a473c3051`, passed `git fsck --full` and
  reproduced the same object IDs and parents.
- The only preserved tags are `v0.1.0` at
  `3b0589a20bc3afebed861f664ceb6167a6785770` and `latest` at
  `a82ffe846349f2d6f9d36f4518cf63847e854bdf`. Both predate and exclude the
  AI contributor `8f000e9403a33c693eeb630771bc3d4846473991`, the human
  exploit-completing contributor
  `c21e8dcd5281cb4b0fda21529ed74ba46e62d873`, and the fix
  `fb6ef59d6c1385400e7acea7ae31fc6a473c3051`.
- Git ancestry proves `8f000e...` precedes `c21e8d...`, which precedes the
  direct fix. No first release containing the fix is available.

Canonical consequence: retain `release=NARROW` and explicit null release
fields. Do not serialize the CVE's commit SHA as `fixed_release`, and do not
serialize `< SHA` as a semantic vulnerable version.

## GHSA-8G98-M4J9-QWW5

The first-party release claim exists, but the artifacts needed to bind that
claim to the audited candidate/fix edge are no longer recoverable:

- The first-party
  [repository advisory](https://github.com/tailot/taylored/security/advisories/GHSA-8g98-m4j9-qww5)
  lists affected `7.0.5` and patched `7.0.8`; its body instead describes
  vulnerable `7.0.7`. It names the missing PayPal webhook validation among a
  four-issue aggregate.
- A fresh request to the [npm packument](https://registry.npmjs.org/taylored)
  returned only version `8.2.4` in `versions` and `latest=8.2.4`. The retained
  `time` keys show that `7.0.5`, `7.0.6`, `7.0.7`, and `7.0.8` once had
  publication timestamps, but all four corresponding official tarball URLs
  currently return HTTP 404. A timestamp is not the artifact's code content.
- A fresh full clone of `https://github.com/tailot/taylored.git` passed
  `git fsck --full --no-dangling`. Its only tag is `8.2.4` at
  `05da9137527cb7be236bb8e63f1c3b0dffcc6b2a`; that tag contains both the
  Jules-authored candidate `c139c021f68a09d22c2af88641b61c00f67f2af4`
  and direct fix `57b7634391959dbbdb39b387ac4dc68157cd58a1`.
- Git and npm chronology are consistent with the advisory, but chronology
  cannot replace containment: there is no surviving tag or tarball containing
  the candidate without the fix.

Canonical consequence: preserve `release=UNKNOWN`, explicit null release
fields, and a precise `unresolved_reason`. This row may remain in the catalog
because identity, AI hunk, topology, but-for, direct reversal, and uniqueness
are all `PASS`; it must not be promoted to an all-gates-pass/confirmed release
claim unless a verifiable 7.0.x artifact is recovered.

## Reproduction commands

All commands were run under `numactl --cpunodebind=1 --membind=1`.

```sh
git clone --no-single-branch https://github.com/MISP/cti-transmute.git /tmp/w9rm
git -C /tmp/w9rm fsck --full --no-dangling
git -C /tmp/w9rm merge-base --is-ancestor 5a4344884f93337a52d0abee1014edade3ed96e6 v1.2
git -C /tmp/w9rm merge-base --is-ancestor cf42409badc27b13d9bb644b9175aa7f27e11259 v1.3

git clone --no-single-branch https://github.com/sumitshahorg/core.git /tmp/ultradag
git -C /tmp/ultradag fetch origin fb6ef59d6c1385400e7acea7ae31fc6a473c3051
git -C /tmp/ultradag fsck --full --no-dangling

git clone --no-single-branch https://github.com/tailot/taylored.git /tmp/taylored
git -C /tmp/taylored fsck --full --no-dangling
git -C /tmp/taylored merge-base --is-ancestor 57b7634391959dbbdb39b387ac4dc68157cd58a1 8.2.4
```
