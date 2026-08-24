# K-N incomplete-remediation GHSA sweep (cf2, grok46-xhigh)

**Verdict: TERMINAL. PASS_PROPOSAL = 0. Countable PASS = 0.**

Worker PASS is proposal only. This packet proposes no admissions.
Canonical85 stays 85. Publication and greater-than-200 remain HOLD.

Inspected 28 unique-repository first-party GHSA identities from the unreviewed
K-N slice of `herdr-260813-ghsa200-commitfirst-kn-grok46-low`. Bound was 40;
the unique-repo security-attempt pool exhausted at 28 without padding.

## Method

Universe: `unresolved-ids.txt` (1421), excluding the source shard's 30 terminal
rows, canonical85 identities, foundation identities, and recorded negative
controls. Ranking and AI-commit scans are routing only.

Selection: AI-marked commits whose subject is an explicit security, validation,
sanitization, authorization, path, SSRF, injection, or resource-limit attempt
on non-cited advisory fix files. Megapatch lockfile rows dropped. One GHSA per
repository.

Adjudication: local commit-gn clones only. No GitHub REST. No credentials.
Missing tags are UNKNOWN, never PASS.

## Conservation

| Set | Count |
|---:|---:|
| K-N unresolved before this packet | 1421 |
| Overlap with canonical85/foundation | 2 |
| No security-attempt AI subject | 1359 |
| Megapatch routing dropped | 14 |
| Scored security-AI rows | 46 |
| Unique-repo inspected | 28 |
| Same-repo scored leftovers (UNREVIEWED) | 18 |

Equalities: 1421 = 2 + 1359 + 14 + 46. 46 = 28 + 18. Source-shard 30 stay excluded.

## Why zero PASS

Incomplete remediation requires an AI-authored prior security boundary whose
chosen guard left the exact residual this GHSA later closed, contained in a
vulnerable release, then amended by the minimum closer.

Observed failure modes:

1. **Post-fix AI follow-up (majority).** The Claude/Copilot "fix(security)"
   commit is a descendant of the advisory closer. Keras CVE-2025-1550-bypass
   language, Koa referer normalize, langgraphjs tag escaping, nodemailer
   address normalize, langflow extra auth, and FacturaScripts escapeColumn
   all land after the GHSA patch. That is later hardening, not a prior
   incomplete attempt.

2. **Sibling guard in a shared file.** Ancestry can be true while the hunk is
   the wrong boundary. n8n GHSA-JH8H: AI XSS sanitizer in `templates.ts` versus
   n8n User Auth cookie bypass in `validateAuth`. local-deep-research
   GHSA-9C54: Copilot `os.path.commonpath` model-path check versus later
   `safe_get` SSRF wrap. undici GHSA-4CWX: SWR/revalidation handlers versus
   `parseCacheControlHeader` empty `private` directives (test-file overlap
   only). nocobase GHSA-MVVV: SES lockdown re-export versus new
   `server-request` SSRF helper. datamodel GHSA-RFR2: `validate_default`
   rewrite versus `allow_private_network` HTTP fetch (closer SHA shared with
   recorded REJECT GHSA-954P).

3. **Advisory closer is not an origin.** AI-marked weekly bundles and listed
   fix SHAs do not transfer authorship onto a residual, and they are not
   counted as introducing hunks.

4. **No local tags.** Every probed clone was fetched `--no-tags`.
   `release_gate` is UNKNOWN. That alone would block PASS even if causal
   gates had closed.

## Closest misses (still REJECT)

- **GHSA-JH8H-6C9Q-7GMW**: AI XSS/parameter validation on Chat Trigger is an
  ancestor of the weekly bundle, but the GHSA residual is auth-cookie
  validation the AI commit did not write. Topology NARROW because the listed
  closer is an AI-marked squash bundle.
- **GHSA-9C54-GXH7-PPJC**: Copilot path-traversal tightening is an ancestor of
  the SSRF closer in `llm_config.py`, but the closer does not amend that path
  guard; it replaces `requests.get`.
- **GHSA-4CWX-7WF7-3272**: Claude cache-revalidation work is an ancestor, but
  production files differ from the private-directive parser fix.
- **GHSA-JGMV-J7WW-JX2X** / **GHSA-C9RC-MG46-23W3**: subject-level IR lookalikes
  whose AI guards post-date the advisory closer.

## Claim boundary

No seven-gate PASS. Remaining K-N rows outside these 28 inspected IDs are
UNREVIEWED, not REJECT. This worker does not edit canonical, site, or pipeline
files.
