# Ordinal 20 official-GHSA composite correction

**Verdict: `KEEP` (proposal).** All seven gates PASS for the full official mechanism: both Claude-authored unbounded SCA HTTP clients. This does not overwrite `herdr-260813-ghsa200-red-upgrade-a`.

## Hypothesis

- Case: GHSA-XW8C-RRVX-F7XQ / CVE-2026-44219 / `Jo-Jo98/ciguard`
- Mechanism: unbounded `resp.read()` in both `src/ciguard/analyzer/sca/endoflife.py` and `src/ciguard/analyzer/sca/osv.py`
- `candidate_set`: `d42195e1` (endoflife.py) and `f08e6549` (osv.py)
- Last named vulnerable tag: `v0.8.1` (`0f294a346c49b358893e39b06d13ac7516775567`)
- Minimum fix: `17a119fe` in `v0.8.2` (`ca5accfeabb96028ec9a07295573ebeeeb09ae0f`)

The worker’s endoflife-only PASS and the prior red-team NARROW of that narrowed edge are not this row.

## Gates

**identity_gate PASS.** Independent global and repo GHSA JSON name `ciguard`, both files, range `>= 0.6.0, <= 0.8.1`, patched `0.8.2`. Not withdrawn. CVE-2026-44219 is on the global object.

**ai_hunk_gate PASS.** Both commits have `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`. Each adds the file and `payload = json.loads(resp.read().decode("utf-8"))`. `v0.8.1` blame binds the endoflife read to `d42195e1` and the osv read to `f08e6549`.

**topology_gate PASS.** Each origin is a single-parent atomic commit. `d42195e1` is an ancestor of `f08e6549`. Both are ancestors of `v0.8.1`. Authorship is not transferred across a squash or marker-less carrier.

**but_for_gate PASS.** Parent of `d42195e1` has no `endoflife.py`. Parent of `f08e6549` has no `osv.py`. Removing both AI commits removes both unbounded clients. This is not preservation of a pre-existing read.

**fix_reversal_gate PASS.** `17a119fe` is **too broad** (also CYCLE-1-001 symlink discovery, CYCLE-1-002 Dockerfile USER, CYCLE-1-004 web headers). It is still an **atomic same-mechanism reversal for both clients**: the same commit replaces both exact unbounded `resp.read()` calls with `MAX_RESPONSE_BYTES` plus an overflow check. Extra hunks do not leave either named read uncapped. This is not a nearby different security commit that misses the invariant.

**release_gate PASS.** Official last vulnerable `v0.8.1` contains both origins, both unbounded reads, and not the fix. `v0.8.2` contains `17a119fe`. First affected tag `v0.6.0` has only endoflife; that is consistent with the published range and is not used as composite containment.

**uniqueness_gate PASS.** One first-party GHSA, one mechanism (unbounded SCA HTTP body read), two origin commits in one case. Not two countable cases.

## Sources

Clone `/tmp/ghsa200-worker-clones/red-upgrade-a-ord20-composite/ciguard` HEAD `1b6eeb790b94de44e7d9e19a672658c23a4d17df` (2026-05-15T22:59:25+01:00). GHSA page SHA-256 values are in `result.json`.
