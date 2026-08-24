# Post-hold canonical integration checkpoint

Date: 2026-08-13 (America/New_York)
Base commit: `20b795ccaa2cbbe22723998e931d1200f043c865`

## Outcome

The accepted terminal corrections are now composed into one generated canonical ledger. The result remains **HOLD**:

- `integration_ready=false`
- `final_count=null`
- physical records: 273
- physical component rows: 216
- canonical components: 211
- source envelopes, not final counts: strict/broad/widest = **134 / 199 / 211**
- released canonical states: **PASS 144 / NARROW 24 / REJECT 23 / UNKNOWN 8**

This checkpoint does **not** claim 200 vulnerabilities. Routing, commit ancestry, and release containment are not treated as causality without the corresponding hunk-level evidence.

## Integrated changes

- Applied all 15 first-party identity corrections: eight omitted GHSA IDs were added, existing IDs were retained, and the WACRM repository was corrected.
- Applied the 21 exact-preconditioned `NARROW -> PASS` promotion patches accepted by the terminal consolidation and independent review.
- Normalized two same-mechanism rows as physical, non-counting `DUPLICATE` records:
  - Scriban lazy range -> array multiplication.
  - GitPython split mode -> kwarg-option bypass. The raw `REJECT + duplicate_of` proposal was intentionally not applied because it violates hardened duplicate semantics.
- Applied the terminal release corrections:
  - Taylored `PASS -> UNKNOWN` because named vulnerable/fixed artifacts are unavailable.
  - Prompty `PASS -> NARROW`, adding formal alias `CVE-2026-73299`; artifact containment closes, but the named merge is not in the patched npm artifact.
  - BSV ARC remains PASS with its first-party named Claude origin, atomic fix member, carrier fix, and RubyGems/tag containment recorded.
- Applied the two minimum-blocker decisions:
  - direct-CDP stays NARROW;
  - trusted-proxy Origin row becomes REJECT because the selected AI commit is a sibling pairing edge and the named predicate is human-origin.
- Added SIPSorcery exactly once as a released strict PASS component.
- Added Relyra once as `STRICT_RELEASED/NARROW`; PASS promotion remains held.
- Kept Koel RJG7 out of the canonical count. Its causal and release evidence is strong, but one independent complete audit identifies its NAT64/6to4 SSRF-validator residual as the same mechanism already represented by `post:n8n-mcp-ipv6-ssrf@canonical`. This conservative conflict is explicit in the HOLD ledger.

## Durable machine inputs

The integration transaction is defined by:

- `integration_corrections.json`: 43 accepted, preconditioned corrections plus 6 explicit HOLD/exclusion records.
- `adjudications.json`: 30 post-hold components and 30 non-counting controls.
- `terminal_sources/`: parsed terminal result/correction files copied from the completed worker packets.
- `source_manifest.json`: SHA-256 bindings for all source files, including the independent integration review.
- `build.py`: deterministic ledger/summary generator.
- `verify.py` and `test_canonical.py`: structural, conservation, duplicate, result-stability, and explicit-cache checks.

## Verification

Passed locally:

```text
python3 build.py --check
PASS: generated ledger and summary are byte-identical

python3 verify.py
PASS: 273 records, source envelope 134/199/211, HOLD

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ... -p test_canonical.py -v
Ran 7 tests ... OK
```

The hardened verifier also preserves the accepted fail-closed rules for duplicate counting, semantic cross-references, exact edge reuse, source hashes, count conservation, stale generated artifacts, result-file stability, and explicit live-cache selection.

Targeted live replay was started with an explicit repository cache. Local Git object/tag checks reached the external first-party advisory phase, where `api.github.com` timed out. No result file was updated by the failed replay. The last durable live evidence therefore remains the previously authenticated targeted snapshot (28 post-hold release edges plus the inherited Batch I-IV targeted replays), and the gate remains `release_containment=PARTIAL` rather than being falsely upgraded.

## Remaining HOLD boundary

- No final 200.
- Alias coverage for the widest envelope is still partial.
- Semantic mechanism review is still partial, including four explicitly deferred equal-score pairs.
- Release containment remains targeted rather than exhaustive.
- Relyra PASS and Koel admission remain conservative policy conflicts.
- Numerous released NARROW/REJECT/UNKNOWN rows remain.

The canonical result is therefore valid as an integrated HOLD checkpoint, not as a publication-ready final census.
