# GHSA-8H88 canonical repair

- Target: `GHSA-8H88-GXP3-J7PG` / `alias-0a97ba3bb4787b9352f519d1`.
- Live base: revision 2, checksum `07b2d4ecfc2413199f95955c3d64c546efb8812e734e981513b1c0f312e81475`.
- Gate verdict: `research/gate-campaign-20260830/verdicts/wave-07.jsonl:14` records all seven gates PASS, candidate `fafdfeed1b279cfe61e86cd8adc132b206eef8d4`, and fix `f4a1ba660063cd9e17883829e5272a248525a16b`.
- Release witness: `research/gate-campaign-20260830/wave-07.jsonl:14` records vulnerable `< 1.4.0` and fixed `1.4.0`.
- Reader summary: `research/gate-campaign-20260830/summaries-by-alias.json:2218-2220`. Its stored mechanism is truncated mid-word, so the patch retains the summary but rewrites the mechanism from the closed causal record.
- Diff provenance: `scripts/generated-code-evidence.json:3759` supplies URLs, markers, and full-patch hashes. The displayed hunks were narrowed against the local objects to the exact `from_dict() -> to_identity()` path and the direct verification reversal; each hunk has a distinct reader annotation and required anchors.
- Local object checks: candidate parent lacks `openssl_encrypt/modules/key_bundle.py`; candidate creates the unverified deserializer and identity conversion; fix makes `verify=True` the default and calls `bundle.verify_signature()` before return.
- Scope: one full-row update only. It preserves every live revision-2 field and adds the missing canonical publication fields. It is not applied, exported, published, or committed by this worker.

