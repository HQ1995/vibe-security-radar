# vLLM canonical code-evidence hunk repair

- Class: `alias-c1c247c618bb54f97b64b4fb` (`CVE-2026-78684` / `GHSA-HW36-J4Q7-VJXX`).
- Fresh Neon base: revision `3`, change set `da7d00db-b73d-413e-9b76-ca34bbc2b62c`.
- Candidate: `9dbcf8c3d5de23925195bac6217fc85df6e8bb71`, parent `091d13976c1c246714bb2112dd2e208561dda6a3`.
- Fix: `d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd`, parent `4635cc3e8f609755ad45f9fc2cdb54fa7552038e`.
- The patch preserves the complete live row and changes only `code_evidence`. It is staged only: it has not been applied, exported, published, copied into generated site data, or committed.

## Stored `git show --unified=3` blocks

Every stored candidate/fix item is one complete, byte-for-byte continuous hunk emitted by the named commit. No synthetic header, clipped body, or multi-header hunk remains.

| Role | File | Header | Parent blob range | Commit blob range |
|---|---|---|---:|---:|
| candidate | `vllm/multimodal/video.py` | `@@ -752,19 +752,128 @@` | 752-770 (19) | 752-879 (128) |
| candidate | `vllm/multimodal/video.py` | `@@ -868,10 +977,38 @@` | 868-877 (10) | 977-1014 (38) |
| fix | `vllm/multimodal/media/video.py` | `@@ -35,6 +35,7 @@` | 35-40 (6) | 35-41 (7) |
| fix | `vllm/multimodal/video.py` | `@@ -92,6 +92,10 @@` | 92-97 (6) | 92-101 (10) |
| fix | `vllm/multimodal/video.py` | `@@ -208,6 +212,7 @@` | 208-213 (6) | 212-218 (7) |
| fix | `vllm/multimodal/video.py` | `@@ -1136,6 +1141,7 @@` | 1136-1141 (6) | 1141-1147 (7) |

The old-side lines of every hunk equal the indicated slice of the parent blob; the new-side lines equal the indicated slice of the commit blob. Header counts were also independently recomputed from context/removal/addition prefixes.

## Fingerprints and publication witnesses

- Candidate hunk SHA-256: `03875dcf0da064903c46ca9f87cb40b51208f326be6db9794573ee488c2dade0`
- Fix hunk SHA-256: `91d87a7f9ef7ba277c7537f5610151070d3104870758621098fdc348a3537ec2`
- Candidate patch files: `vllm/multimodal/video.py`
- Fix patch files: `vllm/multimodal/video.py`, `vllm/multimodal/media/video.py`
- Candidate anchors present: `DeepStreamVideoBackendMixin`; `def _get_pool(cls, pool_size`; `elif backend == "deepstream"`; `probe_metadata(data)`.
- Fix anchors present: `register_gpu_codec("deepstream")`; `runtime_kwargs.pop("pool_size", None)`; `_check_frame_pixel_limit(_w, _h)`.
- All six displayed hunks have distinct, non-empty public annotations; `comparison_hunks` remains empty so the canonical candidate/fix blocks are the displayed blocks.

## Validation

- Patch artifact: exactly one non-empty line; `json.loads` passes.
- Fresh live revision equals `expected_revision == 3`.
- Replacing only the live row's `code_evidence` produces the staged row field-for-field; all other live fields are unchanged.
- `scripts.ledger_store.validate_update(live_row, staged_row)` passes.
- `scripts.site_preflight.valid_unified_hunks` passes for all six blocks.
- Every stored block exactly matches a full hunk from local `git show --format= --no-ext-diff --unified=3 <sha> -- <path>`.
- Parent/commit blob slices, hunk counts, both role hashes, all required anchors, and both patch-file sets recompute successfully.
