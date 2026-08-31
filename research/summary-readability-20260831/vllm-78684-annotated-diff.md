# CVE-2026-78684 / GHSA-HW36-J4Q7-VJXX annotated diff

## Result

The current public evidence shows one 90-line candidate excerpt, then unrelated
installation and documentation changes, while every card repeats the same
truncated audit sentence. The smallest reader-complete replacement is three
candidate evidence units and three fix units:

1. DeepStream was hidden inside the loader registered as `opencv`, so the
   request-time GPU policy did not classify `backend=deepstream` as GPU work.
2. Request `pool_size` initialized a process-wide `DecodePool`; the first request
   chose the shared worker count.
3. The DeepStream branch probed width and height but discarded them before GPU
   decode, bypassing the existing frame-pixel limit.
4. The fix names `deepstream` as GPU-backed, removes request-level `pool_size`,
   and checks dimensions before decode.

Reader summary:

> Claude-assisted code let requests select DeepStream GPU decoding and control a
> shared pool without the normal frame-size limit. An unauthenticated client
> could starve other requests.

This report proposes canonical ledger data and a general publisher precedence
change. It does **not** propose a case-specific component branch or an edit to
`scripts/generated-code-evidence.json`.

## Primary-source verification

The local repository is
`.ai-slop/state/repos/vllm-project_vllm`. It reports
`--is-shallow-repository=false`, and all five objects below are local commits.

| Role | Object | Local result |
|---|---|---|
| PR member / candidate | [`9dbcf8c3d5de23925195bac6217fc85df6e8bb71`](https://github.com/vllm-project/vllm/commit/9dbcf8c3d5de23925195bac6217fc85df6e8bb71) | Parent is `091d13976c1c246714bb2112dd2e208561dda6a3`; the parent has no `deepstream` occurrence in Python, Markdown, or `setup.py`. The commit trailer is `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. |
| Default-branch carrier | [`e23b19309b8705b21c3b3ff4129c9974ba15a419`](https://github.com/vllm-project/vllm/commit/e23b19309b8705b21c3b3ff4129c9974ba15a419) | GitHub squash of PR #42424; `9dbcf8c3…` is not its ancestor, so the member and carrier must remain distinct roles. |
| Carrier parent | `f36284a8d21d3748df30c8f1b30357be711350b5` | Both the pixel-limit change `364ee36a…` and request GPU-policy change `ba221520…` are ancestors. Thus the DeepStream design bypassed controls already present when it landed. |
| Direct fix | [`d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd`](https://github.com/vllm-project/vllm/commit/d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd) | Parent is `4635cc3e8f609755ad45f9fc2cdb54fa7552038e`; that parent still pops request `pool_size`, probes `_w, _h`, and has neither `register_gpu_codec("deepstream")` nor `_check_frame_pixel_limit(_w, _h)`. |
| Vendor advisory | [`GHSA-cqm8-jxg6-fqfq`](https://github.com/vllm-project/vllm/security/advisories/GHSA-cqm8-jxg6-fqfq) | Owns the DeepStream resource-exhaustion mechanism. The public case identity remains CVE-2026-78684 / GHSA-HW36-J4Q7-VJXX. |

Full binary patch SHA-256 values, computed from local `git show --format= --binary`,
are `a853f306055eb44622899697c78f1917885b23ae5f9027c2fb8051b91c903544`
for the candidate and
`cdb45516ecd3a1d68d317d8aef10d7a156983daf3154b91049c84f4390d48e6a`
for the fix. The JSON fragment below separately hashes the six selected display
excerpts, matching the publisher's current selected-hunk hash convention.

## Complete source-to-sink

At the vulnerable carrier, `VideoMediaIO` says configuration can come from the
runtime API field `media_io_kwargs` and filters request-selected GPU backends
([carrier `media/video.py` lines 22–50](https://github.com/vllm-project/vllm/blob/e23b19309b8705b21c3b3ff4129c9974ba15a419/vllm/multimodal/media/video.py#L22-L50)).
The filter calls `backend_requires_gpu()`, which defaults an unregistered name to
`False` ([carrier `video.py` lines 68–96](https://github.com/vllm-project/vllm/blob/e23b19309b8705b21c3b3ff4129c9974ba15a419/vllm/multimodal/video.py#L68-L96)).
DeepStream is an inner codec of the loader registered only as `opencv`
([carrier lines 937–952](https://github.com/vllm-project/vllm/blob/e23b19309b8705b21c3b3ff4129c9974ba15a419/vllm/multimodal/video.py#L937-L952)),
so `backend_requires_gpu("deepstream")` returns false.

The resulting path is:

`runtime media_io_kwargs` → `backend=deepstream` survives the GPU filter →
`pool_size` reaches `VideoBackend.load_bytes()` → the first request initializes
the process-wide `DecodePool` → `probe_metadata()` returns `_w, _h` but they are
not checked → bytes reach NVDEC → oversized decode and shared-worker pressure can
starve concurrent work.

The omission is visible by comparison inside the same carrier: OpenCV, PyAV, and
TorchCodec call `_check_frame_pixel_limit()` before decoding
([lines 1036–1084](https://github.com/vllm-project/vllm/blob/e23b19309b8705b21c3b3ff4129c9974ba15a419/vllm/multimodal/video.py#L1036-L1084)),
while DeepStream proceeds from probe to decode without it
([lines 1096–1121](https://github.com/vllm-project/vllm/blob/e23b19309b8705b21c3b3ff4129c9974ba15a419/vllm/multimodal/video.py#L1096-L1121)).

## Candidate excerpts and reader annotations

These are focused, exact excerpts from the candidate diff. Their smaller hunk
headers describe the actual old/new line spans; no source line is rewritten.

### C1 — codec identity bypasses the request GPU policy

```diff
@@ -755,7 +863,8 @@
 @VIDEO_LOADER_REGISTRY.register("opencv")
 class VideoBackend(
     VideoLoader,
     OpenCVVideoBackendMixin,
     PyAVVideoBackendMixin,
     PyNvVideoCodecVideoBackendMixin,
+    DeepStreamVideoBackendMixin,
 ):
```

Annotation:

> DeepStream is added as an inner codec of the loader registered as `opencv`, not
> as its own GPU backend. At the vulnerable landing, the request filter therefore
> treats `backend=deepstream` as CPU-safe and allows unreserved GPU work. The fix
> explicitly registers `deepstream` as a GPU codec.

Source: [candidate lines 863–870](https://github.com/vllm-project/vllm/blob/9dbcf8c3d5de23925195bac6217fc85df6e8bb71/vllm/multimodal/video.py#L863-L870).

### C2 — one request sizes a process-wide GPU pool

```diff
@@ -754,0 +770,34 @@
+    # Process-wide lazy decode pool, shared across all DeepStream backends.
+    _pool: ClassVar[Any] = None
+    _pool_lock: ClassVar[Any] = None
+
+    @classmethod
+    def _get_pool(cls, pool_size: int | None = None):
+        """Lazy-initialize the shared decode pool on first use.
+
+        ``pool_size`` (number of decode worker threads) comes from
+        ``--media-io-kwargs`` (``{"video": {"pool_size": N}}``); when unset it
+        defaults to the existing ``VLLM_MEDIA_LOADING_THREAD_COUNT`` so no
+        DeepStream-specific env var is needed. The pool is a process-wide
+        singleton, so the first decode's value wins.
+        """
+        if cls._pool is not None:
+            return cls._pool
+        if cls._pool_lock is None:
+            cls._pool_lock = threading.Lock()
+        with cls._pool_lock:
+            if cls._pool is not None:
+                return cls._pool
+            import os
+
+            from nvidia.deepstream_videodecode import DecodePool
+
+            if pool_size is None:
+                pool_size = os.environ.get("VLLM_MEDIA_LOADING_THREAD_COUNT", 8)
+            pool_size = max(1, min(int(pool_size), 16))
+            logger.info(
+                "[DeepStream] initializing decode pool with %d workers",
+                pool_size,
+            )
+            cls._pool = DecodePool(num_workers=pool_size)
+            return cls._pool
```

Annotation:

> `pool_size` comes from request media settings, is clamped, and then sizes a
> process-wide singleton whose first value persists for every later decode. One
> caller can therefore choose the shared GPU worker count. The fix removes
> request-level `pool_size` before settings are merged.

Source: [candidate lines 770–803](https://github.com/vllm-project/vllm/blob/9dbcf8c3d5de23925195bac6217fc85df6e8bb71/vllm/multimodal/video.py#L770-L803).

### C3 — probed dimensions are discarded before GPU decode

```diff
@@ -871,0 +980,28 @@
+        elif backend == "deepstream":
+            assert not frame_recovery, (
+                "frame_recovery is only available for `opencv` backend"
+            )
+            # Decode-pool size comes from media-io-kwargs (no env var); the
+            # pool is a process-wide singleton so the first decode's value
+            # wins. Pop it so it isn't forwarded to the frame sampler.
+            pool_size = kwargs.pop("pool_size", None)
+            # Probe container metadata from the bytes via GStreamer (in
+            # the deepstream video-decode wheel) — no PyAV/pymediainfo, no path.
+            from nvidia.deepstream_videodecode import probe_metadata
+
+            total_frames, original_fps, duration, _w, _h, codec = (
+                probe_metadata(data)
+            )
+            source = cls._prepare_source(
+                VideoSourceMetadata(
+                    total_frames_num=total_frames,
+                    original_fps=original_fps,
+                    duration=duration,
+                )
+            )
+            frame_idx = cls.compute_frames_index_to_sample(
+                source=source, target=target, **kwargs
+            )
+            frames, valid = cls.decode_indices(
+                data, frame_idx, source, codec=codec, pool_size=pool_size
+            )
```

Annotation:

> The request-selected branch reads both `pool_size` and the video's width and
> height, but discards `_w` and `_h` before sending the bytes to the GPU pool.
> Oversized videos thus bypass the normal pixel limit and can starve other work.
> The fix validates those dimensions before decoding.

Source: [candidate lines 980–1007](https://github.com/vllm-project/vllm/blob/9dbcf8c3d5de23925195bac6217fc85df6e8bb71/vllm/multimodal/video.py#L980-L1007).

## Fix excerpts and reader annotations

### F1 — classify the inner codec as GPU-backed

```diff
@@ -92,6 +92,10 @@ def get_backend_for_video_processor(
 
         return self.processor2backend.get(video_processor)
 
+    def register_gpu_codec(self, name: str) -> None:
+        """Mark a codec name as requiring GPU without registering a loader."""
+        self._requires_gpu[name] = True
+
     def backend_requires_gpu(self, name: str) -> bool:
         return self._requires_gpu.get(name, False)
 
@@ -208,6 +212,7 @@ def create_hf_metadata(
 
 
 VIDEO_LOADER_REGISTRY = VideoLoaderRegistry()
+VIDEO_LOADER_REGISTRY.register_gpu_codec("deepstream")
```

Annotation:

> Requests select the codec with `backend=deepstream`. Marking that name as
> GPU-backed makes the existing merge policy reject request-level activation
> unless DeepStream was configured at startup, preventing a caller from starting
> GPU decode work for which the server reserved no resources.

Sources: [fix lines 95–100](https://github.com/vllm-project/vllm/blob/d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd/vllm/multimodal/video.py#L95-L100)
and [214–215](https://github.com/vllm-project/vllm/blob/d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd/vllm/multimodal/video.py#L214-L215).

### F2 — keep shared pool sizing out of request data

```diff
@@ -35,6 +35,7 @@ def merge_kwargs(
             # Decoder GPU memory is reserved from the startup value.
             runtime_kwargs = dict(runtime_kwargs)
             runtime_kwargs.pop("hw_decoders", None)
+            runtime_kwargs.pop("pool_size", None)
 
             # Block request-level selection of GPU video backends that
             # were not configured (and VRAM-reserved) at startup.
```

Annotation:

> Even when DeepStream is allowed by startup configuration, `pool_size`
> previously came from the request and initialized the shared singleton.
> Removing it from runtime settings keeps the worker count under operator
> control instead of letting the first request choose process-wide GPU
> concurrency.

Source: [fix `media/video.py` lines 35–44](https://github.com/vllm-project/vllm/blob/d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd/vllm/multimodal/media/video.py#L35-L44).

### F3 — enforce the existing pixel limit before decode

```diff
@@ -1136,6 +1141,7 @@ def load_bytes(
             from nvidia.deepstream_videodecode import probe_metadata
 
             total_frames, original_fps, duration, _w, _h, codec = probe_metadata(data)
+            _check_frame_pixel_limit(_w, _h)
             source = cls._prepare_source(
                 VideoSourceMetadata(
                     total_frames_num=total_frames,
```

Annotation:

> `probe_metadata` already returns the request video's width and height.
> Applying the common guard before GPU decode rejects frames over
> `VLLM_MAX_IMAGE_PIXELS`, closing the oversized-video resource-exhaustion path
> instead of merely reading and ignoring the dimensions.

Source: [fix lines 1141–1149](https://github.com/vllm-project/vllm/blob/d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd/vllm/multimodal/video.py#L1141-L1149).

## Why the other current cards should be dropped

- `setup.py` only makes the decoder installable. It does not show the
  request-to-GPU path, the policy mismatch, the singleton, or the omitted limit.
- `docs/features/multimodal_inputs.md` corroborates request configurability, but
  production code already proves it and is the stronger evidence card.
- The fix test file confirms intended behavior, but the three production edits
  directly show every closing control. Keeping the tests would add length without
  closing another causal link.
- `comparison_hunks` should be empty for this record. The UI can then render the
  canonical candidate and fix arrays once, preserving each distinct annotation
  instead of duplicating six cards and suppressing repeated prose.

## Canonical ledger and publisher path

### Current gap

The Neon schema already stores each complete ledger row in `ledger_rows.raw_json`;
there is no column-level migration needed for a `code_evidence` object. The
current row `alias-c1c247c618bb54f97b64b4fb` is revision 2 and has no
`code_evidence` field.

The publisher does not currently consume such a row field:

- `build_case()` chooses `scripts/generated-code-evidence.json` first and cached
  generated-site evidence second (`scripts/publish_tp_ledger.py:1412–1420` and
  `:1550–1562`).
- `ai_summary_overlay()` unconditionally replaces the evidence summary from the
  separate summary map (`:986–1015`).
- `scrub_evidence()` already assigns and checks candidate/fix roles, preserves
  genuine per-hunk annotations, and removes duplicates (`:424–492`).

Thus merely adding canonical data to Neon would not change the site; the general
publisher precedence must be fixed.

### Minimal general change

1. Add optional `code_evidence` to the ledger-row contract, using the existing
   published evidence shape. Candidate/fix causal roles are stored explicitly on
   each hunk and also structurally by `candidate_hunks` versus `fix_hunks`.
2. In `build_case()`, validate `row.get("code_evidence")` as an object when
   present and select it before generated or cached fallback evidence. Reuse the
   resulting `case_evidence` variable when assigning `case["code_evidence"]`;
   do not perform the current second generated-evidence lookup.
3. Make `ai_summary_overlay()` return success without mutation when the selected
   canonical evidence already has a valid public `summary`; use the alias summary
   map only as a legacy fallback.
4. Keep `load_generated_evidence()` only for rows not yet migrated. No vLLM ID,
   SHA, or prose belongs in publisher code.
5. Add one generic publisher test: canonical row evidence wins over conflicting
   generated/cache evidence, its summary survives the overlay, all six roles and
   annotations survive `scrub_evidence()`, and normal site preflight passes.

### Transaction coordination

The same class already appears in
`research/provisional-closure-20260831/ready-ledger-patches.jsonl` with
`expected_revision=2`; that full row adds the verified candidate, carrier, fix,
release, gates, and scope fields. The `code_evidence` value below must be merged
into **that existing full-row patch before it is applied**, not emitted as a
second revision-2 patch. If the ready patch has already been applied, re-read the
new Neon revision and build one fresh full-row patch. `ledger_store.py apply`
does not accept the partial `set` form shown below.

## JSON-ready canonical merge suggestion

This is a machine-parseable merge instruction for the existing full-row ledger
patch. It is deliberately not a website/generated-data override.

```json
{
  "operation": "merge_into_existing_full_row_patch",
  "class_id": "alias-c1c247c618bb54f97b64b4fb",
  "observed_neon_revision": 2,
  "existing_patch": "research/provisional-closure-20260831/ready-ledger-patches.jsonl",
  "set": {
    "code_evidence": {
      "ai_marker": "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
      "fix_marker": null,
      "candidate_url": "https://github.com/vllm-project/vllm/commit/9dbcf8c3d5de23925195bac6217fc85df6e8bb71",
      "fix_url": "https://github.com/vllm-project/vllm/commit/d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd",
      "advisory_url": "https://github.com/advisories/ghsa-hw36-j4q7-vjxx",
      "summary": "Claude-assisted code let requests select DeepStream GPU decoding and control a shared pool without the normal frame-size limit. An unauthenticated client could starve other requests.",
      "steps": [
        {
          "title": "AI change",
          "detail": "Claude-assisted DeepStream code accepted request-selected GPU settings and skipped the shared frame-size guard."
        },
        {
          "title": "Security fix",
          "detail": "The later patch classified DeepStream as GPU-backed, removed request-level pool sizing, and checked dimensions before decode."
        }
      ],
      "candidate_hunks": [
        {
          "file": "vllm/multimodal/video.py",
          "role": "candidate",
          "code": "@@ -755,7 +863,8 @@\n @VIDEO_LOADER_REGISTRY.register(\"opencv\")\n class VideoBackend(\n     VideoLoader,\n     OpenCVVideoBackendMixin,\n     PyAVVideoBackendMixin,\n     PyNvVideoCodecVideoBackendMixin,\n+    DeepStreamVideoBackendMixin,\n ):",
          "annotation": "DeepStream is added as an inner codec of the loader registered as `opencv`, not as its own GPU backend. At the vulnerable landing, the request filter therefore treats `backend=deepstream` as CPU-safe and allows unreserved GPU work. The fix explicitly registers `deepstream` as a GPU codec."
        },
        {
          "file": "vllm/multimodal/video.py",
          "role": "candidate",
          "code": "@@ -754,0 +770,34 @@\n+    # Process-wide lazy decode pool, shared across all DeepStream backends.\n+    _pool: ClassVar[Any] = None\n+    _pool_lock: ClassVar[Any] = None\n+\n+    @classmethod\n+    def _get_pool(cls, pool_size: int | None = None):\n+        \"\"\"Lazy-initialize the shared decode pool on first use.\n+\n+        ``pool_size`` (number of decode worker threads) comes from\n+        ``--media-io-kwargs`` (``{\"video\": {\"pool_size\": N}}``); when unset it\n+        defaults to the existing ``VLLM_MEDIA_LOADING_THREAD_COUNT`` so no\n+        DeepStream-specific env var is needed. The pool is a process-wide\n+        singleton, so the first decode's value wins.\n+        \"\"\"\n+        if cls._pool is not None:\n+            return cls._pool\n+        if cls._pool_lock is None:\n+            cls._pool_lock = threading.Lock()\n+        with cls._pool_lock:\n+            if cls._pool is not None:\n+                return cls._pool\n+            import os\n+\n+            from nvidia.deepstream_videodecode import DecodePool\n+\n+            if pool_size is None:\n+                pool_size = os.environ.get(\"VLLM_MEDIA_LOADING_THREAD_COUNT\", 8)\n+            pool_size = max(1, min(int(pool_size), 16))\n+            logger.info(\n+                \"[DeepStream] initializing decode pool with %d workers\",\n+                pool_size,\n+            )\n+            cls._pool = DecodePool(num_workers=pool_size)\n+            return cls._pool",
          "annotation": "`pool_size` comes from request media settings, is clamped, and then sizes a process-wide singleton whose first value persists for every later decode. One caller can therefore choose the shared GPU worker count. The fix removes request-level `pool_size` before settings are merged."
        },
        {
          "file": "vllm/multimodal/video.py",
          "role": "candidate",
          "code": "@@ -871,0 +980,28 @@\n+        elif backend == \"deepstream\":\n+            assert not frame_recovery, (\n+                \"frame_recovery is only available for `opencv` backend\"\n+            )\n+            # Decode-pool size comes from media-io-kwargs (no env var); the\n+            # pool is a process-wide singleton so the first decode's value\n+            # wins. Pop it so it isn't forwarded to the frame sampler.\n+            pool_size = kwargs.pop(\"pool_size\", None)\n+            # Probe container metadata from the bytes via GStreamer (in\n+            # the deepstream video-decode wheel) — no PyAV/pymediainfo, no path.\n+            from nvidia.deepstream_videodecode import probe_metadata\n+\n+            total_frames, original_fps, duration, _w, _h, codec = (\n+                probe_metadata(data)\n+            )\n+            source = cls._prepare_source(\n+                VideoSourceMetadata(\n+                    total_frames_num=total_frames,\n+                    original_fps=original_fps,\n+                    duration=duration,\n+                )\n+            )\n+            frame_idx = cls.compute_frames_index_to_sample(\n+                source=source, target=target, **kwargs\n+            )\n+            frames, valid = cls.decode_indices(\n+                data, frame_idx, source, codec=codec, pool_size=pool_size\n+            )",
          "annotation": "The request-selected branch reads both `pool_size` and the video's width and height, but discards `_w` and `_h` before sending the bytes to the GPU pool. Oversized videos thus bypass the normal pixel limit and can starve other work. The fix validates those dimensions before decoding."
        }
      ],
      "fix_hunks": [
        {
          "file": "vllm/multimodal/video.py",
          "role": "fix",
          "code": "@@ -92,6 +92,10 @@ def get_backend_for_video_processor(\n \n         return self.processor2backend.get(video_processor)\n \n+    def register_gpu_codec(self, name: str) -> None:\n+        \"\"\"Mark a codec name as requiring GPU without registering a loader.\"\"\"\n+        self._requires_gpu[name] = True\n+\n     def backend_requires_gpu(self, name: str) -> bool:\n         return self._requires_gpu.get(name, False)\n \n@@ -208,6 +212,7 @@ def create_hf_metadata(\n \n \n VIDEO_LOADER_REGISTRY = VideoLoaderRegistry()\n+VIDEO_LOADER_REGISTRY.register_gpu_codec(\"deepstream\")",
          "annotation": "Requests select the codec with `backend=deepstream`. Marking that name as GPU-backed makes the existing merge policy reject request-level activation unless DeepStream was configured at startup, preventing a caller from starting GPU decode work for which the server reserved no resources."
        },
        {
          "file": "vllm/multimodal/media/video.py",
          "role": "fix",
          "code": "@@ -35,6 +35,7 @@ def merge_kwargs(\n             # Decoder GPU memory is reserved from the startup value.\n             runtime_kwargs = dict(runtime_kwargs)\n             runtime_kwargs.pop(\"hw_decoders\", None)\n+            runtime_kwargs.pop(\"pool_size\", None)\n \n             # Block request-level selection of GPU video backends that\n             # were not configured (and VRAM-reserved) at startup.",
          "annotation": "Even when DeepStream is allowed by startup configuration, `pool_size` previously came from the request and initialized the shared singleton. Removing it from runtime settings keeps the worker count under operator control instead of letting the first request choose process-wide GPU concurrency."
        },
        {
          "file": "vllm/multimodal/video.py",
          "role": "fix",
          "code": "@@ -1136,6 +1141,7 @@ def load_bytes(\n             from nvidia.deepstream_videodecode import probe_metadata\n \n             total_frames, original_fps, duration, _w, _h, codec = probe_metadata(data)\n+            _check_frame_pixel_limit(_w, _h)\n             source = cls._prepare_source(\n                 VideoSourceMetadata(\n                     total_frames_num=total_frames,",
          "annotation": "`probe_metadata` already returns the request video's width and height. Applying the common guard before GPU decode rejects frames over `VLLM_MAX_IMAGE_PIXELS`, closing the oversized-video resource-exhaustion path instead of merely reading and ignoring the dimensions."
        }
      ],
      "comparison_hunks": [],
      "candidate_patch_sha256": "ec3d7aa6d2f45f4c758cb1840c4b3d888313a58ec9cf9542f28aa4e97ecebac0",
      "fix_patch_sha256": "a995f30db711aa0a61bc8cd85749b5845d7be4084158976d1391c69fdef42ecb"
    }
  }
}
```

## Validation and claim boundary

- All six displayed excerpts were matched against their final candidate or fix
  blob; the candidate parent lacks DeepStream and the fix parent lacks all three
  closing additions.
- The JSON block parses as one object. Its summary is 182 characters. Every
  annotation is 267–294 characters and passes the current `public_explanation()`
  contract.
- Selected-hunk hashes are deterministic SHA-256 over the newline-joined `code`
  strings: candidate `ec3d7aa6…ecebac0`, fix `a995f30d…ef42ecb`.
- The evidence supports resource exhaustion / denial of service. It does not
  support code execution, data disclosure, or a claim that every DeepStream
  request exhausts the GPU.
- No generated evidence, website code, Neon row, ledger export, or existing
  patch file was modified, and no commit was created.
