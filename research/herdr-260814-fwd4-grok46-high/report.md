# fwd-slice-4 timeboxed adjudication

Verdict-first: 0 CONFIRM, 23 FALSE_POSITIVE (no_ai_origin), 2 UNKNOWN, 0 countable. Worker proposal only.

Assigned 25 no-fix-ref rows from fwd-slice-4. Method was agentic file-list and local subject reading. Git blame and SZZ were not used. Unique candidate diffs were not readable because promisor blobs required github.com and DNS failed. Missing evidence was not converted into FAIL; unread overlapping rows stay UNKNOWN.

Identity used local first-party GHSA JSON under commit-oz advisory-database. All 25 advisory files exist for 2026-03. Fix-reversal, release, topology, and uniqueness stay UNKNOWN on every row because this slice has no fix refs and no countable PASS.

## Row 1: GHSA-MQFC-82JX-3MR2 — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate only touches SVG gradientTransform parsing in coders/svg.c plus SVG tests. That cannot create a YUV 4:2:2 decoder overflow.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File and subject mismatch is affirmative exclusion. Diff blobs were not local; remaining gates stay UNKNOWN.

## Row 2: GHSA-WRHR-RF8J-R842 — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate is an SVG gradientTransform double-free fix. It does not touch the PCD decoder.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. coders/svg.c cannot author a PCD decoder overflow. Fix-reversal and release were not opened after causal exclusion.

## Row 3: GHSA-R39Q-JR8H-GCQ2 — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate files are SVG coder and SVG tests, not the SIXEL decoder.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Subsystem mismatch excludes AI hunk authorship of the SIXEL mechanism.

## Row 4: GHSA-932H-JW47-73JM — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate is SVG transform parsing, not morphology kernel parsing.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. No morphology sources appear in the candidate file list.

## Row 5: GHSA-467J-76J7-5885 — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate does not touch the PCL encoder.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. SVG coder change is not a PCL encoder origin.

## Row 6: GHSA-FPVF-FRM6-625Q — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate files are SVG, not MSL decoder sources.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. MSL decoder UAF cannot be introduced by an SVG gradientTransform fix.

## Row 7: GHSA-XXW5-M53X-J38C — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate does not modify MSL encoder code.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. File mismatch excludes AI origin.

## Row 8: GHSA-7H7Q-J33Q-HVPF — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate touches SVG parsing tests, not the MNG encoder.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. MNG encoder overflow is outside the candidate file set.

## Row 9: GHSA-WJ8W-PJXF-9G4F — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate is unrelated SVG gradientTransform handling.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. JBIG decoder is not present in the candidate files.

## Row 10: GHSA-HFFP-Q43Q-QQ76 — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate does not touch DIB coder sources.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. SVG-only file list excludes DIB integer overflow authorship.

## Row 11: GHSA-RQQ8-JH93-F4VG — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate does not modify MagnifyImage.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Transform parsing in svg.c is not MagnifyImage.

## Row 12: GHSA-H95R-C8C7-MRWX — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate files are SVG coder and tests, not UHDR.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. UHDR encoder is outside the candidate diff files.

## Row 13: GHSA-CQW9-W2M7-R2M2 — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate does not touch BilateralBlurImage.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Filter-path overflow cannot be authored by SVG tests plus svg.c transform parsing.

## Row 14: GHSA-5GGV-92R5-CP4P — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate does not modify WaveletDenoiseImage.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. No wavelet-denoise sources in the candidate set.

## Row 15: GHSA-QPG4-J99F-8XCG — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate does not touch WriteXWDImage.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. XWD encoder arithmetic is absent from svg.c and SVG tests.

## Row 16: GHSA-4HJQ-9H5C-252J — FALSE_POSITIVE

Repository: traefik/traefik. Candidate `8ac8473554d7` files: docs/content/expose/docker.md.

Candidate only edits docs/content/expose/docker.md, a docker-guide markdown file, with subject about whoami middleware docs. Markdown cannot create an HTTP/2 frame panic.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Docs-only AI commit is affirmative non-origin. Server HTTP/2 code was not in the file list.

## Row 17: GHSA-92GP-JFGX-9QPV — UNKNOWN

Repository: hyperterse/hyperterse. Candidate `8e7d541c5c32` files: Makefile, README.md, core/cli/cmd/init.go, core/cli/cmd/run.go, core/cli/cmd/start.go, core/cli/internal/loader.go, core/framework/compiler.go, core/framework/types.go.

The unread candidate files are CLI/loader/compiler/types plus Makefile and README. Those names do not prove or disprove creation of an MCP search SQL-exposure surface. Diff blobs were not available locally and GitHub fetch failed.

Gates: identity_gate=PASS, ai_hunk_gate=UNKNOWN, topology_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Missing diff is not converted into FAIL. Identity is first-party; causal gates stay UNKNOWN.

## Row 18: GHSA-GC62-2V5P-QPMP — FALSE_POSITIVE

Repository: ImageMagick/ImageMagick. Candidate `bd4a469adb6d` files: coders/svg.c, tests/Makefile.am, tests/cli-svg.tap, tests/input_svg_gradient_transform.svg.

Candidate files are coders/svg.c and SVG tests, not MagickCore XML-tree sources. Local subject is a double-free fix in SVG gradientTransform/transform parsing, a different mechanism than NewXMLTree overflow.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. NewXMLTree is not in the candidate file set. Unread blobs are not required once the file/subject mismatch excludes the named function.

## Row 19: GHSA-VM69-H85X-8P85 — FALSE_POSITIVE

Repository: siyuan-note/siyuan. Candidate `a539de39ccf7` files: app/src/protyle/render/mermaidRender.ts, app/stage/protyle/js/mermaid/mermaid.min.js.

Candidate is a mermaid v11.13.0 frontend upgrade (mermaidRender.ts and mermaid.min.js). That cannot author a server-side sensitive-path denylist residual.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Frontend mermaid bundle is not the IsSensitivePath boundary.

## Row 20: GHSA-3G9H-9HP4-654V — FALSE_POSITIVE

Repository: siyuan-note/siyuan. Candidate `a539de39ccf7` files: app/src/protyle/render/mermaidRender.ts, app/stage/protyle/js/mermaid/mermaid.min.js.

Same mermaid frontend upgrade. It does not touch WebSocket auth or keepalive handling.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Mermaid renderer files cannot create the keepalive auth bypass.

## Row 21: GHSA-2XR4-CHCF-VMVF — UNKNOWN

Repository: johnbillion/query-monitor. Candidate `2a2939e53abf` files: assets/query-monitor.js, dispatchers/Html.php.

Candidate files are exactly assets/query-monitor.js and dispatchers/Html.php, which can carry reflected Request-URI output. The query-monitor fetch clone was missing and the diff was not read, so AI hunk creation is unproven.

Gates: identity_gate=PASS, ai_hunk_gate=UNKNOWN, topology_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Overlap is not causal proof. Unread diff keeps ai_hunk, but-for, fix-reversal, and release UNKNOWN.

## Row 22: GHSA-WVVQ-WGCR-9Q48 — FALSE_POSITIVE

Repository: traefik/traefik. Candidate `8ac8473554d7` files: docs/content/expose/docker.md.

Docs-only docker.md change cannot alter TLS ClientHello sniffing or mTLS.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Markdown guide is not the TLS sniff path.

## Row 23: GHSA-G3HG-J4JV-CWFR — FALSE_POSITIVE

Repository: traefik/traefik. Candidate `8ac8473554d7` files: docs/content/expose/docker.md.

Candidate only edits docker expose documentation, not BasicAuth middleware comparison code.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Docs-only commit cannot create a password-compare timing oracle.

## Row 24: GHSA-RFX7-8W68-Q57Q — FALSE_POSITIVE

Repository: etcd-io/etcd. Candidate `d741e38c47c6` files: etcdctl/ctlv3/command/util_test.go.

Candidate file is etcdctl/ctlv3/command/util_test.go, a client CLI test. A test helper cannot introduce nested-txn server RBAC bypass.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Object blobs were not local, but the slice file list is already a test-only path outside etcdserver authz.

## Row 25: GHSA-Q8M4-XHHV-38MG — FALSE_POSITIVE

Repository: etcd-io/etcd. Candidate `d741e38c47c6` files: etcdctl/ctlv3/command/util_test.go.

Same etcdctl util_test.go candidate. Multi-API server authorization is not implemented in a CLI test file.

Gates: identity_gate=PASS, ai_hunk_gate=FAIL, topology_gate=UNKNOWN, but_for_gate=FAIL, fix_reversal_gate=UNKNOWN, release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. Countable: no. Test-only file list excludes server API authz origin.

