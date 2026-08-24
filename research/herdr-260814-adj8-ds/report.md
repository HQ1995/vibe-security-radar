# Adjudication report — unr-adj-slice-8 (25 rows)

Verdict: **0 countable**. 24 REJECT, 1 REJECT_AI_FIX_ONLY. Every candidate AI commit is in a code area disjoint from the mechanism named by its advisory.

Method: read each first-party advisory JSON from the local advisory-database clone (git show HEAD:advisories/unreviewed/...), fetched each candidate AI commit into the sweep pool via git smart-HTTP (--filter=blob:none, no GitHub API, no blame/SZZ), then compared the commit's changed files (git diff-tree) and message against the advisory mechanism.

Cross-cutting observation: all 25 advisories are unreviewed (`github_reviewed: false`) with an empty `affected[]` (no package/version range). This is itself a release_gate/identity_gate caveat, but the decisive gate is ai_hunk_gate, which fails for every row.


## Rows

### GHSA-5CG2-9V3X-66CV — Cinnamon/kotaemon → REJECT

- alias: CVE-2026-69098, CWE CWE-502

- mechanism: kotaemon through 0.12.0: insecure deserialization in the check_connection endpoint allows unauthenticated attackers to instantiate arbitrary Python classes via a crafted __type__ field in YAML/JSON input, reaching RCE.

- candidates: 37cdc28ceb46, 03d5a1d29dcf

- candidate files: libs/ktem/ktem/index/file/ui.py (path-traversal fix; check_connection is a different module)

- AI marker: Copilot <175728472+Copilot@users.noreply.github.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (insecure deserialization in check_connection endpoint (RCE)): libs/ktem/ktem/index/file/ui.py (path-traversal fix; check_connection is a different module)


### GHSA-84VG-9R54-XPGH — dgtlmoon/changedetection.io → REJECT

- alias: CVE-2026-71204, CWE CWE-284

- mechanism: /settings handler builds update dict from form.data and blind-merges into stored settings; unchecked checkbox becomes False, silently disabling api_access_token_enabled for the REST API.

- candidates: 126c9864f877, 1a2e9309ed2c

- candidate files: tests/unit/test_step_failure_notification.py; restock_diff/* (out-of-stock detection) — neither touches the /settings save handler

- AI marker: Claude Sonnet 4.6 <noreply@anthropic.com> / Claude <noreply@anthropic.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (/settings save handler blind-merge disables API key enforcement): tests/unit/test_step_failure_notification.py; restock_diff/* (out-of-stock detection) — neither touches the /settings save handler


### GHSA-9VX6-GPFR-5QQ7 — dgtlmoon/changedetection.io → REJECT

- alias: CVE-2026-71203, CWE CWE-306

- mechanism: REST API Spec resource at /api/v1/full-spec (changedetectionio/api/Spec.py) lacks @auth.check_token and @validate_openapi_request; leaks full OpenAPI schema when API auth is enabled.

- candidates: 126c9864f877, 1a2e9309ed2c

- candidate files: tests/unit/test_step_failure_notification.py; restock_diff/* — neither touches api/Spec.py

- AI marker: Claude Sonnet 4.6 / Claude <noreply@anthropic.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (/api/v1/full-spec Spec resource missing @auth.check_token): tests/unit/test_step_failure_notification.py; restock_diff/* — neither touches api/Spec.py


### GHSA-VWQF-JX9P-3VGP — dgtlmoon/changedetection.io → REJECT

- alias: CVE-2026-71205, CWE CWE-307

- mechanism: /login checks a single PBKDF2 hash with no per-IP/session rate limit or lockout; brute-force guess grants full admin access.

- candidates: 126c9864f877, 1a2e9309ed2c

- candidate files: tests/unit/test_step_failure_notification.py; restock_diff/* — neither touches /login or auth

- AI marker: Claude Sonnet 4.6 / Claude <noreply@anthropic.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (/login brute-force with no rate limiting/lockout): tests/unit/test_step_failure_notification.py; restock_diff/* — neither touches /login or auth


### GHSA-2MW2-H8HJ-XPJG — eclipse-theia/theia → REJECT

- alias: CVE-2026-60009, CWE CWE-22

- mechanism: @theia/filesystem POST /file-upload moves attacker-supplied absolute path with overwrite and no workspace confinement/auth, enabling RCE via e.g. ~/.bashrc.

- candidates: a49f01380946, adc480cd2d10

- candidate files: plugin-ext main-file-system-event-service.ts (watch skipping); ai-chat-ui/* (Ask AI mode selector) — neither touches @theia/filesystem upload handler

- AI marker: Claude Opus 4.8 / Copilot@users.noreply.github.com

- reasoning: candidate AI commit(s) do not introduce the named mechanism (POST /file-upload unauthenticated arbitrary file write): plugin-ext main-file-system-event-service.ts (watch skipping); ai-chat-ui/* (Ask AI mode selector) — neither touches @theia/filesystem upload handler


### GHSA-34GW-V4CC-PV7C — eclipse-theia/theia → REJECT

- alias: CVE-2026-12609, CWE CWE-22

- mechanism: @theia/plugin-ext /hostedPlugin endpoint resolves file path with path.resolve without confinement; percent-encoded ../ escapes the plugin dir to read arbitrary files.

- candidates: a49f01380946, adc480cd2d10

- candidate files: plugin-ext main-file-system-event-service.ts (watch skipping, not the /hostedPlugin HTTP resolver); ai-chat-ui/* — neither authors the hostedPlugin path resolution

- AI marker: Claude Opus 4.8 / Copilot@users.noreply.github.com

- reasoning: candidate AI commit(s) do not introduce the named mechanism (/hostedPlugin/:pluginId/:path path traversal file read): plugin-ext main-file-system-event-service.ts (watch skipping, not the /hostedPlugin HTTP resolver); ai-chat-ui/* — neither authors the hostedPlugin path resolution


### GHSA-5F8H-2XPH-WWXV — eclipse-theia/theia → REJECT

- alias: CVE-2026-14574, CWE CWE-1321

- mechanism: @theia/core PreferenceUtils.merge recursively merges without rejecting __proto__/constructor/prototype, polluting Object.prototype from crafted workspace settings.

- candidates: a49f01380946, adc480cd2d10

- candidate files: plugin-ext main-file-system-event-service.ts; ai-chat-ui/* — neither touches @theia/core PreferenceUtils

- AI marker: Claude Opus 4.8 / Copilot@users.noreply.github.com

- reasoning: candidate AI commit(s) do not introduce the named mechanism (PreferenceUtils.merge prototype pollution): plugin-ext main-file-system-event-service.ts; ai-chat-ui/* — neither touches @theia/core PreferenceUtils


### GHSA-XRRM-6636-87R2 — eclipse-theia/theia → REJECT

- alias: CVE-2026-61891, CWE CWE-22

- mechanism: @theia/filesystem GET/PUT /file, /files/ convert client URI directly to path and stream file without workspace confinement/auth.

- candidates: a49f01380946, adc480cd2d10

- candidate files: plugin-ext main-file-system-event-service.ts; ai-chat-ui/* — neither touches @theia/filesystem download endpoints

- AI marker: Claude Opus 4.8 / Copilot@users.noreply.github.com

- reasoning: candidate AI commit(s) do not introduce the named mechanism (GET /file download endpoints unauthenticated arbitrary file read): plugin-ext main-file-system-event-service.ts; ai-chat-ui/* — neither touches @theia/filesystem download endpoints


### GHSA-7FF3-W2CQ-GMPQ — penpot/penpot → REJECT

- alias: CVE-2026-17613, CWE CWE-862

- mechanism: Penpot ::import-binfile RPC lacks authorization on optional file-id, allowing any authenticated user to overwrite files and subscribe to WebSocket events (data exfil/poisoning).

- candidates: 68b1e0b8a006

- candidate files: package.json across submodules (pnpm 10.31.0 bump) — no application code, does not touch the import-binfile RPC

- AI marker: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (::import-binfile RPC missing authorization on file-id): package.json across submodules (pnpm 10.31.0 bump) — no application code, does not touch the import-binfile RPC


### GHSA-67QV-R9GC-CPWJ — django-helpdesk/django-helpdesk → REJECT

- alias: CVE-2026-73531, CWE CWE-79

- mechanism: django-helpdesk before 2.3.3: unauthenticated attackers inject JS via HTML-formatted email or .html/.htm attachments; lack of sanitization/Content-Disposition at attachment-serving layer.

- candidates: b0375c5da9fc

- candidate files: helpdesk/settings.py, tests/test_email_notifications.py, update_ticket.py (HELPDESK_PRIVATE_FOLLOWUP_MEANS_NO_EMAILS) — email notification suppression, not attachment sanitization/XSS

- AI marker: Claude <noreply@anthropic.com> (Generated with Claude Code)

- reasoning: candidate AI commit(s) do not introduce the named mechanism (stored XSS via HTML email/attachment through public ticket submission): helpdesk/settings.py, tests/test_email_notifications.py, update_ticket.py (HELPDESK_PRIVATE_FOLLOWUP_MEANS_NO_EMAILS) — email notification suppression, not attachment sanitization/XSS


### GHSA-4G73-GQQH-RFJC — eclipse-theia/theia → REJECT

- alias: CVE-2026-19884, CWE CWE-15

- mechanism: Theia <=1.69.0 runs git status on opening a folder without trust; attacker-controlled .git/config core.fsmonitor executes arbitrary commands.

- candidates: a49f01380946, adc480cd2d10

- candidate files: plugin-ext main-file-system-event-service.ts; ai-chat-ui/* — neither touches @theia/git or workspace trust

- AI marker: Claude Opus 4.8 / Copilot@users.noreply.github.com

- reasoning: candidate AI commit(s) do not introduce the named mechanism (untrusted workspace runs git commands (core.fsmonitor)): plugin-ext main-file-system-event-service.ts; ai-chat-ui/* — neither touches @theia/git or workspace trust


### GHSA-F46F-FJF4-H4M2 — redis/redis → REJECT

- alias: CVE-2025-46686, CWE CWE-401/CWE-789

- mechanism: Redis through 7.4.3 allocates memory for every bulk argument even when the command is skipped for insufficient permissions.

- candidates: fa040a72c072, abaed0d54c9a, 5d0d64b062c1

- candidate files: src/t_stream.c + command defs (XDELEX/XACKDEL); src/zmalloc.c + jemalloc; src/defrag.c/ebuckets.c — none touch command argument allocation/processCommand permission path

- AI marker: Copilot <175728472+Copilot@users.noreply.github.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (multi-bulk command argument allocation memory DoS): src/t_stream.c + command defs (XDELEX/XACKDEL); src/zmalloc.c + jemalloc; src/defrag.c/ebuckets.c — none touch command argument allocation/processCommand permission path


### GHSA-QGM9-FP3R-VM5V — modelscope/ms-swift → REJECT

- alias: CVE-2025-50472, CWE CWE-502

- mechanism: ms-swift <=2.6.1: load_model_meta() uses pickle.load on untrusted .mdl payload (swift/hub/utils/caching.py), enabling RCE.

- candidates: 5651c468d512, c7baf18c9317, 95ee4d63a4c1

- candidate files: swift/trainers/rlhf_trainer/grpo_trainer.py (+ GRPO docs/args) — none touch swift/hub/utils/caching.py or load_model_meta

- AI marker: gemini-code-assist[bot] <176961590+gemini-code-assist[bot]@users.noreply.github.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (pickle.load deserialization in load_model_meta (ModelFileSystemCache)): swift/trainers/rlhf_trainer/grpo_trainer.py (+ GRPO docs/args) — none touch swift/hub/utils/caching.py or load_model_meta


### GHSA-RQ73-JWRW-JMGW — impress-org/givewp → REJECT

- alias: CVE-2025-8620, CWE CWE-200

- mechanism: GiveWP <=4.6.0: unauthenticated attackers extract donor names, emails, donor id.

- candidates: 9c1816448262, 1c07a03200d0, f4996b1b901e

- candidate files: give-subscription.php (renewal quarter); class-settings-email.php (i18n); .cursor/rules/* — none touch donor data retrieval/export

- AI marker: Copilot <175728472+Copilot@users.noreply.github.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (unauth donor name/email/id information exposure): give-subscription.php (renewal quarter); class-settings-email.php (i18n); .cursor/rules/* — none touch donor data retrieval/export


### GHSA-MXRC-JW32-G6PM — impress-org/givewp → REJECT

- alias: CVE-2025-47444, CWE CWE-201/CWE-862

- mechanism: GiveWP before 4.6.1: sensitive info inserted into sent data / broken access control exposes embedded sensitive data.

- candidates: 9c1816448262, 1c07a03200d0, f4996b1b901e

- candidate files: give-subscription.php; class-settings-email.php; .cursor/rules/* — none touch the PII exposure path

- AI marker: Copilot <175728472+Copilot@users.noreply.github.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (sensitive donor PII in sent data (PII exposure)): give-subscription.php; class-settings-email.php; .cursor/rules/* — none touch the PII exposure path


### GHSA-2WMV-MM4P-P4MX — milvus-io/milvus → REJECT

- alias: CVE-2025-15453, CWE CWE-20

- mechanism: milvus up to 2.6.7: expr.Exec (pkg/util/expr/expr.go) deserialization via HTTP endpoint argument code.

- candidates: 8c73ab660370, 846cf52a953f, a4519b46f1cb

- candidate files: proxy/util_test.go + httpserver tests (credential separator); core query PlanNode*.cpp (vector plan node consolidation) — none touch pkg/util/expr/expr.go

- AI marker: Claude/Copilot (co-author trailers)

- reasoning: candidate AI commit(s) do not introduce the named mechanism (expr.Exec deserialization in pkg/util/expr/expr.go (HTTP endpoint)): proxy/util_test.go + httpserver tests (credential separator); core query PlanNode*.cpp (vector plan node consolidation) — none touch pkg/util/expr/expr.go


### GHSA-5J5Q-MQH9-W768 — linkingvision/rapidvms → REJECT

- alias: CVE-2026-33848, CWE CWE-119

- mechanism: Improper restriction of operations within bounds of a memory buffer in rapidvms before PR#96.

- candidates: 87f6ee96a1c1, 2bd0e2337e26, 633522edb127

- candidate files: 3rdparty/ffmpeg/libavcodec/{xwddec.c,mpegvideodsp.c,dfa.c} — these are vendored upstream ffmpeg FIXES ('Check bpp more completely', 'Fix signedness bug', 'Fix off by 1 error'), remediation not introduction, and unrelated to the rapidvms PR#96 fix

- AI marker: openhands <openhands@all-hands.dev> (author identity pair)

- reasoning: candidate AI commit(s) do not introduce the named mechanism (memory buffer overflow before PR#96): 3rdparty/ffmpeg/libavcodec/{xwddec.c,mpegvideodsp.c,dfa.c} — these are vendored upstream ffmpeg FIXES ('Check bpp more completely', 'Fix signedness bug', 'Fix off by 1 error'), remediation not introduction, and unrelated to the rapidvms PR#96 fix


### GHSA-M5F3-G632-8VR5 — linkingvision/rapidvms → REJECT

- alias: CVE-2026-33849, CWE CWE-119

- mechanism: Improper restriction of operations within bounds of a memory buffer in rapidvms before PR#96.

- candidates: 87f6ee96a1c1, 2bd0e2337e26, 633522edb127

- candidate files: 3rdparty/ffmpeg/libavcodec/{xwddec.c,mpegvideodsp.c,dfa.c} — vendored ffmpeg FIXES, not the rapidvms PR#96 memory-overflow introduction

- AI marker: openhands <openhands@all-hands.dev>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (memory buffer overflow before PR#96): 3rdparty/ffmpeg/libavcodec/{xwddec.c,mpegvideodsp.c,dfa.c} — vendored ffmpeg FIXES, not the rapidvms PR#96 memory-overflow introduction


### GHSA-WJVP-54G5-W8P5 — linkingvision/rapidvms → REJECT

- alias: CVE-2026-33847, CWE CWE-119

- mechanism: Improper restriction of operations within bounds of a memory buffer in rapidvms before PR#98.

- candidates: 87f6ee96a1c1, 2bd0e2337e26, 633522edb127

- candidate files: 3rdparty/ffmpeg/libavcodec/{xwddec.c,mpegvideodsp.c,dfa.c} — vendored ffmpeg FIXES, not the rapidvms PR#98 memory-overflow introduction

- AI marker: openhands <openhands@all-hands.dev>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (memory buffer overflow before PR#98): 3rdparty/ffmpeg/libavcodec/{xwddec.c,mpegvideodsp.c,dfa.c} — vendored ffmpeg FIXES, not the rapidvms PR#98 memory-overflow introduction


### GHSA-FX6G-Q2XM-RMCH — getgrav/grav → REJECT

- alias: CVE-2026-29924, CWE CWE-611

- mechanism: Grav CMS v1.7.x: XML External Entity via SVG file upload in admin panel and File Manager.

- candidates: 2dcf91799901, bf7dd2e6c808, 508650583aae

- candidate files: system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php (Twig3 regex / JIT stack exhaustion) — no relation to SVG upload or XML/XXE parsing

- AI marker: Copilot / Claude Opus 4.5 <noreply@anthropic.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (XXE via SVG upload (admin panel / File Manager)): system/src/Grav/Common/Twig/Compatibility/Twig3CompatibilityTransformer.php (Twig3 regex / JIT stack exhaustion) — no relation to SVG upload or XML/XXE parsing


### GHSA-H848-FW25-HP2W — rizinorg/rizin → REJECT

- alias: CVE-2026-31053, CWE CWE-415

- mechanism: librz/bin/format/le/le.c le_load_fixup_record double-frees relocation entries on malformed LE fixup chains.

- candidates: 5fab5584e2cb, 68da5f7db2f1

- candidate files: librz/bin/format/cart/* (CaRT extractor); librz/arch/isa/h8500/* (Renesas H8/500) — neither touches le.c

- AI marker: Cursor <cursoragent@cursor.com> / Copilot <175728472+Copilot@users.noreply.github.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (double free in le_load_fixup_record (LE format)): librz/bin/format/cart/* (CaRT extractor); librz/arch/isa/h8500/* (Renesas H8/500) — neither touches le.c


### GHSA-HH47-VF3P-8VQ5 — LibreDWG/libredwg → REJECT

- alias: CVE-2026-9500, CWE CWE-119

- mechanism: GNU LibreDWG up to 0.14: read_2004_compressed_section (src/decode.c) heap-based buffer overflow (Dwgread utility).

- candidates: 0fe26633dbad, 0b573035901f, 59c2dae4e536

- candidate files: src/encode.c, in_dxf.c, out_dxf.c, *.spec (r11 DXF roundtrip); src/bits.c/bits.h (ATTRIBUTE_MALLOC) — none touch src/decode.c read_2004_compressed_section

- AI marker: Claude Sonnet 4.6 / Claude Opus 4.7 / Kimi-k2.6

- reasoning: candidate AI commit(s) do not introduce the named mechanism (heap buffer overflow in read_2004_compressed_section (decode.c)): src/encode.c, in_dxf.c, out_dxf.c, *.spec (r11 DXF roundtrip); src/bits.c/bits.h (ATTRIBUTE_MALLOC) — none touch src/decode.c read_2004_compressed_section


### GHSA-5PPW-FXGQ-3W56 — LibreDWG/libredwg → REJECT

- alias: CVE-2026-9529, CWE CWE-404

- mechanism: GNU LibreDWG up to 0.14: match_BLOCK_HEADER (dwggrep.c) null pointer dereference (Dwggrep utility).

- candidates: 0fe26633dbad, 0b573035901f, 59c2dae4e536

- candidate files: src/encode.c, in_dxf.c, out_dxf.c, *.spec; src/bits.c/bits.h — none touch dwggrep.c match_BLOCK_HEADER

- AI marker: Claude Sonnet 4.6 / Claude Opus 4.7 / Kimi-k2.6

- reasoning: candidate AI commit(s) do not introduce the named mechanism (null pointer dereference in match_BLOCK_HEADER (dwggrep.c)): src/encode.c, in_dxf.c, out_dxf.c, *.spec; src/bits.c/bits.h — none touch dwggrep.c match_BLOCK_HEADER


### GHSA-WJP4-MF92-6WH6 — cosimo/perl5-net-statsd → REJECT_AI_FIX_ONLY

- alias: CVE-2026-46739, CWE CWE-93

- mechanism: Net::Statsd before 0.13: metric names/values not checked for newlines/colons/pipes; untrusted sources can inject extra metrics.

- candidates: 583dfdf03851, a10b10173d67

- candidate files: t/sec-CVE-2026-46739.t (tests); lib/Net/Statsd.pm (_validate_metric_name/value) — these ARE the remediation for CVE-2026-46739, not its introduction

- AI marker: Claude Opus 4.8 <noreply@anthropic.com>

- reasoning: candidate AI commit(s) do not introduce the named mechanism (metric injection (unvalidated metric names/values)): t/sec-CVE-2026-46739.t (tests); lib/Net/Statsd.pm (_validate_metric_name/value) — these ARE the remediation for CVE-2026-46739, not its introduction


### GHSA-JF4X-778M-8CJ9 — 389ds/389-ds-base → REJECT

- alias: CVE-2026-12528, CWE CWE-787

- mechanism: 389 DS __aclp__normalize_acltxt (aclparse.c): malformed ACI triggers 1-byte OOB write/read during ACI parsing.

- candidates: b90d03e09297, 22278a4e7f08, 87ef50609ba2

- candidate files: src/cockpit/389-console/**/*.jsx (password policy UI, error handling, progress steppers) — none touch aclparse.c or ACI parsing

- AI marker: Cursor (Assisted-by/Generated-by)

- reasoning: candidate AI commit(s) do not introduce the named mechanism (heap buffer overflow in __aclp__normalize_acltxt (aclparse.c)): src/cockpit/389-console/**/*.jsx (password policy UI, error handling, progress steppers) — none touch aclparse.c or ACI parsing

