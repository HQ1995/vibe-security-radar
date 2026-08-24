# Wave-2 sample12 slice-02 directroot (grok-4.6 high)

Proposal-only seven-gate review of the 30 assigned kind-1 directroot rows in slice-02.jsonl. Frozen local clones were used; GitHub API was not. No first-party GHSA JSON was recovered for any assigned ID, so identity_gate is UNKNOWN on every row and the packet stays NONTERMINAL. Missing evidence was not converted into FAIL or FALSE_POSITIVE. Worker PASS would be a proposal only; none is offered.

## Counts

Reviewed 30/30. CONFIRM 0, NARROW 0, FALSE_POSITIVE 0, UNKNOWN 30. terminal_true 0, terminal_false 30. ai_hunk FAIL 9, ai_hunk UNKNOWN 21. identity UNKNOWN 30. countable_pass 0.

## Method and blockers

Evidence is work/facts.json and work/evidence_compact.json over clones under /home/hanqing/.cache/ghsa200-worker-clones/. Advisory roots and OSV caches returned empty hits for all 30 GHSAs. Uniqueness against the canonical ledger was not closed. Release tags, when present, were not mapped to advisory affected ranges because the advisory objects are missing. Shared SHA clusters (hubuum x3, datamodel-code-generator x4, surrealdb error-serialisation x3) are noted but not counted as unique-mechanism PASS.

Closed FAIL is used only where the local git pair shows the ranked AI commit did not author the GHSA-named hunk (no blamed-file touch and/or unrelated chore/refactor/test-only change). Overlap without blamed-line identity stays UNKNOWN, including several incomplete-remediation leads (datamodel --allow-remote-refs, LightRAG CORS, MCP OAuth provider, Gitea Actions permissions, oh-my-posh templates, Fides duplicate approval).

## Per-row gate decisions

01. GHSA-JMH7-G254-2CQ9 gradio-app/gradio: UNKNOWN (LOW, terminal=false, fp_class=AI_NOT_HUNK_AUTHOR; failing=ai_hunk_gate,but_for_gate; open=identity_gate,topology_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 029034f7 is a Gradio 6.0 feature dump; it does not touch blamed gradio/routes.py. Fix fc7c01ea adds proxy_url host validation on that file. Missing first-party GHSA JSON keeps identity UNKNOWN.

02. GHSA-C32J-VQHX-RX3X jwt/ruby-jwt: UNKNOWN (LOW, terminal=false, fp_class=AI_NOT_HUNK_AUTHOR; failing=ai_hunk_gate,but_for_gate; open=identity_gate,topology_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 3a31a200 is ruby-head RSA/JWK compatibility; overlap is CHANGELOG.md and lib/jwt/version.rb, not HMAC empty-key code in lib/jwt/jwa/hmac.rb. Blame file is version.rb. Not the GHSA hunk.

03. GHSA-M98R-6667-4WQ7 aegra/aegra: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 044d0273 (Claude trailer) overlaps runs.py with ownership-fix e1b20422, but blame_files is empty and no advisory object was recovered. Hunk authorship unproved.

04. GHSA-G3VG-VX23-3858 oscal-compass/compliance-trestle: UNKNOWN (LOW, terminal=false, fp_class=AI_NOT_HUNK_AUTHOR; failing=ai_hunk_gate,but_for_gate; open=identity_gate,topology_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI f85944cf is a hatch build migration with no overlap against path-traversal fix 9abc4923, which is a 2-parent merge. No blamed hunk.

05. GHSA-FQ7H-9X26-6J22 external-secrets/external-secrets: UNKNOWN (LOW, terminal=false, fp_class=AI_NOT_HUNK_AUTHOR; failing=ai_hunk_gate,but_for_gate; open=identity_gate,topology_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 472acbb5 is a Copilot/SWE-agent license-header chore. Overlap on externalsecret_validator.go is header stamping, not secret-overwrite validation. Not an AI security hunk.

06. GHSA-FPW6-HRG5-Q5X5 lin-snow/Ech0: UNKNOWN (LOW, terminal=false, fp_class=AI_NOT_HUNK_AUTHOR; failing=ai_hunk_gate,but_for_gate; open=identity_gate,topology_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 2a5b03a7 only prepends SPDX headers and does not overlap the auth/JTI blacklist fix eab62379 (itself Claude-marked). Origin hunk not AI.

07. GHSA-QX5F-GHC2-7G5C ethyca/fides: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI ae74363d adds pre-approval webhook UI and overlaps privacy_request_service.py with duplicate-verification fix e7a6527b. Possible incomplete-remediation, but blame empty and no GHSA JSON, so patch-delta cannot close.

08. GHSA-F45Q-W629-WR25 hubuum/hubuum-client-rust: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Shared hubuum candidate 5d7af9fd / fix 5a5c275f across three GHSAs. File overlap on client transports exists; blamed hunk for redirect escape is not isolated. Identity object missing.

09. GHSA-QQC3-94QV-7FW3 hubuum/hubuum-client-rust: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Same SHA pair as GHSA-F45Q-W629-WR25 and GHSA-2625-RW7M-5Q5X. Custom-transport bypass not isolated from shared client rewrite. Uniqueness vs siblings also unclosed.

10. GHSA-6XJ8-QV9J-XCJQ JanDeDobbeleer/oh-my-posh: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 367ec833 (Claude/Cursor) touches blamed src/prompt/extra.go and overlaps the trusted-template fix 88ddbe0b. Strongest path-segment template lead, but no advisory JSON and no blamed-line identity, so ai_hunk stays UNKNOWN.

11. GHSA-2625-RW7M-5Q5X hubuum/hubuum-client-rust: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Third hubuum advisory on the same SHA pair; diagnostics leak not isolated. Shared-SHA uniqueness unclosed.

12. GHSA-VX7X-VCC2-C44G koxudaxi/datamodel-code-generator: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI f6d4cbd3 is an explicit --allow-remote-refs security rewrite overlapping http.py with DNS-rebinding fix 25c8b7e4. Incomplete-remediation candidate, but no first-party GHSA JSON and no hunk blame.

13. GHSA-4VGR-H27G-CF9P surrealdb/surrealdb: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 0bf1a519 is error-serialisation (Cursor trailer) overlapping RPC files with /rpc session fix 2f53e6e8. Shared with two other SurrealDB GHSAs. Hunk not proved.

14. GHSA-WHWG-VH4F-PMMF surrealdb/surrealdb: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 54efe747 is a RocksDB cursor perf change overlapping processor.rs/purge.rs with edge-PERMISSIONS fix a80d1784. Contributor possible; hunk unproved.

15. GHSA-RFR2-MQ9M-X2QX koxudaxi/datamodel-code-generator: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Same AI f6d4cbd3 as GHSA-VX7X / GHSA-8359 / GHSA-954P; fix 5fdba4a0 is the --url SSRF host-validation closure. Patch-delta blocked by missing advisory object.

16. GHSA-JPW9-PFVF-9F58 modelcontextprotocol/python-sdk: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 2210c1be (Anthropic/bot) authors src/mcp/server/auth/provider.py, which is the blamed file; fix 1abcca24 adds subject/claims on AccessToken. Principal-binding incomplete-remediation lead, but identity/release unclosed.

17. GHSA-FJ8V-HJWV-QM88 go-gitea/gitea: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 45809c8f adds configurable Actions token permissions and touches blamed repo_permission.go with fork-PR guard fix 1d43b736. Patch-delta lead; identity/release unclosed.

18. GHSA-WP87-MGVQ-5J93 surrealdb/surrealdb: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Same AI 0bf1a519 as GHSA-4VGR and GHSA-5QFP; USE NS/DB auto-create fix f3ee3bd5 overlaps executor.rs. Shared-file history is not hunk proof.

19. GHSA-FW57-JGCH-PGF3 go-gitea/gitea: UNKNOWN (LOW, terminal=false, fp_class=AI_NOT_HUNK_AUTHOR; failing=ai_hunk_gate,but_for_gate; open=identity_gate,topology_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Locale quadratic DoS lives in modules/web/middleware/locale.go. AI 0724344a is CodeQL cleanup overlapping org/team.go, not locale.go. Fix f452c369 is a mixed public-token/push-options/locale commit. AI did not author the locale hunk.

20. GHSA-J2W3-9C3R-G83Q go-gitea/gitea: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI f2a1271f unifies public-only token filtering and overlaps user_repo.go/star.go/watch.go with metadata-leak fix 362539b7. Incomplete-remediation possible; blame empty.

21. GHSA-7WPJ-VVMV-PGM8 pionxzh/wakaru: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI refactor splits the monolith; overlap is crates/cli/src/main.rs only. Unpack path-traversal fix touches unpacker modules. Hunk authorship unproved.

22. GHSA-8359-H9FX-J6V9 koxudaxi/datamodel-code-generator: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Same AI f6d4cbd3; file:// $ref traversal fix overlaps jsonschema parser, not the HTTP allow-remote-refs files. Residual sibling-path vs incomplete-remediation unproved without advisory JSON.

23. GHSA-6X6H-QQR7-855W HKUDS/LightRAG: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI  is an explicit CORS wildcard-membership security patch on blamed lightrag_server.py; later fix fails closed on empty CORS_ORIGINS. Strong incomplete-remediation lead, but no GHSA JSON so identity stays UNKNOWN.

24. GHSA-4JWF-M4WG-8P66 microsoft/kiota: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI maps x-ai-capabilities confirmation and overlaps PluginsGenerationService.cs with unsafe static_template.file rejection. Related surface; blamed lines not isolated. AI and fix tags collide on v1.32.5.

25. GHSA-954P-556P-R752 koxudaxi/datamodel-code-generator: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Same AI f6d4cbd3; silent HTTP $ref SSRF shares the allow-remote-refs rewrite. Distinct GHSA from VX7X/RFR2/8359 but uniqueness/identity unclosed.

26. GHSA-5QFP-32CF-69JH surrealdb/surrealdb: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Same AI 0bf1a519; sessions-method leak fix overlaps ntw/rpc.rs and http.rs. Shared SurrealDB error-serialisation candidate, hunk unproved.

27. GHSA-777R-4V59-6486 go-gitea/gitea: UNKNOWN (LOW, terminal=false, fp_class=None; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI 0724344a? wait no: AI is issue-label deletion with Actions tokens (openai/codex) overlapping notifier_helper.go with fork-PR approval-gate fix. Same-file overlap is not gate-bypass hunk proof.

28. GHSA-28GM-JRMW-XX93 sipsorcery-org/sipsorcery: UNKNOWN (LOW, terminal=false, fp_class=AI_NOT_HUNK_AUTHOR; failing=ai_hunk_gate,but_for_gate; open=identity_gate,topology_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    AI aebe49c-equivalent here is  consolidating projects into one repo with zero overlap against RTP/STUN length-check fix. Carrier/refactor, not origin.

29. GHSA-8XCM-R25X-G524 nodejs/undici: UNKNOWN (LOW, terminal=false, fp_class=AI_NOT_HUNK_AUTHOR; failing=ai_hunk_gate,but_for_gate,fix_reversal_gate; open=identity_gate,topology_gate,release_gate,uniqueness_gate)
    AI is a 2-parent merge of main into next with empty file list. Named fix only corrects retry-handler test fixtures. Neither hunk nor reversal closes.

30. GHSA-FM2F-4339-4P2F FlowiseAI/Flowise: UNKNOWN (LOW, terminal=false, fp_class=NO_AI_MARKER; failing=none; open=identity_gate,ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate,uniqueness_gate)
    Assigned AI SHA has n_parents=0, empty subject, and no AI marker. Overlap is Permissions.ts only. Stop at ai_hunk_gate UNKNOWN per 2000-commit / missing-marker rule.

## Disagreement with stored labels

Slice-02 rows carry status=hit routing scores, not ledger verdicts. This worker does not adopt those hits as PASS. No stored CONFIRM/NARROW/FALSE_POSITIVE labels were replayed as evidence. Strongest unfinished leads that a leader could still close after recovering advisory JSON: GHSA-6X6H-QQR7-855W (CORS fail-closed residual), GHSA-JPW9-PFVF-9F58 (OAuth principal binding), GHSA-6XJ8-QV9J-XCJQ (template extras), GHSA-FJ8V-HJWV-QM88 (Actions fork-PR guard), and the datamodel-code-generator f6d4cbd3 quartet under the incomplete-remediation patch-delta rule.

