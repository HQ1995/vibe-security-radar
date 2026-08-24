# G-N deferred heavy repos (n8n, gitea, mise, PraisonAI, gogs)

Terminal: 228=12+216. PASS=0. Canonical94 stays 94 HOLD. Worker PASS is proposal-only and this packet emits none. Greater-than-200 remains unsupported.

## Freeze

Source universe: unreviewed G-N subject-only intersections in `autoresearch/herdr-260813-ghsa200-commitfirst-gn` (cases sha256 `47538e731f8c4979651ff36ead7063ea23a1adc05e551a99ae94ceaafd835b2d`; result sha256 `4443df9d098302be1b3fc3b73dbdc0ae7b76471a5f2f67aeed97c98ec1d6c08a`). Subject-only count 640. Heavy slice n8n-io/n8n, go-gitea/gitea, jdx/mise, MervinPraison/PraisonAI, gogs/gogs = 294.
Excluded canonical94 ledger sha256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` (0 heavy hits) plus every identity with a terminal cases.jsonl verdict in herdr-260813/260814 and orchestrator-260813/260814 after the CF2 freeze (skip work/notes/pages/snapshot/clones/cache/tmp), including CF2 inspected GHSA-25GQ and GHSA-6CQF and G-N source-shard terminals. Heavy terminals excluded: 66. Remaining 228. Equation 294=66+228.
CONTRACT.md sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Matcher `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Rank (desc): source_matcher AI on blamed mechanism hunk, then file-add AI, then atomic AI member, then first-party repo advisory, then same-repo closer object, then atomic closer, then closer-not-policy-AI, then overlap policy AI, then case_id. Hunk and add hits were 0 on the blob:none clones. 14 remaining rows have a local atomic human closer. Cap 12 by case_id. Tied leftovers GHSA-RJV5-9PX2-FQW6 and GHSA-W96V-GF22-CRWP stay UNREVIEWED. Did not pad.
Anonymous smart-HTTP recovered closer/parent blobs for the 12. Shared clones were not mutated. No GitHub REST/GraphQL. No credentials. Carrier trailers, shared SHA, same file, AI-on-fix, and old-bug preservation are not proof.

## Verdicts

### GHSA-38C7-23HJ-2WGQ REJECT

Identity PASS: first-party github-reviewed GHSA-38C7-23HJ-2WGQ, repo n8n-io/n8n, not withdrawn. Advisory sha256 `5ef11eb70e1be754664032a893474afdde2823a2dd75ec35d04ff1d5d61226b3`.
Mechanism: Zendesk Trigger webhook accepts unsigned payloads; closer adds verifySignature.
Closer `3839e310bd4c3002c646c363d1411916fa195151` n_parents=1 email dawid.myslak@gmail.com subject feat(Zendesk Trigger Node): Add webhook signature verification (#24881). Tree `b8fb76d7b1c03c61b35207cb771d29ed9e3d3ea6`. Parent `470f65a22545b404510a300eb558c5ef1a035224` tree `abba98c4e4a7071077b66a4afba34cbf178cd218`. source_matcher empty.
Semantic: verifySignature.call(this) in webhook(); parent blob e46cd59e00 has no verifySignature import.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 1.123.18,2.6.2; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-49MX-FJ45-Q3P6 REJECT

Identity PASS: first-party github-reviewed GHSA-49MX-FJ45-Q3P6, repo n8n-io/n8n, not withdrawn. Advisory sha256 `d886845de5a06c3013941919d2225d7990b7dd39851fe4c28c1910309c985f21`.
Mechanism: JsTaskRunner exposes Buffer.allocUnsafe in the task sandbox.
Closer `2c4c2953199733c791f739a40879ae31ca129aba` n_parents=1 email ivov.src@gmail.com subject Merge commit from fork. Tree `880df87fb0ebd56bceb2603148b74d8668d5f671`. Parent `4c6b0180bd62b4ec79ae752975398a377b59c204` tree `e119d2dca956488a24c7aeebfdc32e7690b5519a`. source_matcher empty.
Semantic: Buffer proxy replaces allocUnsafe/allocUnsafeSlow with Buffer.alloc except mode===insecure.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 1.114.3; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-5VJ6-WJR7-5V9F REJECT

Identity PASS: first-party github-reviewed GHSA-5VJ6-WJR7-5V9F, repo n8n-io/n8n, not withdrawn. Advisory sha256 `0516ca9538a2b1c70461efa2566f100157db09d1c5dc458c66b3a70d3fc06106`.
Mechanism: SigninView honors an open redirect query on /signin.
Closer `4865d1e360a0fe7b045e295b5e1a29daad12314e` n_parents=1 email MarcL@users.noreply.github.com subject fix(editor): Stop nefarious redirects during sign in (#16034). Tree `050c971a461b187b3c746080ecaa481bfb7b58de`. Parent `02ed7b663184276a1aac96b3cd5b6fa54e554baa` tree `7052ae41717b49aaa23c619ba49ff22d6703c7d0`. source_matcher empty.
Semantic: SigninView.vue plus tests; parent blob 6290e77b16 lacks the redirect allowlist added by 4865d1e360.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 1.98.0; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-825Q-W924-XHGX REJECT

Identity PASS: first-party github-reviewed GHSA-825Q-W924-XHGX, repo n8n-io/n8n, not withdrawn. Advisory sha256 `a4bcd5eae9d5ecebbc65a68cc3fb83bf5a928c91b3d6ea013ea10ac3693d1b68`.
Mechanism: html-sandbox isHtmlRenderedContentType misses padded Content-Type and under-applies CSP.
Closer `ced34c0f93ab4c759a56065965986094d8ef7323` n_parents=1 email 10324676+tomi@users.noreply.github.com subject fix(core): Fix html header check (#22713). Tree `f730ac1237bd6f3c78389dfdd7d95659269f2c51`. Parent `57d6015f2ea0442c24e0449105325b7e36f066df` tree `1caca2bc54ce932ff4de7e5a47b887b7a84b6929`. source_matcher empty.
Semantic: contentType.trim().toLowerCase() vs parent 8c52e8692d without trim.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 1.122.5,1.123.2; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-9GM9-C8MQ-VQ7M REJECT

Identity PASS: first-party github-reviewed GHSA-9GM9-C8MQ-VQ7M, repo MervinPraison/PraisonAI, not withdrawn. Advisory sha256 `b27b6c781dbe36232766ec79909aafdfcd404578cfcf913e3372ddd6e52e6d4a`.
Mechanism: MCPHandler.parse_mcp_command() runs unsandboxed argv[0] as an OS command.
Closer `47bff65413beaa3c21bf633c1fae4e684348368c` n_parents=1 email praison.ms@gmail.com subject feat(mcp): enhance command validation in MCPHandler. Tree `7e23396a83add1680769aa7f46019d6acd4d09b8`. Parent `66bd9ee2a9c8c1e14514fe4d135b7e73e96a66fc` tree `7e63c6f70c6283f2e7eb8a9fc1d684c1748386d1`. source_matcher empty.
Semantic: Allowlist npx/node/python/uvx/docker/deno/bun/pipx; parent blob 03c847b076 has none.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 4.5.69; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-F3F2-MCXC-PWJX REJECT

Identity PASS: first-party github-reviewed GHSA-F3F2-MCXC-PWJX, repo n8n-io/n8n, not withdrawn. Advisory sha256 `e36dc35d417599aee49a28815e0051baf8f96f4f697f3563f730e1030ddef1fd`.
Mechanism: MySQL/Postgres/MSSQL nodes interpolate identifiers without escaping.
Closer `f73fae6fe7fc34907bba102648a9997186aa4385` n_parents=1 email yehor.kardash@n8n.io subject fix: Escape special characters in queries (#23133). Tree `0edd67774d25b5aba1dc3643d7d93238bf82e21e`. Parent `9ce3ac092cf7339f3c4a416cdea6e5fa2d5b22b9` tree `57e67870aa40443f0087958e5af264c66ce348c5`. source_matcher empty.
Semantic: escapeIdentifier replaces ] with ]]; parent formatColumns used raw [column.trim()].
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 2.4.0; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-FVFV-PPW4-7H2W REJECT

Identity PASS: first-party github-reviewed GHSA-FVFV-PPW4-7H2W, repo n8n-io/n8n, not withdrawn. Advisory sha256 `4406ae7aded231649cdd87e07aeaf3a99b4ed90f99fb286b6aa96cace4e674eb`.
Mechanism: Guardrails LLM JSON schema is non-strict and extra fields bypass flagged.
Closer `8d0251d1deef256fd3d9176f05dedab62afde918` n_parents=1 email 94372015+ShireenMissi@users.noreply.github.com subject fix(Guardrails Node): Improve Guardrails validation (#25390). Tree `5679c59c6f4eac09a46dcea9c1ab1b114bb6726f`. Parent `ead83ca8d954c8c177940b6310bb725c6c1ea567` tree `29c81401b3a111f6e93f5899d36818801732a8ad`. source_matcher empty.
Semantic: LlmResponseSchema.strict(); parent blob 66e1a1f07a is non-strict.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 2.10.0; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-GGJM-F3G4-RWMM REJECT

Identity PASS: first-party github-reviewed GHSA-GGJM-F3G4-RWMM, repo n8n-io/n8n, not withdrawn. Advisory sha256 `74af92bfae29a2b9580f077ee78401cd30d53f3d51ebc7750408876b221b83df`.
Mechanism: Read/Write File uses path.resolve so a symlink can escape blocked paths.
Closer `c2c3e08cdf33570d9051e659812cbfbdd3c077fd` n_parents=1 email roman.davydchuk@n8n.io subject fix(core): Handle symlinks in blocked paths (#17735). Tree `41c98e6d1b2978f7106675f42ef0341955c12550`. Parent `e8e7b23d47ca3fa7fb40e951763b7ad871110fc7` tree `cc99e1fa59612f72dc736be6c8757b201f7cfdf9`. source_matcher empty.
Semantic: isFilePathBlocked awaits fsRealpath; parent blob e575b29845 uses resolve().
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 1.106.0; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-GQ57-V332-7666 REJECT

Identity PASS: first-party github-reviewed GHSA-GQ57-V332-7666, repo n8n-io/n8n, not withdrawn. Advisory sha256 `1cecb2dcd3d171c09f228843aca3e7a2df7c213fc871b43e56093ae76debbdef`.
Mechanism: /stop stops executions without a shared-workflow authorization check.
Closer `e5edc60e344924230baafb11fa1f0af788e9ca9a` n_parents=1 email MarcL@users.noreply.github.com subject fix(core): Prevent unauthorised workflow termination (#16405). Tree `13556afde572a9768b3a99e5b3e8d5b90861371c`. Parent `569e522232b1fc6fcaa7935b4a601b391b96b891` tree `0cf16288edcfba09611ab358abbcd92ee790dee7`. source_matcher empty.
Semantic: stop() gains sharedWorkflowIds; parent blob 889882aa57 looks up by id only.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 1.99.1; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-HFMV-HHH3-43F2 REJECT

Identity PASS: first-party github-reviewed GHSA-HFMV-HHH3-43F2, repo n8n-io/n8n, not withdrawn. Advisory sha256 `4c18155e8cbc78769d0fb677365bc6f6513db61b7fa6c1bfdc4f8bcbdcea6913`.
Mechanism: Form Trigger stored XSS via iframe/video/source in rendered form HTML.
Closer `7940384a85041a1890b1203d69c092c887312500` n_parents=1 email 152518854+dana-gill@users.noreply.github.com subject fix(n8n Form Node): Prevent XSS with video and source tags (#16329). Tree `5beb5a32fc1f9124474dd9b87f86577317f5613d`. Parent `84a5cc67f77b7b1237f67e64ffad173ff5762e57` tree `bd2a45db31aa6bb93f332f522adaf92e7a8c1693`. source_matcher empty.
Semantic: Form.node.ts blob 5d98716d4c -> e306360f39; utils relocated under utils/.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 1.98.2; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-JF52-3F2H-H9J5 REJECT

Identity PASS: first-party github-reviewed GHSA-JF52-3F2H-H9J5, repo n8n-io/n8n, not withdrawn. Advisory sha256 `9a22c88bbd63f6240db8054956b42a44dd4ca8f6a5f03d3712246e11663e6d9e`.
Mechanism: Stripe Trigger accepts unsigned webhooks.
Closer `a61a5991093c41863506888336e808ac1eff8d59` n_parents=1 email 94372015+ShireenMissi@users.noreply.github.com subject fix(Stripe Trigger Node): Add Stripe signature verification (#22764). Tree `97a01c5ef41343ed982a9fa9a7ef7c41bc120ca7`. Parent `8f4b84fdd3b316dffe7d9e37c13f94fc99718c39` tree `8aaacab4ce70dbbf671370097084faae35dd031c`. source_matcher empty.
Semantic: StripeApi.credentials.ts parent 68bd4bb7f4 has no signatureSecret; closer blob 69858ba3dd adds it.
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 2.2.2; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

### GHSA-PR9R-GXGP-9RM8 REJECT

Identity PASS: first-party github-reviewed GHSA-PR9R-GXGP-9RM8, repo n8n-io/n8n, not withdrawn. Advisory sha256 `bbc57f6445195807f9884bbb07de2f05f4342f94734a3407d9bfbc81a9608e77`.
Mechanism: Malformed binaryDataId with empty path after the mode colon DoS the binary-data controller.
Closer `43c52a8b4f844e91b02e3cc9df92826a2d7b6052` n_parents=1 email ivov.src@gmail.com subject fix(core): Prevent DoS via malformed binary data ID (#16229). Tree `ac5ad701bd85d5c8ea49ad262720047e9440b5d0`. Parent `7177e3aab082cc7964698221a9440cd92dfaed03` tree `b9d7038dc0bb58725d2f3b0021b1676820567f10`. source_matcher empty.
Semantic: path === '' || '/' || '//' throws; parent blob f6344da6df only checked includes(':').
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release UNKNOWN (ls-remote names 1.99.0; local 0 tags; peel not closed).
Subject-overlap policy-AI commits have empty path overlap with the closer. Same-file/shared-SHA/carrier-trailer inference is forbidden.

## Conservation

294 heavy subject-only = 66 excluded terminals + 228 remaining. 228 = 12 inspected + 216 unreviewed. Equation 228=12+216 holds. Inspected 11 n8n-io/n8n plus 1 MervinPraison/PraisonAI. Remaining includes go-gitea/gitea 23, jdx/mise 5, gogs/gogs 3 (tied closer GHSA-RJV5-9PX2-FQW6), n8n 91, PraisonAI 94. Did not pad. PASS_PROPOSAL=0. Canonical94 untouched. Countable remains false.

Stop. No ledger, site, scripts, or other-packet edits. No credentials. No GitHub API.
