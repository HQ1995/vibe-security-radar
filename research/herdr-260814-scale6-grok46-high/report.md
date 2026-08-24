# Direct-root scale6 (dr-slice-6) — grok-4.6-high

Assigned 25, reviewed 25, countable proposals 0. Status: COMPLETE_REVIEW_NO_COUNTABLE_PASS.

Unclosed gates remain UNKNOWN. Missing evidence was not converted into FAIL.

## 1. GHSA-X6FH-7QMF-69XH — UNKNOWN

Repository: slackhq/nebula
AI ancestor: `00458302caf8132923d53df42b1fc4143e8a6d14` — Bump the golang-x-dependencies group with 4 updates (#1174)
Fix: `e264a0ff888c7bf0568579306755a60fc42f6ecc`
Overlap: ['go.mod', 'go.sum']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 2. GHSA-69X3-G4R3-P962 — UNKNOWN

Repository: slackhq/nebula
AI ancestor: `bf49e78243d15ee822cb6901b91e265ca997cc57` — Bump github.com/sirupsen/logrus from 1.9.3 to 1.9.4 (#1581)
Fix: `f573e8a26695278f9d71587390fbfe0d0933aa21`
Overlap: ['go.mod', 'go.sum']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 3. GHSA-7WQ2-32H4-9HC9 — UNKNOWN

Repository: aws/aws-advanced-go-wrapper
AI ancestor: `cfebf6149af3645bafcd34f2fd4db08cedb96b19` — test: add stress tests (#251)
Fix: `7b405f95fe71db644cd8336ba5fa28b41e89d03e`
Overlap: ['.test/test_framework/container/test_utils/aurora_test_utility.go', '.test/test_framework/container/test_utils/driver_helper.go']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 4. GHSA-GFM2-XM6C-37QC — UNKNOWN

Repository: open-webui/open-webui
AI ancestor: `e7ff4768f8ffe1924b4576381c9e45e8a64350e4` — fix: Add ownership checks to global task endpoints (#23454)
Fix: `cf4218e688def6f11d195aeda6665ae5b5376b67`
Overlap: ['backend/open_webui/main.py', 'src/lib/components/chat/Chat.svelte']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Co-authored-by: Claude <noreply@anthropic.com>
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 5. GHSA-MH29-5H37-FV8M — UNKNOWN

Repository: nodeca/js-yaml
AI ancestor: `b1cc0e99bdf2fc5a25db06e663b2d7b2ed69b54f` — Remember cursor position for 'duplicate mapping key' exception
Fix: `383665ff4248ec2192d1274e934462bb30426879`
Overlap: ['CHANGELOG.md', 'lib/loader.js']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: cursor
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 6. GHSA-W7FW-MJWX-W883 — UNKNOWN

Repository: ljharb/qs
AI ancestor: `fbc5206c25b4d1851cea683f02c10756c521d15a` — [Fix] `parse`: fix error message to reflect arrayLimit as max index; remove extraneous comments
Fix: `f6a7abff1f13d644db9b05fe4f2c98ada6bf8482`
Overlap: ['lib/parse.js', 'test/parse.js']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 7. GHSA-Q8MJ-M7CP-5Q26 — UNKNOWN

Repository: ljharb/qs
AI ancestor: `a0a81ea2071acce3eff41a040f719ac8f5c4f64c` — [Fix] `stringify`: use configured `delimiter` after `charsetSentinel`
Fix: `21f80b33e5c8b3f7eba1034fff0da4a4a37a1d41`
Overlap: ['lib/stringify.js', 'test/stringify.js']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Co-Authored-By: Claude <noreply@anthropic.com>
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 8. GHSA-HM5P-X4RQ-38W4 — UNKNOWN

Repository: jnunemaker/httparty
AI ancestor: `8901c238c00d0aca8920271314c4c5d7dd2701fb` — feat: stream multipart file uploads to reduce memory usage
Fix: `0529bcd6309c9fd9bfdd50ae211843b10054c240`
Overlap: ['lib/httparty/request.rb', 'spec/httparty/request_spec.rb']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Claude Code, Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 9. GHSA-2CP6-34R9-54XX — UNKNOWN

Repository: microsoft/maker.js
AI ancestor: `5da2b6d3b6304046395495fd84d17efa83d01415` — Add fontkit support alongside opentype.js (#640)
Fix: `85e0f12bd868974b891601a141974f929dec36b8`
Overlap: ['package-lock.json', 'packages/maker.js/package.json']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 10. GHSA-4XC5-WFWC-JW47 — UNKNOWN

Repository: baptisteArno/typebot.io
AI ancestor: `0250ff8b64eb33663ecaf9034cabedd1f1cf6b3e` — 💄(embed) fix button cursor
Fix: `a68f0c91790af8f52f17557f4aa202e966e7e579`
Overlap: ['packages/embeds/js/package.json', 'packages/embeds/react/package.json']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: cursor
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 11. GHSA-9G8X-92Q2-P28F — UNKNOWN

Repository: patriksimek/vm2
AI ancestor: `093494c0c3ef2390d2e56909f9d56e290e6f18b0` — fix(GHSA-248r-7h7q-cr24): close async generator yield*-return thenable exception capture
Fix: `e1c48fce05189f48e71efbd32af0754efa4066bb`
Overlap: ['CHANGELOG.md', 'docs/ATTACKS.md']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 12. GHSA-C4CF-2HGV-2QV6 — UNKNOWN

Repository: patriksimek/vm2
AI ancestor: `093494c0c3ef2390d2e56909f9d56e290e6f18b0` — fix(GHSA-248r-7h7q-cr24): close async generator yield*-return thenable exception capture
Fix: `26d0318b5e6555be4b187ba05d6cf378ccecfe22`
Overlap: ['CHANGELOG.md', 'docs/ATTACKS.md']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 13. GHSA-R9PM-GXMW-WV6P — UNKNOWN

Repository: patriksimek/vm2
AI ancestor: `093494c0c3ef2390d2e56909f9d56e290e6f18b0` — fix(GHSA-248r-7h7q-cr24): close async generator yield*-return thenable exception capture
Fix: `436053e30eecbabd487e2fd2959c137ac34e2bb1`
Overlap: ['CHANGELOG.md', 'docs/ATTACKS.md']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 14. GHSA-RP36-8XQ3-R6C4 — UNKNOWN

Repository: patriksimek/vm2
AI ancestor: `093494c0c3ef2390d2e56909f9d56e290e6f18b0` — fix(GHSA-248r-7h7q-cr24): close async generator yield*-return thenable exception capture
Fix: `a1ed47a98d1cc36cb48c0d566d55889688e0b59b`
Overlap: ['CHANGELOG.md', 'docs/ATTACKS.md']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 15. GHSA-9C48-W39G-HM26 — UNKNOWN

Repository: RustCrypto/RSA
AI ancestor: `a2ed9dd3c0e7c01c1135c3e143b9d4f4ed1383f8` — build(deps): bump spki from 0.7.2 to 0.7.3 (#396)
Fix: `2926c91bef7cb14a7ccd42220a698cf4b1b692f7`
Overlap: ['Cargo.lock', 'Cargo.toml']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 16. GHSA-8P85-9QPW-FWGW — UNKNOWN

Repository: fastify/middie
AI ancestor: `d44cd56eb724490babf7b452fdbbdd37ea2effba` — fix: decode paths before matching (#245)
Fix: `140e0dd0359d890fec7e6ea1dcc5134d6bd554d4`
Overlap: ['lib/engine.js', 'package.json']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 17. GHSA-7P5M-XRH7-769R — UNKNOWN

Repository: nyariv/SandboxJS
AI ancestor: `584f8ae960b4fcfc18feb833c8c6b49157874ccd` — Bump serialize-javascript and @rollup/plugin-terser (#47)
Fix: `cc8f20b4928afed5478d5ad3d1737ef2dcfaac29`
Overlap: ['package-lock.json', 'package.json']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 18. GHSA-G8F2-4F4F-5JQW — UNKNOWN

Repository: nyariv/SandboxJS
AI ancestor: `584f8ae960b4fcfc18feb833c8c6b49157874ccd` — Bump serialize-javascript and @rollup/plugin-terser (#47)
Fix: `826865251232611ec94078bab5a18ec875dad4a5`
Overlap: ['package-lock.json', 'package.json']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 19. GHSA-GQ9C-WG68-GWJ2 — UNKNOWN

Repository: openclaw/openclaw
AI ancestor: `1af0edf7ff222f6784a1ffa45cdacc89fa383feb` — fix: ensure exec approval is registered before returning (#2402) (#3357)
Fix: `7f0489e4731c8d965d78d6eac4a60312e46a9426`
Overlap: ['CHANGELOG.md', 'src/discord/monitor/threading.test.ts']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 20. GHSA-XWJM-J929-XQ7C — UNKNOWN

Repository: openclaw/openclaw
AI ancestor: `1af0edf7ff222f6784a1ffa45cdacc89fa383feb` — fix: ensure exec approval is registered before returning (#2402) (#3357)
Fix: `7f0489e4731c8d965d78d6eac4a60312e46a9426`
Overlap: ['CHANGELOG.md', 'src/discord/monitor/threading.test.ts']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 21. GHSA-JMMG-JQC7-5QF4 — UNKNOWN

Repository: openclaw/openclaw
AI ancestor: `eb73e87f18d1e94ff240c419ffcff6776f551a3d` — fix(session): prevent silent overflow on parent thread forks (#26912)
Fix: `c736f11a16d6bc27ea62a0fe40fffae4cb071fdb`
Overlap: ['CHANGELOG.md', 'docs/gateway/configuration-reference.md']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 22. GHSA-PJVX-RX66-R3FG — UNKNOWN

Repository: openclaw/openclaw
AI ancestor: `4f08dcccfd7130bb8853072e26284820bd61ff2c` — Mattermost: add interactive model picker (#38767)
Fix: `70da80bcb5574a10925469048d2ebb2abf882e73`
Overlap: ['CHANGELOG.md', 'src/auto-reply/reply/commands.test.ts']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- no explicit AI trailer matched in local ancestor message; ai_hunk_gate not closed from subject routing alone
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 23. GHSA-RHFG-J8JQ-7V2H — UNKNOWN

Repository: openclaw/openclaw
AI ancestor: `dad68d319b190e3d8df2d4a4be73051bfc5280cd` — Remove Qwen OAuth integration (qwen-portal-auth) (#52709)
Fix: `f92c92515bd439a71bd03eb1bc969c1964f17acf`
Overlap: ['docs/.generated/config-baseline.json', 'docs/.generated/config-baseline.jsonl']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Qwen Code
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 24. GHSA-8J7F-G9GV-7JHC — UNKNOWN

Repository: openclaw/openclaw
AI ancestor: `dad68d319b190e3d8df2d4a4be73051bfc5280cd` — Remove Qwen OAuth integration (qwen-portal-auth) (#52709)
Fix: `f92c92515bd439a71bd03eb1bc969c1964f17acf`
Overlap: ['docs/.generated/config-baseline.json', 'docs/.generated/config-baseline.jsonl']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Qwen Code
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
## 25. GHSA-FWHJ-785H-43HH — UNKNOWN

Repository: OliveTin/OliveTin
AI ancestor: `aa2bd95ccb8f00a1c97ebcb0a03e8d49867ffde6` — feat(policy): add policy to show/hide version number
Fix: `bb14c5da3e64b03f207c7f38139eb60e97c278fc`
Overlap: ['service/internal/api/api.go', 'service/internal/api/apiActions.go']
Gates: identity=UNKNOWN ai_hunk=UNKNOWN topology=PASS but_for=UNKNOWN fix_reversal=UNKNOWN release=UNKNOWN uniqueness=UNKNOWN
Countable proposal: False

- advisory JSON not found locally; identity_gate left UNKNOWN
- ai_ancestor is an ancestor of fix_ref in the local pool
- explicit AI marker on ancestor: Cursor
- vulnerable hunk vs AI ancestor diff was not fully replayed (blobless pool / no fetched parent blobs); unclosed gates left UNKNOWN rather than FAIL
