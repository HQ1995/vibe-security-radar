# Canonical72 uniqueness audit (proposal)

Verdict first: the 72 `STRICT_RELEASED_CASE` rows in `autoresearch/orchestrator-260813-ghsa200-canonical71/ledger.jsonl` are **72 unique first-party GHSA identities**. This audit found **zero SAME_MECHANISM duplicates**. No canonical survivor is named. Status is **HOLD** because this is a proposal pending leader replay. This packet does not admit cases, does not rewrite the ledger, and does not support a more-than-200 claim.

## Scope and counting unit

- Input: canonical71 HOLD ledger, record kind `STRICT_RELEASED_CASE` only (72 rows).
- Counting unit: first-party GHSA case, once.
- CVE aliases are stored on rows and are never counted.
- Shared candidate, carrier, or fix SHA alone never dedupes.
- SAME_MECHANISM requires matching file/sink/invariant/scope plus first-party identity (same GHSA, or a formal alias of that GHSA). Distinct first-party GHSAs with a shared SHA stay SEPARATE unless that identity test also holds.

Owned directory only: `autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/`. Canonical and other files were not edited. Nothing was committed or pushed.

## Conservation

| Check | Result |
|---|---|
| Ledger records | 540 |
| PRESERVED_HYPOTHESIS | 211 |
| PRESERVED_PUBLIC_CASE | 212 |
| STRICT_RELEASED_CASE | 72 |
| Unique counted `case_id` | 72 |
| Unique `mechanism_fingerprint` | 72 |
| Unique `mechanism_key` | 72 |
| CVE used as `case_id` | none |
| CVE counted as the unit | false |
| One CVE claimed by two counted GHSAs | none |
| GHSA aliasing the same first-party advisory under two counted IDs | none |
| Append identities absent from the 212 | `GHSA-6P9M-Q3JP-47H4`, `GHSA-G39V-CVJH-8FPF`, `GHSA-PF93-J98V-25PV` |
| `GHSA-4FXP-2M36-QV64` in counted set | absent |
| `GHSA-7C3W-FXGH-FRC7` in counted set | absent |
| `GHSA-F38V-77QJ-H4JQ` in counted set | absent |
| ChurchCRM ordinal-200 dual IDs `GHSA-3J8Q-FWPJ-F8J5` / `GHSA-JJCJ-H3CM-P7X7` | in the 212 source layer only, not counted |

Source conservation (211 hypotheses, 212 GHSA cases) is separate from the counted set. Same-id upgrades rewrite overlay fields and do not append.

## Risk pairs

`pairs.jsonl` lists **186** risk pairs (every pair that shares a candidate SHA, fix SHA, carrier SHA, normalized repository, or similar mechanism text), including resolved SEPARATE pairs. All **186** are SEPARATE. SAME_MECHANISM = 0.

Normalized repository fills five counted rows whose ledger `repository` is null from the reviewed GHSA package URL `openclaw/openclaw`. That is a pairing aid only; it does not change the ledger.

### SHA-sharing pairs (do not merge)

These are the pairs that share a candidate, fix, or carrier SHA. Each stays SEPARATE on file/sink/invariant and first-party identity.

| Left | Right | Shared | Why SEPARATE |
|---|---|---|---|
| GHSA-RV2Q-F2H5-6XMG | GHSA-RV39-79C4-7459 | candidate `079af0d0` | Same `message-handler.ts` connect path. RV39 is skip-on-token-presence vs validated `sharedAuthOk` (fix `fe81b1d7`, CVE-2026-28472). RV2Q is residual `role=node` device-less connect after shared auth (fix `ddcb2d79`, CVE-2026-32001). |
| GHSA-83XP-526H-J3WW | GHSA-8WC8-HF36-MJH9 | candidate `847d08bd` | Zip-slip archive builder vs dangling-symlink ScopedFs write. Canonical ordinal 165 delete-scope FALSE_POSITIVE is not counted. |
| GHSA-8JPQ-5H99-FF5R | GHSA-X22M-J5QQ-J49M | fix `5b4121d6` | sendMediaFeishu local-path read vs remote media SSRF. |
| GHSA-8JPQ-5H99-FF5R | GHSA-J4XF-96QF-RX69 | candidate `2267d58a` | Local-path media vs Feishu `allowFrom` display-name collision. |
| GHSA-877V-W3F5-3PCQ | GHSA-C6HR-W26Q-C636 | candidate `4286755f` | Feishu quoted/thread sender allowlist vs mention RegExp injection. |
| GHSA-877V-W3F5-3PCQ | GHSA-X22M-J5QQ-J49M | candidate `4286755f` | Quoted/thread allowlist vs media SSRF. |
| GHSA-C6HR-W26Q-C636 | GHSA-X22M-J5QQ-J49M | candidate `4286755f` | Mention RegExp vs media SSRF. |
| GHSA-VJ3G-5PX3-GR46 | (877V, C6HR, X22M) | carrier `2267d58a` | Feishu temp-file path traversal vs the three other Feishu invariants. |
| GHSA-FMFG-9G7C-3VQ7 | GHSA-PF93-J98V-25PV | candidate+fix `39806871` / `dc8eaa16` | OAuth `ha_url` SSRF vs consent-form XSS. One commit pair, two sinks. PF93 is an append identity. |
| GHSA-539M-9XH6-Q6RR | GHSA-5XXX-QHH7-9287 | candidate `701ce32f` | GitPython `archive` omitted `--add-file` vs `blame` omitted `--contents`. |
| GHSA-539M-9XH6-Q6RR | GHSA-R9MR-M37C-5FR3 | candidate `701ce32f` | Archive denylist vs kwarg option-token smuggling. |
| GHSA-5XXX-QHH7-9287 | GHSA-R9MR-M37C-5FR3 | candidate `701ce32f` | Blame `--contents` vs kwarg smuggling. |
| GHSA-3WXW-XV34-2FRG | GHSA-5XXX-QHH7-9287 | fix `1b0d2d9b` | Tag positional `--file` bypass vs blame `--contents`. One later fix can close two mechanisms. |
| GHSA-9HFR-GW99-8RHX | GHSA-HC36-C89J-5F4J | fix `db97de47` | ARC status treated as success vs unverified certificate signature persist. |
| GHSA-C4GH-RV8H-Q9VW | GHSA-W28W-GP39-M4P6 | candidate `a0e61088` | Prompty JS frontmatter vs Nunjucks SSTI. |
| GHSA-C4GH-RV8H-Q9VW | GHSA-WXHM-2MQ7-7697 | candidate `a0e61088` | JS frontmatter vs unbounded `${file:...}` resolver. |
| GHSA-W28W-GP39-M4P6 | GHSA-WXHM-2MQ7-7697 | candidate `a0e61088` | Nunjucks SSTI vs file resolver. |
| GHSA-MF5G-6R6F-GHHM | GHSA-RQP8-Q22P-5J9Q | candidate `03586e3d` | Synology unthrottled 401 vs webhook path collision. |

### Similar-text SEPARATE pairs

- GHSA-877V-W3F5-3PCQ vs GHSA-RG8M-3943-VM6Q: both say thread/reply context bypasses sender allowlist. Feishu quoted fetch vs Matrix thread-root fetch. Distinct channel, file, GHSA, CVE.
- GitPython GHSA-3RP5-JJMW-4WV2 / GHSA-JM78-9FVV-MHGR / GHSA-MV93-W799-CJ2W: config injection family with distinct parser sites (`]` section, option-name tokens, section newline).
- Synology GHSA-GW85-XP4Q-5GP9 vs RQP8 / MF5G: empty-allowlist fail-open vs path collision vs unthrottled token guess.

Remaining pairs are same-repository only (OpenClaw after URL fill, GitPython, ha-mcp, PraisonAI, scriban, filebrowser, bsv-ruby-sdk, ChurchCRM, clearancekit, Prompty). Each still has a distinct fingerprint, key, and first-party GHSA.

## Alias and identity gates

- Every counted `case_id` matches `GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}`.
- Counted-row `aliases` are CVE strings only. No counted row lists another GHSA as an alias.
- 58 CVE aliases on counted rows, 58 unique, none used as the counting unit.
- Append identities are not in the 212 `PRESERVED_PUBLIC_CASE` IDs and have `in_fp211_212=false` on their counted rows.
- 4FXP / 7C3W / F38V appear only as NARROW supersede / source-layer rows, never as `STRICT_RELEASED_CASE`.

## Claim boundary

Canonical strict count 72 is a HOLD snapshot. This uniqueness proposal does not make it publication-ready. Integration_ready is false. Causal admission is false. The 73 figure is not terminal. A more-than-200 claim is unsupported.

Replay: `autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/replay.sh`.
