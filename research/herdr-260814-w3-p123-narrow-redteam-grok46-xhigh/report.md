# Hostile red-team: w3 p1/p2/p3 NARROW four

**KEEP 1. REJECT 3. UNKNOWN 0.** Packet delta 0. Current leader-accepted count remains 84.

Independent hostile review of the four NARROW proposals in `autoresearch/orchestrator-260814-w3-sol-p1/result.json`, `p2/result.json`, and `p3/result.json`. Stored worker verdicts were not trusted. Generic Copilot/Claude carrier metadata was not transferred onto a human member hunk. Genuine AI incomplete remediation is accepted only when the AI change is an explicit security attempt and the later fix closes that exact residual.

Conservation: assigned=4, reviewed=4, unreviewed=0.

Worker PASS remains proposal only. This packet does not admit a row, does not edit canonical84, and does not support a greater-than-200 claim.

## Verdict table

| Case | Stored | This review | Class | Failed gates |
|---|---|---|---|---|
| GHSA-282G-FHMX-XF54 | NARROW | REJECT | squash copy of old self-verify | ai_hunk, topology, but-for |
| GHSA-45Q4-X4R9-8FQJ | NARROW | REJECT | grammar sibling / wrong edge | ai_hunk, but-for |
| GHSA-8359-H9FX-J6V9 | NARROW | KEEP | AI incomplete remediation | none |
| GHSA-954P-556P-R752 | NARROW | REJECT | AI default still fetches; shared-fetcher closer | but-for (patch-delta) |

## GHSA-282G-FHMX-XF54 -- REJECT

Identity PASS. Frozen `GHSA-282g-fhmx-xf54`, github-reviewed, withdrawn null, alias CVE-2026-27946. Summary names self-verify of email/phone via UpdateHumanUser.

Candidate `8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f` is a GitHub squash of PR 9794. Single parent `e2a61a60029783f9a29bf7b71f2ac3d8fd39bb78`. Author Elio Bischof. Committer GitHub. 86 files. Trailers: Copilot and Livio Spring. Body also points at PRs 9680, 9763, and 9771. Generic Copilot trailer cannot author `internal/api/grpc/user/v2/human.go`.

Parent `user.go` already has `UpdateHumanUser` and maps `IsVerified` into `command.Email` / `command.Phone`. The candidate creates `human.go` and copies that mapping into `setHumanEmailToEmail` / `setHumanPhoneToPhone` for a new `UpdateUser` route. `human.go` does not exist on the parent.

But-for FAIL. Removing the candidate leaves the GHSA-named UpdateHumanUser path. Advisory 2.x range starts at 2.43.0. Candidate is not an ancestor of `v2.71.0`.

Fix-reversal PASS as a mechanism check, not a save. `0261536243e500dccfd8c7f547d592c822478327` adds `requireWritePermission` when verified email/phone is requested inside shared `ChangeUserHuman`. Equivalent `288f064e3ca990fde195e9a7ab363616e4fccdf1` is the `v4.11.1` tag commit. `02615362` is not an ancestor of `v4.11.1`.

Release PASS as containment, not a save. `v4.0.0` / `v4.11.0` contain the candidate and the old `!metadataChanged` permission check. `v4.11.1` contains `requireWritePermission`.

Uniqueness PASS. Absent from canonical84 counted 84.

## GHSA-45Q4-X4R9-8FQJ -- REJECT

Identity PASS. Frozen `GHSA-45q4-x4r9-8fqj`, github-reviewed, withdrawn null, alias CVE-2026-35600. Details quote the overdue Markdown join `* [` + task.Title + `](` + public URL + `tasks/` + id.

Candidate `5f795bb531eefb1ada2d4597a47074af0e8fbc90` is single-parent `d5a46310a7b84c4ff9add156994d9f5e213d566e`. Git author is Copilot. Subject is a self-assignment "themselves" wording change (#1836). Diff adds one `Doer.ID == Assignee.ID` branch and i18n strings. It does not touch `overdueLine`.

Parent already interpolates `n.Doer.GetName()` and `n.Task.Title` on assignment mail and already builds the unescaped overdue title join. Topology PASS because Copilot is the author, not a trailer transferred onto a human member. That does not make the grammar branch the advisory hunk.

But-for FAIL. Removing the candidate leaves the overdue title sink the GHSA names.

Fix-reversal PASS. `0f3730d045f20e261e3cdfc6d93c325653395b64` wraps the overdue join with `notifications.EscapeMarkdown(task.Title)` and also escapes many sibling sinks, including the Copilot-added line.

Release PASS as containment, not a save. Annotated `v2.2.2` peels to `772316b47f966cfce07c8241a099088aff0e6a74`, contains the candidate, and still has the unescaped overdueLine. Annotated `v2.3.0` peels to `28b537837f9808dc106c9058b5829c65759fddf2` and contains the fix. Tags were read from `/home/hanqing/.cache/ghsa200-w3-fetch/go-vikunja__vikunja` because the gn clone has no tags.

Uniqueness PASS. Absent from canonical84. Distinct from the other three proposals.

## GHSA-8359-H9FX-J6V9 -- KEEP (proposal only)

Identity PASS. Frozen `GHSA-8359-h9fx-j6v9`, github-reviewed, withdrawn null, alias CVE-2026-55389. The advisory quotes the candidate gate skip `if not resolved_ref.startswith("file://")` and names the `--no-allow-remote-refs` bypass.

Candidate `f6d4cbd3440a84e801566fa758ab2bf483322082` is single-parent `7e1a5c751b7b4b07aaf7d860d93162f1a75822b7`. Author Mikhail Butvin. Committer GitHub. Subject is PR 3051. Every reconstructed member and the squash trailer is `Co-Authored-By: Claude Opus 4.6`. There is no second human coauthor. This is not Copilot-trailer transfer onto a different human member.

Parent `_get_ref_body` has no `allow_remote_refs` and already loads `file://` plus `base_path / resolved_ref` with no confinement. The candidate is an explicit security attempt: it adds `allow_remote_refs` around HTTP(S) fetches and states "file:// URLs are still allowed without the flag since they are local." That skip is the residual.

Patch-delta but-for PASS. A released incomplete attempt exists. The GHSA covers that residual. Closer `2ff4a72b4550a2b2069754c5b075b1655067e5fb` removes the file:// exemption so `--no-allow-remote-refs` applies to file://, and adds `_resolve_local_ref_path` using the same flag. Reopening the older ungated filesystem read is not a patch-delta failure.

Relative `../` local refs were ungated in the parent and were not rewritten by the candidate except a FileNotFoundError wrap. KEEP is narrowed to the GHSA-quoted file:// gate bypass. The closer extending the same AI flag to local paths does not create a second counted case.

Release PASS.

| Tag | Peel | Candidate | 5fdba4a (954P closer) | 2ff4a72 (8359 closer) | file:// gate skip |
|---|---|---|---|---|---|
| 0.55.0 | 362453380f453d53cdd236d8817488631a8f9652 | no | no | no | no gate |
| 0.56.0 | 52d9ef9dec52f3ad14130710eefb010f0e492160 | yes | no | no | yes |
| 0.60.2 | e0ea4e45117acd41dcf6ae3a6639cc3f41b59045 | yes | no | no | yes |
| 0.61.0 | 21a25c4aa3ac6cf55c2e20e33467b95d07892602 | yes | yes | no | yes |
| 0.62.0 | 00de1a3517b0c41eb478c6efbd58220aea249db1 | yes | yes | yes | removed |

Uniqueness PASS. Absent from canonical84. Distinct from GHSA-954P (HTTP SSRF / shared fetcher), GHSA-RFR2 (CLI --url), and GHSA-VX7X (DNS pin). Shared candidate SHA does not merge cases.

original_vulnerability: original_advisory_ids is null. The worker listed GHSA-954P as the original advisory; that is a sibling residual of the same candidate, not the original hole. This review does not invent an original advisory ID. original_introducing_commit is null.

## GHSA-954P-556P-R752 -- REJECT

Identity PASS. Frozen `GHSA-954p-556p-r752`, github-reviewed, withdrawn null, alias CVE-2026-54690. Range introduced 0.9.1, fixed 0.61.0.

AI hunk and topology PASS for the same Claude squash. The candidate does add the tri-state `allow_remote_refs` branch the advisory quotes, including default None warn-then-fetch.

Patch-delta but-for FAIL. The omitted case of the AI gate is default None still fetches. Closer `5fdba4a09f2d7a9996a504975b7ef7d63e3715bb` leaves that branch in place. It adds `_validate_url_for_fetch` and disables automatic redirects on `http.py:get_body`. Parent and candidate `get_body` already used `follow_redirects=True` with no IP check. 0.56.0 and 0.60.2 match that old fetcher. 0.61.0 adds the validator. The advisory states the compatibility default was not flipped and that this report is fixed by the same shared fetcher hardening as GHSA-RFR2.

That is a later fix to a pre-existing HTTP client, not an amendment of the AI-added allow_remote_refs residual. Incomplete remediation is not counted.

Fix-reversal PASS as a first-party closer of internal SSRF, not a save. Release PASS as 0.56.0-0.60.2 versus 0.61.0, not a save. Uniqueness PASS versus 8359.

original_vulnerability is recorded so the failed patch-delta is explicit. original_advisory_ids is null.

## Cross-proposal uniqueness

The four identities are pairwise distinct. 8359 and 954P share candidate `f6d4cbd` and repository. They have different CWEs, different closers, different residuals, and different fixed tags (0.62.0 versus 0.61.0). Canonical84 counted 84 contains none of the four IDs and none of the three repositories.

## Claim boundary

KEEP is a proposal. Leader replay is still required. Canonical84 was not edited. Publication and more-than-200 stay HOLD.

## Replay commands

`zsh replay.zsh` exited 0 with `REPLAY_OK reviewed=4 KEEP_proposal=1 REJECT=3 UNKNOWN=0 BLOCKED=0`. See `replay.zsh` and `replay.txt` in this directory. Key clones:

- zitadel: `/home/hanqing/.cache/cve-analyzer/repos/zitadel_zitadel`
- vikunja diffs: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja`
- vikunja tags: `/home/hanqing/.cache/ghsa200-w3-fetch/go-vikunja__vikunja`
- datamodel diffs: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/koxudaxi__datamodel-code-generator`
- datamodel tags: `/home/hanqing/.cache/ghsa200-w3-fetch/koxudaxi__datamodel-code-generator`

No GitHub API. No ledger edits. No commit or push.

## Input hashes (SHA-256)

- p1 result.json `0ac57a79984c896e0455287ee014d75452a3d605fd073195ff09b7bcd840745f`
- p2 result.json `90f9fe8e82a1b72136593edbdbc437c01f141267f6fd12955eca785f764e1cd4`
- p3 result.json `59129732ab900f53f0a1912aa44654d3614b7f4e58c764cd8b259c712b41ab5b`
- CONTRACT.md `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- canonical84 ledger.jsonl `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`
