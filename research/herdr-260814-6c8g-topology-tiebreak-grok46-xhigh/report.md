# Hostile topology tie-break: GHSA-6C8G-7P36-R338

Verdict first: **REJECT**. Named failing gates are **ai_hunk_gate** and **topology_gate**. Scoped contributor but-for was not applied because authorship and topology did not close. 0 PASS_PROPOSAL. Conservation **1=1+0**. Canonical88 remains **88 HOLD**. Publication and greater-than-200 remain HOLD. Worker PASS is proposal only; this packet emits none.

Two prior packets conflicted. nearclosed-a proposed AI_NEW_SURFACE_CONTRIBUTOR PASS because Copilot `8b95e0a76` first added archive-level `WriteToDirectoryAsync` with uncontained directory-entry `Path.Combine`. causal-consensus-b REJECTED because the advisory-named `WriteToDirectoryAsyncInternal` is absent from that commit and later humans add `IAsyncArchiveExtensions.cs`. This packet reconstructs the full move/refactor chain from parent `3f9986c13` through NuGet 0.47.4 and closer `2021a066` using blob, patch-id, diff, default blame, and release artifacts. Copy-blame and similar semantics are not authorship.

Bound to CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical88 summary `81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921`. Ledger `35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074`. Reviewed advisory `48c903f727ee06ce23d71a01df78940279ceb1f017e157817419f06470c9e014`. Shared tracked files and canonical ledgers were not edited. No commit, push, or padding.

## Identity

github-reviewed first-party GHSA-6c8g-7p36-r338, alias CVE-2026-44788, not withdrawn. Package SharpCompress, introduced 0, fixed 0.48.0. Details name both `WriteToDirectoryInternal` (sync, `IArchiveExtensions.cs:48-61`) and `WriteToDirectoryAsyncInternal` (async, `IAsyncArchiveExtensions.cs:70-84`). Those async line numbers match tag 0.47.4 / NuGet 0.47.4 after the human `extension()` rewrite, not Copilot's `IArchiveExtensions.cs` `WriteToDirectoryAsync`. identity_gate PASS.

## Topology chain (parent through 0.47.4 through fix)

All SHAs below are first-party git objects in `/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/sharpcompress`. n_parents=1 on the candidate and the closer.

1. Parent `3f9986c13c973f5e9b8e08da8bfb5e8259044a44`. Tree already has James Hood 2023 `ExtractToDirectory` directory-entry `Path.Combine(destination, entry.Key)` plus `Directory.CreateDirectory`. No archive-level `WriteToDirectoryAsync` on `IArchiveExtensions.cs`. Blob `d9701da301568451cedfc73021a01e376cd5458b`. Directory-entry block sha256 `e11b2796e6756d5363472f4891b817ea317d14479d88922fd7b2ad6b2da6bd6b`.

2. Copilot `8b95e0a76d6b387533175730e2895ccd16772d07` (copilot-swe-agent[bot], n_parents=1). Subject: Standardize on WriteToDirectory naming and add async support. Touches `IArchiveExtensions.cs` and tests only. Adds archive-level `WriteToDirectoryAsync` with `emptyDirectory` and split `Path.Combine(destinationDirectory, entry.Key)`. Does not contain symbol `WriteToDirectoryAsyncInternal`. Tree has no `IAsyncArchiveExtensions.cs`. Blob `628155995c06131bcba910a5f2504fda5d0804f6`. Directory-entry block sha256 `87dff43f93eeb3f466845cac0dcf58b783771129230ede4744b60a3aa3b60524`. Full-commit stable patch-id `70ced4867c631c52fd52c6d0d9da6d9a90e97c1c`. Parent-to-candidate file patch-id `7bd36bfff290ee3baef0236ca9f0b1e9ee69e9b4`.

3. Later Copilot commits on the same file (`54b64a8c` emptyDirectory to parentDirectory, `2f0eb0bd` IProgress, `c701bbbe` format, `d3929917` drop sync CancellationToken) still live in `IArchiveExtensions.cs`. They are not the advisory-named Internal method.

4. Human Adam `c2e01798f8bbe63fd4c3568d8e2d594d7c504ae9` "refactor archive extensions". First appearance of `WriteToDirectoryAsyncInternal`. Wraps the file in C# `extension(IArchive archive)` and extracts a private Internal method. Blob `0d39c6e2c149064467b74ddf77bfe58d058a863b`. Directory-entry block sha256 `5409fc198a65a099e4b3ac7cee16dd7f66fa595102849f8e7d40ea7c9fd57771` (indent of the extension block; identifier parentDirectory). This is a human extract, not an AI commit.

5. Human Adam `8e42296c3a6454e9a5f91446cd040cef64dde2ee` "switch Task to ValueTask". Git copy-detection at default `-C` is `C053` from `IArchiveExtensions.cs` to new `IArchiveAsyncExtensions.cs` (53 percent). At `-C60` the copy disappears and the async file is a plain add. Blob `ca3db1cf2c9cbbecd9eb299f2d3de7dc61bd4b75`. `c2e01798` is an any-parent ancestor but is not on the first-parent walk of `8e42296c`. File patch-id versus c2e `4119ed56bc4277b079e17be3ea1ab0db4bd51fec`.

6. Human Adam `b501bac54ae3f70fba9d86e437fb2e4ea79fd960` "better names for new interfaces". Deletes `IArchiveAsyncExtensions.cs` and adds `IAsyncArchiveExtensions.cs` as name-status `A` at every copy threshold from `-C20 --find-copies-harder` through `-C90`. Blobs differ: deleted `ca3db1cf2c9c` versus added `b6b0cad1e9ee799c03539e46c70cf11150084450`. File patch-id `1d747d822b24e758dd225c2736cfa561ec87aa59`. Git does not treat this as a rename or copy of the Copilot file.

7. Human Adam `5c4719f4a92c0a9bcc84334b6b5784e7aaba0199` "missing extensions". Rewrites `IAsyncArchiveExtensions.cs` 66 insertions / 67 deletions into `extension(IAsyncArchive archive)` members. Blob `df4cb05c4a7f55e3fb0a4080f31a21cdc3605557`. File patch-id versus 1b4cedfa `2114e31f94bc85b6e19a5c46a3054b6d1b7440ec`. Default blame of the `extension(...)` wrapper at 0.47.4 is this commit.

8. Further human blobs on the async file: `c5d74079` Task to ValueTask, `04dd177f` options, `3aca691e` ConfigureAwait, `ba1cd663` extraction options back. Tag 0.47.4 peel `5758b08236b275b926bc2c3d97604a96d21546c0` async blob `9ba599776f56d4e238f93416343cb3a181033f7a`. Sync `IArchiveExtensions.cs` blob `80857a25c30fac320fdda30fce98ddfe2fedd03d` equals the 5c4719f4 sync blob. Async directory-entry block sha256 `5409fc198a65a099e4b3ac7cee16dd7f66fa595102849f8e7d40ea7c9fd57771` equals the human c2e/5c47 block, not the Copilot 8b95e0a76 block. Candidate-file to 0.47.4-async file patch-id `7fcbcbc5aaa67a48f542fb9e6cfeada650127e17` (not identity).

9. Closer `2021a06626d0555a4d69471386e763ca5f5d5dfb` (Adam Hathcock, add zipslip tests and fixes). Inserts `Path.GetFullPath` plus `StartsWith` on `WriteToDirectoryAsyncInternal`. Async blob `5d9ef261594aeaab45f56226794cd007b3622423`. Directory-entry block sha256 `88f4b199310cd166b52561b33f0c46db84a02b4bc99a197d21fee1900c7675fb`. Tag 0.48.0 peel `6e59c7d7bbf8c19a8a92c3c382599906684bb93d` contains the closer.

Tag 0.43.0 already contains the candidate and human Internal inside `IArchiveExtensions.cs`, and still has no `IAsyncArchiveExtensions.cs`. Tag 0.45.0 is the first tag with that async file. The GHSA async line numbers are the 0.47.4 file.

## Authorship: default blame versus copy-blame

Default blame (`git blame -w`, no `-C`) on 0.47.4 `IAsyncArchiveExtensions.cs` lines 70-84 (the GHSA citation):

- `Path.Combine` / `CreateDirectory` directory-entry body: `b501bac54` Adam Hathcock.
- `extension(IAsyncArchive archive)` wrapper: `5c4719f4` Adam Hathcock.
- `ValueTask WriteToDirectoryAsyncInternal` signature: `c5d74079` Adam Hathcock.
- Zero lines blame to `8b95e0a76`.

Copy-blame (`-C -C -C`) would move some wrapped `Path.Combine(destinationDirectory, ...)` lines onto Copilot `8b95e0a76` and would also move `if (entry.IsDirectory)` onto James Hood `c7c143fe` (2023-07-19 `ExtractToDirectory`). CONTRACT topology forbids transferring authorship across commits. Copy-blame is not used.

Same-file default blame on 0.47.4 sync `WriteToDirectoryInternal` does attribute the wrapped `Path.Combine` lines to Copilot `8b95e0a76` because that is the file Copilot edited. Those lines are a wrap/rename of parent `ExtractToDirectory` (`destination` to `destinationDirectory`). `if (entry.IsDirectory)` still blames to James Hood. That older sync sibling is not a preserved async carrier, and it is not origin of the zip-slip.

ai_hunk_gate FAIL: the exact released async Internal hunk is not authored by the atomic AI commit. topology_gate FAIL: there is no blob-equal, rename, or patch-id-identical carrier from `8b95e0a76` into `IAsyncArchiveExtensions.cs` at 0.47.4. The chain is human extract, 53-percent copy, delete-plus-add new file, then `extension()` rewrite.

## Scoped contributor but-for (not applied)

CONTRACT: apply `AI_NEW_SURFACE_CONTRIBUTOR` but-for only after authorship and topology close. They did not. Deleting `8b95e0a76` does not remove later human `b501bac54` / `5c4719f4` Internal. Parent already exposed directory-entry `Path.Combine` zip-slip. but_for_gate FAIL.

## Fix reversal and release

Closer `2021a066` does reverse the released human Internal with `GetFullPath`/`StartsWith`. That is reversal of a human method, not of an AI hunk. fix_reversal_gate NARROW.

NuGet SharpCompress 0.47.4 nupkg sha256 `987d11f9a976194a26218922798b9d4e61759809c852289f40f4e9d77794160f`, nuspec commit equals tag 0.47.4 peel `5758b082`. net8.0 dll contains `WriteToDirectoryAsyncInternal`. Git tree at that commit still `Path.Combines` directory entries and has no `GetFullPath` in the async file. NuGet 0.48.0 nupkg sha256 `d8c5da8a76d325eb81c1103a78953e025513f22ade36b5b11d8342324146f0b7`, nuspec commit equals `6e59c7d7`. Candidate is an ancestor of 0.47.4; closer is not; closer is an ancestor of 0.48.0. release_gate PASS and does not promote authorship.

## Uniqueness and claim boundary

GHSA-6C8G-7P36-R338 is not in canonical88 strict_released_case_ids (88). It is not GHSA-8RW6-P7M8-63JP. uniqueness_gate PASS. Countable PASS requires all seven gates PASS plus leader admission. This packet proposes none. Canonical88 was not rebuilt. Did not pad. Status TERMINAL.
