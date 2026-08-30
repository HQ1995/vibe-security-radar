# Coding-agent Git traces — 2026-08-26

How shipping coding agents leave machine-readable traces in Git, compared
with `cve-analyzer/src/cve_analyzer/source_policy.py` (schema v5). Primary
sources only: vendor docs and first-party source. PR bodies, issue comments,
and Cursor Blame overlays are not production commit evidence.

The largest scanner gaps against **current first-party defaults** are
Claude Code’s documented Markdown footer URL
(`https://claude.com/claude-code`, not the registered `claude.ai/code`),
Devin’s documented `Generated with [Devin]` / `Co-Authored-By: Devin` lines
(bot login is registered; these message lines are not), Kilo Cloud’s
first-party test identity `kiloconnect[bot]`, and Amazon Q Developer’s
GitHub App (`amazon-q-developer`) which authors PRs/commits with no
registered login. OpenCode’s 2025 tool prompt instructed
`noreply@opencode.ai` plus a Markdown footer that the verb matcher cannot
see; that prompt file is gone from current `dev`, so treat those strings as
historical census traces, not a live default. Gemini CLI, Cline, Goose core,
Continue, SWE-agent, and most IDE tab-complete products emit no official
git trailer.

Coverage below is the **production matcher** only (author pair, vendor
email, GitHub bot login, co-author identity, complete unquoted attribution
line). Shadow regexes in `ai_signatures.py` are out of scope. Channel
kinds: **(a)** human is git author, tool leaves a trailer/footer;
**(b)** the tool is git author; **(c)** GitHub App is PR/commit author
(squash may drop trailers).

## Inventory vs `source_policy.py`

| Product | Vendor | Channel | Exact first-party string | Default | Policy |
|---|---|---|---|---|---|
| Claude Code CLI | Anthropic | (a) trailer; Markdown footer variants | `Co-Authored-By: <model> <noreply@anthropic.com>`; footer `🤖 Generated with [Claude Code](https://claude.com/claude-code)` | On; hide with empty `attribution.commit` | Email covered. **New URL not in markers.** Old `claude.ai/code` markers still registered. |
| Claude cloud / Remote Control | Anthropic | (a) extra trailer | `Claude-Session:` + claude.ai URL | On; `attribution.sessionUrl` | **Not registered** (session pointer, not authorship) |
| Claude GitHub Action / App | Anthropic | (b)/(c); human as co-author on Action | App: `claude[bot]`, `anthropic-code-agent[bot]`. Action footer `Generated with [Claude Code](https://claude.ai/code)` | App commits; `includeCoAuthoredBy` | Bots covered. Action footer URL is the **old** registered marker. |
| Cursor local Agent / CLI | Anysphere | (a) git trailer | Docs: “Made with Cursor” trailer. Policy/git `--trailer` form: `Made-with: Cursor`. Co-author email `cursoragent@cursor.com` | On; Settings > Git & PRs > Attribution | `Made-with: Cursor` marker covered. Email covered. |
| Cursor Cloud Agent | Anysphere | (b) signed author | Signed HSM commits; GitHub App [cursor](https://github.com/apps/cursor) → `cursor[bot]`. Email `cursoragent@cursor.com` | Always for cloud | Email + `cursor` login covered |
| OpenAI Codex CLI | OpenAI | (a) trailer | `Co-authored-by: Codex <noreply@openai.com>` | On when git-attribution enabled; blank `commit_attribution` disables | Co-author + vendor emails covered |
| Codex GitHub App | OpenAI | (b)/(c) | logins `chatgpt-codex-connector`, `openai-code-agent`, `codex`. Real `%an` is often `GPT 5.x` | App commits | Login covered. GPT display name on those logins admitted from author_identity v3 |
| GitHub Copilot cloud agent | GitHub | (b); human as co-author | Author is Copilot; signed; session-log URL in message | Always for cloud agent | logins `copilot`, `copilot-swe-agent` covered |
| Copilot CLI | GitHub | (a) trailer | Docs: `Co-authored-by` trailer, default `includeCoAuthoredBy: true`. Exact line **UNCONFIRMED** in docs (VS Code uses `copilot@github.com`) | On | Emails `copilot@github.com` and `223556219+Copilot@…` covered |
| VS Code Git | Microsoft | (a) trailer | `Co-authored-by: Copilot <copilot@github.com>` | **Off** (`git.addAICoAuthor` default `off` as of 1.119) | Email covered |
| Copilot Autofix | GitHub | (b) | `github-advanced-security`, `github-code-quality`; assignee `copilot-swe-agent[bot]` | App / Autofix | Covered as `security_autofix` / autonomous |
| Aider | Aider-AI | (a) name suffix and/or trailer | `Co-authored-by: aider (<model>) <aider@aider.chat>`; else `%an` += ` (aider)` | Trailer default True (options.html); takes precedence over suffix | Trailer + emails covered. **Name suffix not covered.** |
| OpenHands | All Hands | (b) or (a) co-author | `openhands <openhands@all-hands.dev>` | On (historical CLI wrapper) | Vendor email covered |
| OpenCode | SST / anomalyco | (a) historical prompt; (b) GitHub Action | 2025 prompt: `🤖 Generated with [opencode](https://opencode.ai)` + `Co-Authored-By: opencode <noreply@opencode.ai>`. Current Action: `{slug}[bot]@users.noreply.github.com` as author | Historical on; current local prompt **does not** contain those lines | `opencode@sst.dev` registered. **`noreply@opencode.ai` and Markdown footer not registered.** |
| Gemini CLI | Google | none | No official identity | No default | Alias `Gemini CLI` is verb-line only |
| Gemini Code Assist | Google | (b) | `gemini-code-assist[bot]` | App commits | Covered |
| Google Jules | Google Labs | (b)/(c) | App creates PRs; logins `google-labs-jules`, `labs-code-app` | App commits | Covered. Exact `%an <%ae>` **UNCONFIRMED** in docs |
| Devin | Cognition | (b) configurable; (a) CLI trailer | App `devin-ai-integration[bot]`. CLI: `Generated with [Devin]` + `Co-Authored-By: Devin` | CLI attribution default true | Bot login covered. **Message lines not registered.** |
| Warp / Oz | Warp | (b) GitHub App | Docs: Warp Factories GitHub App authors PRs/commits. Also `@oz-agent` / Oz by Warp App in Actions docs | App vs user depends on API key | `oz-by-warp`, `agent@warp.dev`, `oz-agent@warp.dev` covered. **“Warp Factories” slug UNCONFIRMED** |
| Mistral Vibe | Mistral | (a) footer + trailer | `Generated by Mistral Vibe.` + `Co-Authored-By: Mistral Vibe <vibe@mistral.ai>` | On (`include_commit_signature: true`) | Co-author + email covered. Footer matches verb+alias (`Generated by Mistral Vibe.`) |
| Qwen Code | Alibaba | (a) trailer; git notes | `Co-authored-by: Qwen-Coder <qwen-coder@alibabacloud.com>`; notes `refs/notes/ai-attribution` | On (`general.gitCoAuthor.commit: true`) | Co-author + email covered. Notes are **not** commit messages |
| Qoder | Alibaba | (b) | `qoderai[bot]` | App commits | Covered |
| Atlassian Rovo | Atlassian | (a) bare co-author (CLI, observed); Jira agent is **user as author** | Policy: `Co-authored-by: Atlassian Rovo Dev`. Jira Coding Agent: user is commit/PR author | CLI UNCONFIRMED in current docs; Jira: user | Bare name covered. Jira path leaves **no bot author** |
| Pi | earendil-works | none in core | Core has no trailer. Community extension: `Generated-By: pi 0.63.2` | Core: none | Versioned `Generated-By: pi` line already matched. Not a first-party default |
| Kilo Code | Kilo-Org | (a) cloud co-author hook | Tests: `Co-authored-by: kiloconnect[bot] <240665456+kiloconnect[bot]@users.noreply.github.com>`. IDE commit-message button: no trailer | Cloud hook when co-author configured | Alias only. **`kiloconnect` login not registered** |
| Roo Code / Roomote | Roo Code | (b) Roomote | `roomote@roocode.com`, login `roomote` | Cloud Roomote | Covered. Local Roo: **no trailer found** |
| Cline | Cline | none | Commit-message generator only | No trailer | No identity |
| Goose | Block / AAIF | none | No trailer in core | No default | Verb alias only |
| Continue | Continue.dev | none | No trailer found | No default | Unregistered |
| SWE-agent | Princeton NLP | none | No trailer found | No default | Unregistered |
| Amazon Q / Kiro | AWS | (c) Q GitHub App; Kiro Web (a)/(c) | App [amazon-q-developer](https://github.com/apps/amazon-q-developer). Kiro: “you and itself as co-authors”; PRs by Kiro Agent app | App / agent | **Q login not registered.** Kiro exact strings **UNCONFIRMED** |
| JetBrains Junie | JetBrains | (c) CI/GitHub; local UNCONFIRMED | Docs: Junie can `git commit`. No documented trailer | UNCONFIRMED | **Not registered** |
| Vercel Agent / v0 | Vercel | (b) App; human as co-author | “created and signed by the Vercel Agent GitHub App, with you added as a git co-author” | App commits | v0 verb alias only. **App login UNCONFIRMED** |
| CodeRabbit | CodeRabbit | reviewer; optional user-identity push | Reviews PRs; can push **as the requester** | Not a default author bot | Do not treat as git author |
| Windsurf/Cascade, Amp, Factory Droid, Trae, Augment, Replit Agent, Lovable, Zed, Tabnine | various | none found | — | UNCONFIRMED none | Do not invent strings |

## Per-agent notes

### Claude Code (Anthropic)

English settings reference
([code.claude.com/docs/en/settings-reference](https://code.claude.com/docs/en/settings-reference)):

- Default **commit** attribution: `Co-Authored-By: <noreply@anthropic.com>`
  with the session model name (`Claude Sonnet 5`, or `Claude` when the
  model is not public).
- Default **PR** attribution (not production git evidence):
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- Cloud / Remote Control commits add a `Claude-Session` trailer with a
  claude.ai session URL (`attribution.sessionUrl`, default `true`).
- Hide with empty `attribution.commit` / `attribution.pr` and
  `sessionUrl: false`. Deprecated `includeCoAuthoredBy: false` still
  works until `attribution.commit` or `.pr` is set.

Localized settings pages still print a **commit** default that includes
the Markdown footer plus the co-author, e.g.
`🤖 Generated with [Claude Code](https://claude.com/claude-code)` then
`Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`
([docs.anthropic.com/de/docs/claude-code/settings](https://docs.anthropic.com/de/docs/claude-code/settings)).
Treat the English reference as the spec and the localized block as a
real emitted variant.

`anthropics/claude-code-action` still instructs the PR body signature
`Generated with [Claude Code](https://claude.ai/code)`
(`src/create-prompt/index.ts`) and a **human** `Co-authored-by:` on
Action commits. `includeCoAuthoredBy` remains in the Action README.

Matcher: vendor emails `noreply@anthropic.com` / `claude@anthropic.com`
ignore display-name suffixes, so model-tagged co-authors are covered.
Registered Markdown markers still use `https://claude.ai/code`. The
documented `https://claude.com/claude-code` URL is a **gap**.
`Claude-Session` is a session pointer, not authorship.

GitHub App identities `claude[bot]` and `anthropic-code-agent[bot]` are
registered.

### Cursor (Anysphere)

Help docs: when Agent creates commits or PRs via `gh pr create`, Cursor
can add a **`Made with Cursor` trailer**. On by default. Toggle:
Settings > Agent > Attribution; from 3.11, Settings > Git & PRs >
Attribution. Enterprise admin can force off.
Source: [cursor.com/help/integrations/git](https://cursor.com/help/integrations/git).

The help page does **not** quote the hyphenated git trailer key. The
production marker already registered is `Made-with: Cursor` (trailer key
`Made-with`, value `Cursor`). The verb table cannot match it (`Made` is
not a verb; `-with:` is not a connector). Do not loosen verbs.

Co-author identity `Cursor` / `Cursor Agent` `<cursoragent@cursor.com>`
is registered. Cloud Agents sign every commit with an HSM-backed
Ed25519 key and show Verified
([cursor.com/docs/cloud-agent/security-network](https://cursor.com/docs/cloud-agent/security-network)).
GitHub App: [github.com/apps/cursor](https://github.com/apps/cursor) →
login `cursor` registered.

Cursor Blame is an Enterprise server overlay, not a commit trailer
([cursor.com/docs/integrations/cursor-blame.md](https://cursor.com/docs/integrations/cursor-blame.md)).

### OpenAI Codex

Current first-party source
[`openai/codex` `codex-rs/ext/git-attribution/src/world_state.rs`](https://github.com/openai/codex/blob/main/codex-rs/ext/git-attribution/src/world_state.rs):

```
Co-authored-by: Codex <noreply@openai.com>
```

Legacy instructions used the same trailer. Enabled instructions also
tell the model to put `Generated with [Codex](https://openai.com/codex/).`
on **pull request bodies** (not production git evidence). Attribution is
gated on backend `commit_attribution_enabled`; blank config disables.
Injection is prompt-based, not a git hook, so the model can omit the
trailer. Local sessions often commit as the human with no trailer
([discussion #9449](https://github.com/openai/codex/discussions/9449)).
That population is unobservable; message regex cannot recover it.

Three observable channels:

1. **Author email `@openai.com`.** `Codex <codex@openai.com>` and
   `GPT 5.x <codex@openai.com>`. GitHub `author-email:codex@openai.com`
   was ~326k commits (2026-08-26). Vendor-exclusive emails already
   ignored the display name.
2. **Author is a GitHub App, display name is the model.**
   `GPT 5.6 <…+codex@users.noreply.github.com>` was a matcher miss:
   the author module required the name to share a vendor word with the
   bot login (`codex` / `chatgpt` / `openai`). Fixed 2026-08-26
   (author_identity v3): model-family tokens (`gpt`, `codex`, `o3`,
   `o4`) corroborate the same tool’s GitHub bot address. Crossed pairs
   (`GPT 5.6` + Cursor bot email) still fail.
3. **Human author + trailer.** Wild names next to `@openai.com`
   (`OpenAI Codex`, `OpenAI`, `ChatGPT`, `Codex o4-mini`) already
   matched via the co-author vendor-email fallback.

Do not register `codex@example.com` (hijacked placeholder,
[codex#18095](https://github.com/openai/codex/issues/18095)).

Vendor emails `codex@openai.com` and `noreply@openai.com` are registered
and ignore display names (`GPT 5.x`). GitHub logins
`chatgpt-codex-connector`, `openai-code-agent`, `codex` are registered.

### GitHub Copilot

Cloud agent: commits are **authored by Copilot**, the human who started
the task is co-author, commits are signed, message includes a session-log
URL.
[docs.github.com/en/copilot/responsible-use/agents](https://docs.github.com/en/copilot/responsible-use/agents),
[manage-and-track-agents](https://docs.github.com/en/copilot/how-tos/copilot-on-github/use-copilot-agents/manage-and-track-agents).
API examples assign `copilot-swe-agent[bot]`.

Copilot CLI: `includeCoAuthoredBy` boolean, default `true`
([CLI config directory](https://docs.github.com/en/enterprise-cloud@latest/copilot/reference/copilot-cli-reference/cli-config-dir-reference)).
Docs do not quote the exact `Name <email>` pair.

VS Code first-party source
[`extensions/git/src/repository.ts`](https://github.com/microsoft/vscode/blob/main/extensions/git/src/repository.ts):

```
Co-authored-by: Copilot <copilot@github.com>
```

`git.addAICoAuthor` default in that file is `'off'` (opt-in after the
1.119 revert; docs pages still sometimes list `chatAndAgent` as default —
trust the source default `'off'`).

Autofix / Code Quality: registered as `github-advanced-security` and
`github-code-quality` (`security_autofix`). Suggested-fix “Commit
suggestion” on GitHub is the **human** applying the suggestion unless
agentic autofix opens a PR as Copilot.

### Aider

[`aider/repo.py`](https://github.com/Aider-AI/aider/blob/main/aider/repo.py)
emits:

```
Co-authored-by: aider ({model_name}) <aider@aider.chat>
```

when `aider_edits` and `attribute_co_authored_by`. Otherwise it sets
`GIT_AUTHOR_NAME` / `GIT_COMMITTER_NAME` to `{user.name} (aider)`.

[Options reference](https://aider.chat/docs/config/options.html):
`--attribute-co-authored-by` default **True**, and then takes precedence
over the name suffix unless `--attribute-author` / `--attribute-committer`
are explicitly True. [Git docs](https://aider.chat/docs/git.html) still
describe the suffix as the attribution mechanism.

Matcher has `name_pattern` `aider \([^\r\n<>]+\)` on the **co-author
name**, plus emails `aider@aider.chat` / `aider@aider.dev`. It does not
treat `Jane Doe (aider)` as an author identity. Older suffix-only
commits are silent. Committer-only `(aider)` is not production evidence
(`committer_identity_is_production_evidence: false`).

### OpenHands (All Hands)

Historical CLI wrapper
([OpenHands#10300](https://github.com/All-Hands-AI/OpenHands/pull/10300))
injects `Co-authored-by: openhands <openhands@all-hands.dev>`. Vendor
email `openhands@all-hands.dev` is registered and covers author and
co-author. Current `OpenHands/OpenHands` default branch is a frontend
app; `OpenHands/software-agent-sdk` has no attribution path in the tree.
Treat the email identity as still valid for the census window; do not
claim a new 2026 default from the current UI repo.

Login `openhands-agent` is registered.

### OpenCode (SST / anomalyco)

Pinned first-party prompt
[`sst/opencode` `packages/opencode/src/tool/bash.txt` @ `fd4648da`](https://github.com/sst/opencode/blob/fd4648da177d264a0bb0239455355e045f892c19/packages/opencode/src/tool/bash.txt)
instructed HEREDOC commits ending with:

```
🤖 Generated with [opencode](https://opencode.ai)

Co-Authored-By: opencode <noreply@opencode.ai>
```

The same Markdown line was for PR bodies (not production git evidence).
The verb regex requires a complete line `Generated with OpenCode`
**without** a Markdown link, so that footer misses. `noreply@opencode.ai`
is not in `VENDOR_EXCLUSIVE_EMAILS` (only `opencode@sst.dev`).

On current `anomalyco/opencode` `dev`, `packages/opencode/src/tool/bash.txt`
is absent and `packages/opencode/src/session/prompt/default.txt` does not
mention those lines. GitHub Action
[`packages/opencode/src/cli/cmd/github.handler.ts`](https://github.com/anomalyco/opencode/blob/dev/packages/opencode/src/cli/cmd/github.handler.ts)
commits as the App (`{slug}[bot]@users.noreply.github.com` from
`.github/actions/setup-git-committer/action.yml`) and optionally
`Co-authored-by: ${actor} <${actor}@users.noreply.github.com>` (the
**human** trigger, not OpenCode).

### Gemini CLI / Code Assist / Jules

Gemini CLI `scripts/generate-git-commit-info.js` embeds the **CLI’s own**
git SHA into the build; it does not write commit trailers. First-party
issues document the **absence** of an official co-author
([gemini-cli#25721](https://github.com/google-gemini/gemini-cli/issues/25721),
[#25525](https://github.com/google-gemini/gemini-cli/issues/25525)). Do
not register guessed emails.

Gemini Code Assist `gemini-code-assist[bot]` and Jules
`google-labs-jules` / `labs-code-app` are registered GitHub Apps. Jules
docs ([jules.google/docs](https://jules.google/docs/),
[developers.google.com/jules/api](https://developers.google.com/jules/api))
describe GitHub App PRs (`AUTO_CREATE_PR`) but do not quote `%an <%ae>`.

### Devin (Cognition)

GitHub App login `devin-ai-integration` is registered. Org **Commit
authoring** can put Devin or the user on `%an`
([docs.devin.ai/integrations/gh](https://docs.devin.ai/integrations/gh)).
In user-as-author modes the bot login is absent from `%an`.

CLI config
([docs.devin.ai/cli/reference/configuration/config-file](https://docs.devin.ai/cli/reference/configuration/config-file)):
`attribution` default `true` adds a `Generated with [Devin]` line and a
`Co-Authored-By: Devin` trailer to commits and PRs. Set `false` to omit.
The Markdown/`[Devin]` form does **not** match the verb+alias complete
line (`Generated with Devin` without brackets). Bare `Co-Authored-By: Devin`
(no email) is not in `BARE_COAUTHOR_IDENTITIES`. Both are **gaps**.

### Warp / Oz

[docs.warp.dev GitHub integration](https://docs.warp.dev/platform/integrations/github/):
`@warp-agent` runs authenticate as the **Warp Factories GitHub App**;
commits and PRs are attributed to that App, not the mentioning user.
Actions docs still mention the **Oz by Warp GitHub App** and requiring
the `oz-agent` GitHub user. Policy has `oz-by-warp`, `oz-agent@warp.dev`,
`agent@warp.dev`. The current “Warp Factories” App slug is
**UNCONFIRMED** as a GitHub login spelling.

### Mistral Vibe

[`mistralai/mistral-vibe` `vibe/core/system_prompt.py`](https://github.com/mistralai/mistral-vibe/blob/main/vibe/core/system_prompt.py)
`_add_commit_signature()` (included when `include_commit_signature` is
true, default in config):

```
Generated by Mistral Vibe.
Co-Authored-By: Mistral Vibe <vibe@mistral.ai>
```

Co-author identity is registered. `Generated by Mistral Vibe.` matches
the verb+alias complete-line regex (`Generated` + ` by ` + `Mistral Vibe`
+ optional period). No marker addition needed.

### Qwen Code / Qoder

[docs/users/configuration/settings.md](https://github.com/QwenLM/qwen-code/blob/main/docs/users/configuration/settings.md):
`general.gitCoAuthor.commit` default `true` adds a Co-authored-by trailer
**and** a git note on `refs/notes/ai-attribution`. First-party default
identity from PR #207 / config: `Qwen-Coder <qwen-coder@alibabacloud.com>`.
That pair is registered. Git notes are not commit messages and are
invisible to message scanners. `general.gitCoAuthor.pr` appends a PR
attribution line (not production git evidence); exact PR string not
quoted.

Qoder GitHub App `qoderai[bot]` is registered. Policy also has
`Qwen Code` / `agents-noreply@craft.do` as a co-author pair
(2026-06-11); that email was **not** re-confirmed in qwen-code source
this round.

### Atlassian Rovo Dev

Jira Coding Agent
([support.atlassian.com/rovo/docs/generate-code-from-a-work-item-in-jira](https://support.atlassian.com/rovo/docs/generate-code-from-a-work-item-in-jira/)):
**you** are listed as pull request author and author of any commits.
That path is (a) with **no** bot author. Policy `BARE_COAUTHOR_IDENTITIES`
`Atlassian Rovo Dev` remains for CLI trailers; current Rovo Dev CLI docs
do not quote that exact line.

### Pi (earendil-works/pi)

First-party `packages/coding-agent` has git helpers and example
extensions; **no** `Generated-By` in core. `Generated-By: pi v?X.Y.Z` is
matched in `source_matcher.py` because of census volume. The npm package
`pi-co-authored-by` is a **community** extension (`Co-Authored-By: …
<noreply@pi.dev>` + `Generated-By: pi 0.63.2`). Do not treat
`noreply@pi.dev` as a first-party vendor email.

### Kilo Code

IDE docs
([git-commit-generation.md](https://github.com/Kilo-Org/kilocode/blob/main/packages/kilo-docs/pages/code-with-ai/features/git-commit-generation.md))
generate a conventional commit **message** only; no trailer.

Cloud wrapper
[`Kilo-Org/cloud` `commit-co-author-hook.ts`](https://github.com/Kilo-Org/cloud/blob/main/services/cloud-agent-next/wrapper/src/commit-co-author-hook.ts)
appends `Co-authored-by: ${name} <${email}>` via a managed
`prepare-commit-msg` hook. Unit tests use:

```
Co-authored-by: kiloconnect[bot] <240665456+kiloconnect[bot]@users.noreply.github.com>
```

That login is **not** in `GITHUB_AI_BOT_LOGINS`. Town settings copy
allows omitting the trailer. Kilo’s vendored OpenCode GitHub handler
co-authors the **workflow actor**, not Kilo.

### Roo Code / Cline / Goose / Continue / SWE-agent

Roo local: no `Co-authored-by` / `Made-with` in the Roo-Code tree.
Roomote email `roomote@roocode.com` and login `roomote` are registered.

Cline `commit-message-generator.ts` writes a message for the SCM input;
no trailer.

Goose (`aaif-goose/goose`, formerly `block/goose`): no attribution
module. Verb alias `Goose` only.

Continue and SWE-agent: no trailer files found.

### Amazon Q Developer / Kiro

Amazon Q for GitHub App:
[github.com/apps/amazon-q-developer](https://github.com/apps/amazon-q-developer),
docs
[amazon-q-for-github](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/amazon-q-for-github.html).
The App creates PRs and can commit on the PR branch. Exact
`amazon-q-developer[bot]` noreply spelling is **UNCONFIRMED** against a
quoted identity page; the App slug is first-party.

Kiro Web
([kiro.dev/docs/web/github](https://kiro.dev/docs/web/github/)): the
agent “includes both you and itself as co-authors in every commit”; PRs
default to the **Kiro Agent GitHub app**, optional “create PRs as your
GitHub user”. Exact `Co-authored-by:` name/email **UNCONFIRMED**. Kiro
IDE source-control docs generate commit messages only.

### JetBrains Junie

Junie can stage and commit
([jetbrains.com/help/resharper/Execute_complex_tasks_with_Junie.html](https://www.jetbrains.com/help/resharper/Execute_complex_tasks_with_Junie.html)).
No documented trailer. Do not use leaked-prompt strings.

### Vercel Agent / v0

[vercel.com/docs/agent/chat/github](https://vercel.com/docs/agent/chat/github):
commits and PRs are **created and signed by the Vercel Agent GitHub
App**, with the user added as a git co-author. Branches
`vercel-agent/…`. Exact App login and co-author email **UNCONFIRMED**.
Policy has verb alias `v0` only.

### CodeRabbit

Primary product is PR review
([docs.coderabbit.ai](https://docs.coderabbit.ai/platforms/github-com)).
Changelog: Agent can push / open PRs **using the requester’s GitHub
identity**. That is not a default bot-author trace. Do not add as an
authoring tool without a first-party author identity.

### Products with no first-party git trace found

Windsurf / Cascade (now Devin Desktop docs), Sourcegraph Amp / Cody,
Factory Droid, Trae, Augment Code, Replit Agent, Lovable, Zed agent,
Tabnine: no official “we always write this git line” in docs fetched
this round. Mark **UNCONFIRMED none**; do not invent strings.

## Variants that break matching

- **Emoji prefix** on Markdown footers (`🤖 Generated with …`). Exact
  markers must include the emoji line separately from the plain line.
- **Markdown link** around the product name. Verb+alias complete-line
  matching requires `Generated with OpenCode`, not
  `Generated with [opencode](https://opencode.ai)`.
- **Model-name suffix** on author/co-author display names (`Claude Opus
  4.6 (1M context)`). Vendor-exclusive email already ignores display
  name; exact `AUTHOR_IDENTITIES` pairs do not.
- **URL drift** (`claude.ai/code` → `claude.com/claude-code`).
- **Squash-merge** often drops trailers unless GitHub “use PR title and
  description” keeps the PR body; PR body is not production evidence.
- **Cloud vs local**: Cursor / Copilot / Devin / Warp identity depends
  on which surface created the commit. IDE attribution toggles often do
  not apply to cloud authors.

## Policy gaps

Add **only** first-party confirmed exact markers or identities. Do not
widen `EXPLICIT_ATTRIBUTION_VERBS`.

Worth adding:

1. **Claude Code Markdown footer URL** (`claude_code` markers), exact
   lines:
   - `Generated with [Claude Code](https://claude.com/claude-code)`
   - `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
   Keep the existing `claude.ai/code` lines for older commits.
2. **Devin commit lines** (`devin`):
   - `Generated with [Devin]`
   - `🤖 Generated with [Devin]` if a first-party example appears
     (docs quote without emoji)
   - Bare co-author name `Devin` in `BARE_COAUTHOR_IDENTITIES` (docs:
     `Co-Authored-By: Devin` with no email)
3. **OpenCode historical co-author** (census window, not necessarily
   current default): vendor-exclusive or co-author pair
   `opencode <noreply@opencode.ai>`, plus exact marker
   `🤖 Generated with [opencode](https://opencode.ai)` and the
   non-emoji form if pinned source shows it without emoji (the 2025
   prompt used the emoji form).
4. **Kilo Cloud** GitHub login `kiloconnect` on
   `GITHUB_AI_BOT_LOGINS` (autonomous_agent), from first-party tests.
5. **Amazon Q Developer** GitHub App login, after confirming the
   `[bot]` noreply spelling on a real App-authored commit. App slug
   `amazon-q-developer` is first-party.

Not recommended without more evidence:

- `Claude-Session:` (session URL, not authorship)
- Gemini CLI guessed emails
- Junie `junie@jetbrains.com` until JetBrains documents it
- Aider `(aider)` author-name suffix as a substring (high FP); would
  need a dedicated suffix module
- `noreply@pi.dev` (community extension)
- Warp “Factories” login until the App slug is quoted
- Kiro / Vercel Agent co-author emails until docs quote them
- PR-body footers (`pr_body_is_production_evidence` stays false)
- Cursor Blame
- Git notes (`refs/notes/ai-attribution`)
- Verb-table loosening for Markdown / `Made-with:`

## Method

GitHub code search (rate-limited; used recursive git trees + raw files
instead), official docs fetches, and `source_policy.py` /
`source_matcher.py` complete-line rules. Claims without a docs URL or
source file are marked UNCONFIRMED.
