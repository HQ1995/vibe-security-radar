# AI markers

A lead list for step 5 of the [audit protocol](AUDIT-PROTOCOL.md): where AI tools leave
traces on commits, pull requests and repositories. Use it to know what to look for on the
causal object. It is not a verdict rule:

- A match is a lead. Attribution still needs the marker on the object that carries the
  causal change, with its exact quote, as DATA-SCHEMA requires.
- No match proves nothing. `NOT_AI` needs the named identity, object-local marker absence
  and disclosure-convention check the protocol defines.
- Repository configuration files and AI activity elsewhere in a repository are never
  admissible attribution for a specific change.
- A marker dated before the tool existed (see *Earliest dates*) needs a second look.

Extracted on 2026-10-14 from the retired `cve-analyzer` detectors (`source_policy.py`
schema 5, `ai_signatures.py`; see commit `f857e3f`). Add new tools here as
cases surface them.

## High-precision identities

Exact identities and lines that the old detector treated as production evidence.

### `aider`

- Co-author trailer: `aider` with `aider@aider.dev`, `aider@aider.chat`
- Vendor-only email: `aider@aider.dev`, `aider@aider.chat` (assistant)

### `atlassian_rovo`

- Bare co-author name: `Atlassian Rovo Dev`

### `claude_code`

- Author identity: `claude[bot] <209825114+claude[bot]@users.noreply.github.com>` (from 2025-05-20); `anthropic-code-agent[bot] <242468646+Claude@users.noreply.github.com>` (from 2025-11-06)
- Co-author trailer: `Claude` with `noreply@anthropic.com`, `claude@anthropic.com`; `anthropic-code-agent[bot]` with `242468646+Claude@users.noreply.github.com`
- Vendor-only email: `noreply@anthropic.com`, `claude@anthropic.com` (assistant); `claude-bot@bun.sh` (autonomous_agent)
- GitHub bot login: `claude`, `anthropic-code-agent` (autonomous_agent, from 2025-05-20)
- Complete attribution line: `Generated with [Claude Code](https://claude.ai/code)`; `🤖 Generated with [Claude Code](https://claude.ai/code)`; `Changes auto-committed by Conductor`
- Model family names: `claude`, `opus`, `sonnet`, `haiku`

### `cursor`

- Author identity: `cursor[bot] <206951365+cursor[bot]@users.noreply.github.com>` (from 2025-06-04)
- Co-author trailer: `Cursor`, `Cursor Agent` with `cursoragent@cursor.com`
- Vendor-only email: `cursoragent@cursor.com` (autonomous_agent)
- GitHub bot login: `cursor` (autonomous_agent, from 2025-06-04)
- Complete attribution line: `Made-with: Cursor`

### `devin`

- GitHub bot login: `devin-ai-integration` (autonomous_agent, from 2024-03-01)

### `github_copilot`

- Co-author trailer: `Copilot` with `223556219+Copilot@users.noreply.github.com`, `copilot@github.com`
- Vendor-only email: `copilot@github.com` (assistant)
- GitHub bot login: `copilot`, `copilot-swe-agent` (autonomous_agent, from 2022-06-01); `github-advanced-security`, `github-code-quality` (security_autofix, from 2024-01-01)

### `google_gemini`

- Author identity: `gemini-code-assist[bot] <176961590+gemini-code-assist[bot]@users.noreply.github.com>` (from 2025-12-15)
- GitHub bot login: `gemini-code-assist` (autonomous_agent, from 2025-02-01)
- Model family names: `gemini`

### `google_jules`

- Author identity: `labs-code-app[bot] <161369871+labs-code-app[bot]@users.noreply.github.com>` (from 2024-12-11)
- GitHub bot login: `google-labs-jules`, `labs-code-app` (autonomous_agent, from 2024-12-11)

### `kimi_code`

- Model family names: `kimi`

### `mistral_vibe`

- Co-author trailer: `Mistral Vibe` with `vibe@mistral.ai`
- Vendor-only email: `vibe@mistral.ai` (assistant)
- Model family names: `mistral`, `devstral`

### `openai_codex`

- Author identity: `Codex <chatgpt-codex-connector[bot]@users.noreply.github.com>` (from 2025-05-01); `openai-code-agent[bot] <242516109+Codex@users.noreply.github.com>` (from 2025-11-06)
- Co-author trailer: `Codex` with `chatgpt-codex-connector[bot]@users.noreply.github.com`, `noreply@openai.com`, `codex@openai.com`; `openai-code-agent[bot]` with `242516109+Codex@users.noreply.github.com`
- Vendor-only email: `codex@openai.com`, `noreply@openai.com` (assistant)
- GitHub bot login: `chatgpt-codex-connector`, `openai-code-agent`, `codex` (autonomous_agent, from 2025-05-01)
- Model family names: `gpt`, `codex`, `o3`, `o4`

### `opencode`

- Vendor-only email: `opencode@sst.dev` (assistant)

### `openhands`

- Vendor-only email: `openhands@all-hands.dev` (autonomous_agent)
- GitHub bot login: `openhands-agent` (autonomous_agent, from 2024-03-01)

### `openwork`

- Co-author trailer: `OpenWork` with `noreply@alibaba.com`

### `qoder`

- Author identity: `qoderai[bot] <215938697+qoderai[bot]@users.noreply.github.com>` (from 2025-01-01)
- GitHub bot login: `qoderai` (autonomous_agent, from 2025-01-01)

### `qwen_code`

- Co-author trailer: `Qwen-Coder` with `qwen-coder@alibabacloud.com`; `Qwen Code` with `agents-noreply@craft.do`
- Vendor-only email: `qwen-coder@alibabacloud.com` (assistant)
- Model family names: `qwen`

### `roo_code`

- Vendor-only email: `roomote@roocode.com` (autonomous_agent)

### `roomote`

- GitHub bot login: `roomote` (autonomous_agent, from 2025-01-01)

### `warp`

- Author identity: `warp[bot] <agent@warp.dev>` (from 2023-06-01); `oz-by-warp[bot] <243557089+oz-by-warp[bot]@users.noreply.github.com>` (from 2026-05-01)
- Co-author trailer: `Oz`, `Oz Agent` with `oz-agent@warp.dev`
- Vendor-only email: `agent@warp.dev`, `oz-agent@warp.dev` (assistant)
- GitHub bot login: `oz-by-warp` (autonomous_agent, from 2026-05-01)

A complete, unquoted line `<Generated/Created/Written/Assisted> with <tool>` names the tool for: Claude Code, GitHub Copilot, Cursor, Aider, OpenAI Codex, Gemini CLI, OpenCode, Roo Code, Mistral Vibe, Pi, Kilo Code, v0, Goose.

## Broader leads by tool

Case-insensitive patterns from the old detector, by the commit field they read. They are
noisier than the identities above; confirm every hit on the object itself.

- **`abacus_ai`** (from 2025-01-01)
  - author_email: `@abacus\.ai`
  - author_name: `abacus-ai\[bot\]`; `deep-agent\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Abacus`
- **`aether`**
  - author_email: `@tryaether\.ai`
  - author_name: `aether[_-]ai[_-]agent`
  - message: `Co-[Aa]uthored-[Bb]y:.*[Aa]ether.*<.*@tryaether\.ai>`; `Merged via /review-pr\s*->\s*/prepare-pr\s*->\s*/merge-pr`; `Merged via squash\.\s*\n\s*\nPrepared head SHA:`
- **`aider`** (from 2023-05-01)
  - author_email: `aider@aider\.dev`
  - author_name: `\(aider\)`
  - committer_email: `aider@aider\.dev`
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*aider[ \t]*\([^\r\n<>]+\)[ \t]*<aider@aider\.chat>[ \t]*(?=$|\r?\n)`; `Assisted-by:\s*[Aa]ider\b`; `Co-Authored-By:.*aider.*<.*@aider\.dev>`; `Co-authored-by:.*\baider\b`
- **`amazon_q`** (from 2023-11-01)
  - author_email: `amazonq.*@amazon\.com`
  - author_name: `amazon-?q(?:-developer)?\[bot\]`
  - message: `Assisted\s+by\s+\[?Amazon\s*Q(?:\s*Developer)?\]?`; `Co-authored-by:.*\bamazon.?q\b`
- **`amp`** (from 2025-05-01)
  - author_email: `amp@sourcegraph\.com`
  - author_name: `\bamp-agent\b`; `amp\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Amp.*<.*@sourcegraph\.com>`; `Co-authored-by:.*\bamp\b.*sourcegraph`
- **`atlassian_rovo`**
  - author_name: `^atlassian[.-]rovo(?:-dev)?$`
  - message: `Co-[Aa]uthored-[Bb]y:.*Atlassian Rovo`
- **`augment_code`** (from 2025-04-01)
  - author_email: `@augmentcode\.com`
  - author_name: `augment-code\[bot\]`; `augment\[bot\]`
  - message: `Co-authored-by:.*\baugment\b`
- **`blackbox_ai`** (from 2023-01-01)
  - author_email: `@blackbox\.ai`
  - author_name: `blackbox-ai\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Blackbox\s*AI`
- **`bolt_new`** (from 2024-06-01)
  - author_email: `@stackblitz\.com`; `^bolt@stackblitz\.com$`
  - author_name: `bolt-new\[bot\]`; `bolt\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*\bBolt\b(?!ins)`; `Co-authored-by:.*\bbolt\.new\b`
- **`claude_code`** (from 2025-01-01)
  - author_email: `(noreply|claude)@anthropic\.com`; `^209825114\+claude\[bot\]@users\.noreply\.github\.com$`; `^242468646\+Claude@users\.noreply\.github\.com$`
  - author_name: `^anthropic-code-agent\[bot\]$`; `^claude\[bot\]$`
  - committer_email: `(noreply|claude)@anthropic\.com`
  - message: `(?:^|\r?\n)Changes auto-committed by Conductor[ \t]*(?=$|\r?\n)`; `(?:^|\r?\n)Co-authored-by:[ \t]*anthropic-code-agent\[bot\][ \t]*<242468646\+Claude@users\.noreply\.github\.com>[ \t]*(?=$|\r?\n)`; `Assisted-by:\s*Claude\b`; `Co-Authored-By:.*Claude.*<.*@anthropic\.com>`; `Co-authored-by:.*\bclaude\b`; `Generated with Claude Code`
- **`cline`** (from 2024-06-01)
  - author_email: `@cline\.bot`
  - author_name: `cline\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Cline.*<.*@cline\.bot>`; `Co-authored-by:.*\bcline\b`
- **`codegeex`**
  - author_email: `@codegeex\.cn`
  - author_name: `codegeex\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*CodeGeeX`; `Co-authored-by:.*\bcodegeex\b`
- **`codegpt`**
  - author_email: `@codegpt\.co`
  - author_name: `codegpt\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*CodeGPT`; `Co-authored-by:.*\bcodegpt\b`
- **`codeium`**
  - author_email: `@codeium\.com`
  - message: `Co-authored-by:.*\bcodeium\b`
- **`coderabbit`** (from 2023-08-22)
  - author_email: `^136622811\+coderabbitai\[bot\]@users\.noreply\.github\.com$`
  - author_name: `^coderabbitai\[bot\]$`
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*CodeRabbit[ \t]*<noreply@coderabbit\.ai>[ \t]*(?=$|\r?\n)`; `(?:^|\r?\n)Co-authored-by:[ \t]*coderabbitai\[bot\][ \t]*<136622811\+coderabbitai\[bot\]@users\.noreply\.github\.com>[ \t]*(?=$|\r?\n)`
- **`continue_dev`**
  - author_email: `@continue\.dev`
  - message: `Co-[Aa]uthored-[Bb]y:.*\bContinue\b`
- **`cosine_genie`** (from 2024-06-01)
  - author_email: `@cosine\.sh`
  - author_name: `cosine-genie\[bot\]`; `genie\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Genie.*<.*@cosine\.sh>`
- **`cursor`** (from 2023-03-01)
  - author_email: `^206951365\+cursor\[bot\]@users\.noreply\.github\.com$`; `cursoragent@cursor\.com`
  - author_name: `^cursor\[bot\]$`
  - committer_email: `cursoragent@cursor\.com`
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*Cursor Agent[ \t]*<cursoragent@cursor\.com>[ \t]*(?=$|\r?\n)`; `(?:^|\r?\n)Co-authored-by:[ \t]*Cursor[ \t]*<cursoragent@cursor\.com>[ \t]*(?=$|\r?\n)`; `Assisted-by:\s*Cursor\b`; `Co-authored-by:.*\bcursor\b`
- **`devin`** (from 2024-03-01)
  - author_email: `@devin\.ai`
  - author_name: `\bDevin\s+AI\b`; `devin-ai-integration\[bot\]`; `devin-ai\[bot\]`; `devin\[bot\]`
  - committer_email: `@devin\.ai`
- **`ellipsis`** (from 2023-12-05)
  - author_email: `^65095814\+ellipsis-dev\[bot\]@users\.noreply\.github\.com$`
  - author_name: `^ellipsis-dev\[bot\]$`
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*ellipsis-dev\[bot\][ \t]*<65095814\+ellipsis-dev\[bot\]@users\.noreply\.github\.com>[ \t]*(?=$|\r?\n)`
- **`factory_droid`** (from 2024-06-01)
  - author_email: `@factory\.ai`
  - author_name: `factory-droid\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Factory\s*Droid`
- **`fine_dev`**
  - author_email: `@fine\.dev`
  - author_name: `fine-dev\[bot\]`
- **`forgecode`** (from 2025-06-01)
  - author_email: `@forgecode\.dev`
  - author_name: `forgecode\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*ForgeCode`
- **`github_copilot`** (from 2022-06-01)
  - author_email: `copilot.*@users\.noreply\.github\.com`
  - author_name: `copilot-swe-agent\[bot\]`; `copilot\[bot\]`
  - committer_email: `copilot.*@users\.noreply\.github\.com`
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*Copilot[ \t]*<223556219\+Copilot@users\.noreply\.github\.com>[ \t]*(?=$|\r?\n)`; `(?:^|\r?\n)Co-authored-by:[ \t]*Copilot[ \t]*<copilot@github\.com>[ \t]*(?=$|\r?\n)`; `Assisted-by:\s*(?:GitHub\s*)?Copilot\b`; `Co-authored-by:.*\bcopilot\b`
- **`gitlab_duo`**
  - author_name: `gitlab-duo\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*GitLab Duo`
- **`google_antigravity`** (from 2026-05-19)
  - message: `Co-[Aa]uthored-[Bb]y:.*Antigravity.*<.*@google\.com>`; `Co-authored-by:.*\bantigravity\b`; `Generated (?:with|by) (?:Google )?Antigravity`
- **`google_gemini`** (from 2023-12-01)
  - author_email: `^176961590\+gemini-code-assist\[bot\]@users\.noreply\.github\.com$`
  - author_name: `gemini-code-assist\[bot\]`
  - message: `Assisted-by:\s*Gemini\b`; `Co-authored-by:.*\bgemini.cli\b`; `Co-authored-by:.*\bgemini\b`; `Generated (?:with|by) Gemini CLI`
- **`google_jules`** (from 2024-12-11)
  - author_email: `^161369871\+labs-code-app\[bot\]@users\.noreply\.github\.com$`
  - author_name: `^labs-code-app\[bot\]$`; `jules-agent`; `jules\[bot\]`
  - message: `Co-authored-by:.*\bjules\b`
- **`goose`** (from 2024-10-01)
  - author_name: `goose\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*\bGoose\b`; `Generated (?:with|by) Goose`
- **`grok_build`** (from 2026-05-25)
  - message: `Co-[Aa]uthored-[Bb]y:.*Grok.*<.*@x\.ai>`; `Generated (?:with|by) Grok Build`
- **`jetbrains_junie`** (from 2025-04-01)
  - author_email: `junie.*@jetbrains\.com`
  - author_name: `jetbrains-junie\[bot\]`; `junie-agent`; `junie-bot\[bot\]`
  - message: `Co-authored-by:.*\bjunie\b`
- **`kilo_code`**
  - author_email: `@kilo\.ai`
  - author_name: `kilo-code\[bot\]`; `kilocode\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Kilo\s*Code`; `Co-authored-by:.*\bkilo\b`; `Generated (?:with|by) Kilo\s*Code`
- **`kimi_code`**
  - message: `(?:^|\r?\n)Co-[Aa]uthored-[Bb]y:[ \t]*Kimi[^\r\n<]*<[^>]+@moonshot\.ai>[ \t]*(?=$|\r?\n)`; `Co-authored-by:.*\bkimi\b`; `Generated (?:with|by) Kimi Code`
- **`kiro`** (from 2025-07-01)
  - author_email: `@kiro\.dev`
  - author_name: `kiro\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Kiro.*<.*@kiro\.dev>`; `Co-authored-by:.*\bkiro\b`
- **`leap_new`**
  - author_email: `@leap\.new`
  - author_name: `leap\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Leap\.?new`
- **`letta_code`** (from 2025-01-01)
  - author_email: `@letta\.com`
  - author_name: `letta-code\[bot\]`; `letta\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Letta`
- **`lovable`** (from 2024-10-01)
  - author_email: `@lovable\.dev`
  - author_name: `gpt-engineer-app\[bot\]`; `lovable\[bot\]`
  - message: `Co-authored-by:.*\blovable\b`
- **`mentat`** (from 2024-01-01)
  - author_email: `@mentat\.ai`
  - author_name: `mentat\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Mentat`
- **`mistral_vibe`** (from 2025-12-09)
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*Mistral Vibe[ \t]*<vibe@mistral\.ai>[ \t]*(?=$|\r?\n)`; `(?:^|\r?\n)Generated by Mistral Vibe\.[ \t]*(?=$|\r?\n)`
- **`mux`** (from 2025-06-01)
  - author_email: `mux@coder\.com`
  - author_name: `mux\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*\bMux\b.*<.*@coder\.com>`
- **`openai_codex`** (from 2025-05-01)
  - author_email: `^242516109\+Codex@users\.noreply\.github\.com$`; `^chatgpt-codex-connector\[bot\]@users\.noreply\.github\.com$`; `codex@openai\.com`; `noreply@openai\.com`
  - author_name: `Codex04l`; `^openai-code-agent\[bot\]$`; `chatgpt-codex-connector\[bot\]`
  - committer_email: `^chatgpt-codex-connector\[bot\]@users\.noreply\.github\.com$`; `noreply@openai\.com`
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*Codex[ \t]*<chatgpt-codex-connector\[bot\]@users\.noreply\.github\.com>[ \t]*(?=$|\r?\n)`; `(?:^|\r?\n)Co-authored-by:[ \t]*openai-code-agent\[bot\][ \t]*<242516109\+Codex@users\.noreply\.github\.com>[ \t]*(?=$|\r?\n)`; `Assisted-by:\s*(?:OpenAI\s*)?Codex\b`; `Co-[Aa]uthored-[Bb]y:.*OpenAI.*<.*@openai\.com>`; `Co-[Aa]uthored-[Bb]y:\s*Codex\s*<.*@openai\.com>`; `Co-authored-by:.*\bcodex\b`; `Co-authored-by:.*\bopenai\b`
- **`opencode`** (from 2025-06-01)
  - author_email: `noreply@opencode\.ai`
  - message: `Co-[Aa]uthored-[Bb]y:\s*opencode\s*<.*@opencode\.ai>`; `Co-authored-by:.*\bopencode\b`; `Generated with opencode`
- **`openhands`** (from 2024-03-13)
  - author_name: `^openhands-ai\[bot\]$`; `opendevin\[bot\]`; `openhands-agent`; `openhands\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*\bOpenHands\b`; `Co-authored-by:.*\bopenhands\b`
- **`openwork`** (from 2026-06-06)
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*OpenWork[ \t]*<noreply@alibaba\.com>[ \t]*(?=$|\r?\n)`
- **`pi`** (from 2026-03-29)
  - message: `(?:^|\r?\n)Generated-By:[ \t]*pi[ \t]+v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?[ \t]*(?=$|\r?\n)`
- **`plandex`** (from 2024-03-01)
  - author_email: `@plandex\.ai`
  - author_name: `plandex\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Plandex`
- **`qoder`** (from 2025-08-21)
  - author_email: `^215938697\+qoderai\[bot\]@users\.noreply\.github\.com$`
  - author_name: `^qoderai\[bot\]$`
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*QoderAI[ \t]*<qoder_ai@qoder\.com>[ \t]*(?=$|\r?\n)`
- **`qodo`**
  - author_email: `@qodo\.ai`
  - author_name: `codiumai\[bot\]`; `qodo\[bot\]`
  - message: `Co-authored-by:.*\bqodo\b`
- **`qwen_code`** (from 2025-08-07)
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*Qwen Code[ \t]*<agents-noreply@craft\.do>[ \t]*(?=$|\r?\n)`; `(?:^|\r?\n)Co-authored-by:[ \t]*Qwen-Coder[ \t]*<qwen-coder@alibabacloud\.com>[ \t]*(?=$|\r?\n)`
- **`replit_agent`** (from 2024-09-01)
  - author_email: `agent@replit\.com`
  - author_name: `Replit Agent`; `replit-agent`
  - message: `Co-authored-by:.*\breplit\b`
- **`roo_code`** (from 2025-01-01)
  - author_name: `roo-code\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Roo\s*Code`; `Co-authored-by:.*\broo\b`; `Generated (?:with|by) Roo\s*Code`
- **`roomote`** (from 2026-07-10)
  - author_email: `^roomote@roomote\.dev$`
  - committer_email: `^roomote@roomote\.dev$`
- **`same_dev`**
  - author_email: `@same\.dev`
  - author_name: `same-dev\[bot\]`; `same\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Same\.dev`
- **`sourcegraph_cody`**
  - author_email: `cody(-agent)?@sourcegraph\.com`
  - author_name: `cody\[bot\]`
  - message: `Co-authored-by:.*(?:sourcegraph\s+cody|cody\s*\[bot\])`
- **`sweep`**
  - author_name: `sweepai\[bot\]`
- **`tabnine`**
  - author_email: `@tabnine\.com`
  - author_name: `tabnine\[bot\]`
  - message: `Co-authored-by:.*\btabnine\b`
- **`trae`** (from 2025-01-01)
  - author_name: `trae-agent`; `trae\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*\bTrae\b`; `Co-authored-by:.*\btrae\b`
- **`traycer`**
  - author_email: `@traycer\.ai`
  - author_name: `traycer-ai\[bot\]`; `traycer\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Traycer`
- **`unknown_ai`**
  - author_name: `.*\bassistant\b.*\[bot\]$`
  - message: `(?:^|\r?\n)Agent-Logs-Url:[ \t]*https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/sessions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[ \t]*(?=$|\r?\n)`; `Assisted-by:\s*\S+`; `\b(?:wrote|written)\s+(?:this\s+)?(?:with|by)\s+ChatGPT\b`; `\bAI[- ]assisted\b`; `\bAI[- ]generated\b`; `\bLLM[- ]generated\b`; `\bcopilot[- ]assisted\b`; `\bgenerated by AI\b`; `\bgenerated with GPT\b`
- **`v0`** (from 2024-06-01)
  - author_email: `\bv0@vercel\.com`
  - author_name: `\bv0\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*v0.*<.*@vercel\.com>`; `Generated (?:with|by) v0(?![.\d\w-])`
- **`warp`** (from 2025-01-01)
  - author_email: `^243557089\+oz-by-warp\[bot\]@users\.noreply\.github\.com$`; `^agent@warp\.dev$`; `^oz-agent@warp\.dev$`
  - author_name: `^oz-by-warp\[bot\]$`; `^warp\[bot\]$`
  - message: `(?:^|\r?\n)Co-authored-by:[ \t]*Oz(?: Agent)?[ \t]*<oz-agent@warp\.dev>[ \t]*(?=$|\r?\n)`; `Co-[Aa]uthored-[Bb]y:.*Warp.*<.*@warp\.dev>`
- **`windsurf`** (from 2024-11-01)
  - author_email: `windsurf@codeium\.com`
  - message: `Co-[Aa]uthored-[Bb]y:.*Windsurf.*<.*@codeium\.com>`; `Co-authored-by:.*\bwindsurf\b`
- **`zencoder`**
  - author_email: `@zencoder\.ai`
  - author_name: `zencoder\[bot\]`
  - message: `Co-[Aa]uthored-[Bb]y:.*Zencoder`; `Co-authored-by:.*\bzencoder\b`

## Pull-request bodies

A line such as `Generated with <Tool>`, `Built with <Tool>`, `Created by <Tool>` or
`Made with <Tool>` in a PR body discloses that PR's assistance; bind it to the causal
change before using it. Tools covered: `abacus_ai`, `aider`, `amazon_q`, `amp`, `augment_code`, `blackbox_ai`, `bolt_new`, `claude_code`, `cline`, `cosine_genie`, `cursor`, `devin`, `factory_droid`, `forgecode`, `github_copilot`, `google_gemini`, `goose`, `grok_build`, `jetbrains_junie`, `kiro`, `leap_new`, `letta_code`, `lovable`, `mentat`, `mux`, `openai_codex`, `openhands`, `plandex`, `qwen_code`, `replit_agent`, `roo_code`, `same_dev`, `sweep`, `trae`, `traycer`, `v0`, `warp`, `windsurf`.

## Repository configuration files

These show that a repository uses an AI tool. They never attribute a specific change:
`CLAUDE.md`, `.claude`, `.cursor`, `.cursorignore`, `.cursorrules`, `.aider`, `.aider.conf.yml`, `.github/copilot-instructions.md`, `.windsurfrules`, `codex.md`, `.codex`, `AGENTS.md`, `.gemini`, `.kimi-code`, `.qwen`, `.pi`, `.coderabbit.yaml`, `ellipsis.yaml`.

## Earliest dates

| Tool | Earliest plausible marker date |
| --- | --- |
| `abacus_ai` | 2025-01-01 |
| `aider` | 2023-05-01 |
| `amazon_q` | 2023-11-01 |
| `amp` | 2025-05-01 |
| `augment_code` | 2025-04-01 |
| `blackbox_ai` | 2023-01-01 |
| `bolt_new` | 2024-06-01 |
| `claude_code` | 2025-01-01 |
| `cline` | 2024-06-01 |
| `coderabbit` | 2023-08-22 |
| `cosine_genie` | 2024-06-01 |
| `cursor` | 2023-03-01 |
| `devin` | 2024-03-01 |
| `ellipsis` | 2023-12-05 |
| `factory_droid` | 2024-06-01 |
| `forgecode` | 2025-06-01 |
| `github_copilot` | 2022-06-01 |
| `google_antigravity` | 2026-05-19 |
| `google_gemini` | 2023-12-01 |
| `google_jules` | 2024-12-11 |
| `goose` | 2024-10-01 |
| `grok_build` | 2026-05-25 |
| `jetbrains_junie` | 2025-04-01 |
| `kiro` | 2025-07-01 |
| `letta_code` | 2025-01-01 |
| `lovable` | 2024-10-01 |
| `mentat` | 2024-01-01 |
| `mistral_vibe` | 2025-12-09 |
| `mux` | 2025-06-01 |
| `openai_codex` | 2025-05-01 |
| `opencode` | 2025-06-01 |
| `openhands` | 2024-03-13 |
| `openwork` | 2026-06-06 |
| `pi` | 2026-03-29 |
| `plandex` | 2024-03-01 |
| `qoder` | 2025-08-21 |
| `qwen_code` | 2025-08-07 |
| `replit_agent` | 2024-09-01 |
| `roo_code` | 2025-01-01 |
| `roomote` | 2026-07-10 |
| `trae` | 2025-01-01 |
| `v0` | 2024-06-01 |
| `warp` | 2025-01-01 |
| `windsurf` | 2024-11-01 |
