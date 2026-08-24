# GHSA-FWJX-9P69-H25H

repo: JanDeDobbeleer/oh-my-posh

summary: Oh My Posh: Terminal escape sequence injection via unsanitized prompt segment data

aliases: ['CVE-2026-73506']

severity: MODERATE

evidence: file_history blamed_lines=0 files=['src/terminal/writer.go', 'src/terminal/writer_test.go']

intro: 63e124333f859d586d2ac575eb8628b0633ab9f1

intro_subject: feat(terminal): make progress sequence terminals configurable

intro_date: 2026-05-21T05:45:14+00:00

fix: edcf3c88f3fb582e84358b385c49d33d04c04224

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
Oh My Posh renders dynamic, potentially attacker-controlled strings (the current directory name, Git commit metadata, environment variable values, command output) into the prompt without neutralizing raw terminal control characters. An attacker who controls one of these values can inject ANSI/OSC escape sequences that the victim's terminal executes on every prompt render. (This is separate from the path-segment command-execution report; it has a different root cause and fix.)

### Details
`src/terminal/writer.go`, `write(s rune)`: the literal characters of rendered segment content are emitted to the output buffer, and the only neutralization is a lookup in `formats.EscapeSequences`, which per shell contains only the shell's prompt-length markers (`\` for bash, `%` for zsh, nothing for fish/pwsh/cmd/nu). Raw C0/C1 control bytes (ESC `0x1b`, BEL `0x07`, CSI, OSC) are written verbatim.

Oh My Posh's own styling is emitted through separate paths (`writeEscapedAnsiString`, `writeColorise`, `builder.WriteString(formats.Hyperlink...)`), so any control rune reaching `write(s rune)` originates from rendered data. `trimAnsi` is already applied to the console title (`FormatTitle`) but not to the prompt body.

### Attacker-controlled sources (both verified)
1. Current directory name (default config, Linux/macOS). Directory names may contain any byte except `/` and NUL, including `0x1b`. The path segment renders the working directory in every theme.
2. Git commit subject / author / upstream URL (cross-platform, including Windows). `Git.Commit()` runs `git log -1 --pretty=format:...su:%s...` and exposes `.Commit.Subject`, `.Commit.Author.Name`/`.Email` and `.RawUpstreamURL`; Git imposes no restriction on these, so they can carry raw escape sequences.

### PoC
Git commit-subject vector (config: a single git segment with template `{{ .Commit.Subject }}`):

```
printf 'feat: \033]0;HACKED\007\033]52;c;ZWNobyBQV05FRA==\007 update' > msg.txt
git commit --allow-empty -F msg.txt
oh-my-posh print primary --config poc.omp.json --shell fish | xxd
```

Output (excerpt) shows the attacker's OSC 0 (set title) and OSC 52 (clipboard write) passed through unmodified, wrapped only in Oh My Posh's colors:

```
...255m feat: 1b5d 303b 4841 434b 4544 07 1b5d 3532 3b63 3b5a 574e ... 07 ...
              ESC ] 0 ; H A C K E D  BEL  ESC ] 5 2 ; c ; <base64>  BEL
```

The directory-name vector reproduces identically via the path segment.

### Impact
The terminal interprets the inje

REFS:
- WEB https://github.com/JanDeDobbeleer/oh-my-posh/security/advisories/GHSA-fwjx-9p69-h25h
- WEB https://github.com/JanDeDobbeleer/oh-my-posh/commit/edcf3c88f3fb582e84358b385c49d33d04c04224
- PACKAGE https://github.com/JanDeDobbeleer/oh-my-posh
- WEB https://github.com/JanDeDobbeleer/oh-my-posh/releases/tag/v29.35.1
- WEB https://github.com/JanDeDobbeleer/oh-my-posh/releases/tag/v29.36.0

INTRO_LOG:
63e124333f859d586d2ac575eb8628b0633ab9f1
copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
2026-07-11T14:55:10+02:00
feat(terminal): make progress sequence terminals configurable

resolves #7379

Entire-Checkpoint: 4551f81cf553



INTRO_STAT:
 src/cli/font.go                        |  4 ++
 src/cli/upgrade.go                     |  4 +-
 src/config/config.go                   |  1 +
 src/terminal/features.go               | 21 ++++++++
 src/terminal/writer.go                 | 16 +++++--
 src/terminal/writer_test.go            | 87 ++++++++++++++++++++++++++++++++++
 themes/schema.json                     | 15 ++++++
 website/docs/configuration/general.mdx | 22 ++++++++-
 8 files changed, 165 insertions(+), 5 deletions(-)


INTRO_DIFF_OVERLAP:
diff --git a/src/terminal/writer.go b/src/terminal/writer.go
index 77c1f634..f0eef9c6 100644
--- a/src/terminal/writer.go
+++ b/src/terminal/writer.go
@@ -3,6 +3,7 @@ package terminal
 import (
 	"fmt"
 	"os"
+	"slices"
 	"strings"
 	"unicode/utf8"
 
@@ -63,6 +64,8 @@ var (
 	Shell   string
 	Program string
 
+	progressTerminals []string
+
 	formats *shell.Formats
 
 	// escapePrefix/escapeSuffix are formats.Escape ("...%s...") split around its
@@ -172,6 +175,7 @@ func Init(sh string) {
 
 	color.TrueColor = Program != AppleTerminal
 
+	progressTerminals = []string{WindowsTerminal}
 	formats = shell.GetFormats(Shell)
 
 	escapePrefix, escapeSuffix = "", ""
@@ -319,8 +323,14 @@ func LineBreak() string {
 	return cr + lf
 }
 
+func progressSupported() bool {
+	return slices.ContainsFunc(progressTerminals, func(program string) bool {
+		return strings.EqualFold(program, Program)
+	})
+}
+
 func StartProgress() string {
-	if Program != WindowsTerminal {
+	if !progressSupported() {
 		return ""
 	}
 
@@ -328,7 +338,7 @@ func StartProgress() string {
 }
 
 func SetProgress(percentage int) string {
-	if Program != WindowsTerminal {
+	if !progressSupported() {
 		return ""
 	}
 
@@ -336,7 +346,7 @@ func SetProgress(percentage int) string {
 }
 
 func StopProgress() string {
-	if Program != WindowsTerminal {
+	if !progressSupported() {
 		return ""
 	}
 
diff --git a/src/terminal/writer_test.go b/src/terminal/writer_test.go
index 0e382392..7eda1e1c 100644
--- a/src/terminal/writer_test.go
+++ b/src/terminal/writer_test.go
@@ -294,3 +294,90 @@ func TestWriteLength(t *testing.T) {
 		assert.Equal(t, tc.Expected, got, tc.Case)
 	}
 }
+
+func TestProgressFunctions(t *testing.T) {
+	originalProgram := Program
+	originalProgressTerminals := progressTerminals
+
+	t.Cleanup(func() {
+		Program = originalProgram
+		progressTerminals = originalProgressTerminals
+	})
+
+	cases := []struct {
+		Features       *Features
+		Case           string
+		Program        string
+		ExpectProgress bool
+	}{
+		{
+			Case:           "Windows Terminal default",
+			Program:        WindowsTerminal,
+			ExpectProgress: true,
+		},
+		{
+			Case:    "Unknown terminal default",
+			Program: Unknown,
+		},
+		{
+			Case:           "Ghostty configured",
+			Program:        "ghostty",
+			Features:       &Features{Progress: []string{"ghostty", WindowsTerminal}},
+			ExpectProgress: true,
+		},
+		{
+			Case:           "case insensitive match",
+			Program:        "ghostty",
+			Features:       &Features{Progress: []string{"Ghostty"}},
+			ExpectProgress: true,
+		},
+		{
+			Case:           "Windows Terminal with custom list",
+			Program:        WindowsTerminal,
+			Features:       &Features{Progress: []string{"ghostty", WindowsTerminal}},
+			ExpectProgress: true,
+		},
+		{
+			Case:     "Unknown terminal with custom list",
+			Program:  Unknown,
+			Features: &Features{Progress: []string{"ghostty", WindowsTerminal}},
+		},
+		{
+			Case:     "Custom terminal not in list",
+			Program:  "alacritty",
+			Features: &Features{Progress: []string{"ghostty"}},
+		},
+		{
+			Case:           "empty features keep the default",
+			Program:        WindowsTerminal,
+			Features:       &Features{},
+			ExpectProgress: true,
+		},
+		{
+			Case:           "empty list keeps the default",
+			Program:        WindowsTerminal,
+			Features:       &Features{Progress: []string{}},
+			ExpectProgress: true,
+		},
+	}
+
+	for _, tc := range cases {
+		t.Run(tc.Case, func(t *testing.T) {
+			Program = tc.Program
+			progressTerminals = []string{WindowsTerminal}
+
+			tc.Features.Apply()
+
+			if tc.ExpectProgress {
+				assert.NotEmpty(t, StartProgress(), tc.Case)
+				assert.NotEmpty(t, SetProgress(50), tc.Case)
+				assert.NotEmpty(t, StopProgress(), tc.Case)
+				return
+			}
+
+			assert.Empty(t, StartProgress(), tc.Case)
+			assert.Empty(t, SetProgress(50), tc.Case)
+			assert.Empty(t, StopProgress(), tc.Case)
+		})
+	}
+}


FIX_LOG:
edcf3c88f3fb582e84358b385c49d33d04c04224
Jan De Dobbeleer <jan.de.dobbeleer@gmail.com>
2026-07-23T12:44:26+02:00
fix(terminal): strip control runes from rendered segment content

Segment text (directory names, git commit metadata, environment
variables, command output) can be attacker-controlled and reached the
terminal unfiltered through write(s rune), the only sink Oh My Posh's
own styling never uses. Raw ESC/BEL/CSI/OSC bytes let an attacker
inject terminal escape sequences (title spoofing, OSC 52 clipboard
writes) via a malicious directory name or git commit subject.

GHSA-fwjx-9p69-h25h

Entire-Checkpoint: 65f209a5fba9



FIX_STAT:
 src/terminal/writer.go                | 24 ++++++++++++++++++++++++
 src/terminal/writer_hyperlink_test.go |  5 +++++
 src/terminal/writer_test.go           | 12 ++++++++++++
 3 files changed, 41 insertions(+)


FIX_DIFF_OVERLAP:
diff --git a/src/terminal/writer.go b/src/terminal/writer.go
index 5383778e..f72e3c81 100644
--- a/src/terminal/writer.go
+++ b/src/terminal/writer.go
@@ -674,6 +674,15 @@ func write(s rune) {
 		return
 	}
 
+	// segment content (directory names, git metadata, environment variables,
+	// command output) is potentially attacker-controlled and never passes through
+	// this function when it's Oh My Posh's own styling; drop C0/C1 control runes
+	// (ESC, BEL, CSI, OSC, ...) so they can't be interpreted as escape sequences
+	// by the terminal, including inside a hyperlink target.
+	if isControlRune(s) {
+		return
+	}
+
 	if isHyperlink {
 		builder.WriteRune(s)
 		return
@@ -694,6 +703,21 @@ func write(s rune) {
 	builder.WriteRune(s)
 }
 
+// isControlRune reports whether s is a C0 (0x00-0x1F), DEL (0x7F), or C1
+// (0x80-0x9F) control character. These are the bytes a terminal can interpret
+// as the start of an escape sequence (ESC, BEL, CSI, OSC, ...); no legitimate
+// rendered segment content needs them. '\n' is exempt: Oh My Posh itself
+// prepends a literal newline ahead of the transient prompt (see
+// Engine.getNewline), and unlike ESC/BEL/CSI/OSC a bare LF can't be
+// interpreted as the start of an escape sequence.
+func isControlRune(s rune) bool {
+	if s == '\n' {
+		return false
+	}
+
+	return s <= 0x1f || (s >= 0x7f && s <= 0x9f)
+}
+
 // writeVisibleRune stamps the active gradient color(s) for the current cell
 // before writing s, then advances cellIndex by s's rune width. It is only
 // called from writeBodyGradient, so isInvisible/isHyperlink runes are
diff --git a/src/terminal/writer_test.go b/src/terminal/writer_test.go
index 7eda1e1c..926769b8 100644
--- a/src/terminal/writer_test.go
+++ b/src/terminal/writer_test.go
@@ -219,6 +219,18 @@ func TestWriteANSIColors(t *testing.T) {
 			Expected: "\x1b[33mhello \x1b[48;2;130;170;255m\x1b[38;2;1;22;39mnew\x1b[49m\x1b[33m world\x1b[0m",
 			Colors:   &color.Set{Foreground: "yellow", Background: "transparent"},
 		},
+		{
+			Case:     "OSC injection stripped from segment content",
+			Input:    "before\x1b]0;HACKED\x07after",
+			Expected: "\x1b[47m\x1b[30mbefore]0;HACKEDafter\x1b[0m",
+			Colors:   &color.Set{Foreground: "black", Background: "white"},
+		},
+		{
+			Case:     "CSI and C1 control runes stripped from segment content",
+			Input:    "before\x1b[31mred\u009bafter",
+			Expected: "\x1b[47m\x1b[30mbefore[31mredafter\x1b[0m",
+			Colors:   &color.Set{Foreground: "black", Background: "white"},
+		},
 	}
 
 	for _, tc := range cases {


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []