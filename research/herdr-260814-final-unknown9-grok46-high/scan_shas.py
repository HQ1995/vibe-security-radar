#!/usr/bin/env python3
import os, subprocess, json
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-final-unknown9-grok46-high")

CASES = {
  35: {"repo":"coolify","shas":["473c32270d72252ee6753afc35c3ea4360d169e0","bc972505e381b12ad999e5066d3fe5770c5e1bd4","b1de75a7c67ce6aee977bd788b41e61837dbe0b9","733c20fc9d4af7c109c711315e63bbd21623e62f","99043600ee881fd8581185e7590604d9882382cd"]},
  51: {"repo":"openclaw","shas":["f05553413db29ebcf5d8c75c8a6154a9e9987690","daf13dbb0616115bf0aa946f46c3ba2afb93d283","a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf","78ec0a1edfcd113840e0f0a5a510031d3bcc16ee"]},
  53: {"repo":"wacrm","shas":["b7b362ae427ccf4b33b8e8cd147f16410f3ce800","7d1ddbfdb8296058ab787f7c57b8943c0214d14d","23838a995955","66dd4ef"]},
  56: {"repo":"taylored","shas":["c139c021f68a09d22c2af88641b61c00f67f2af4","57b7634391959dbbdb39b387ac4dc68157cd58a1","5e5a80b5"]},
  84: {"repo":"taylored","shas":["57b7634391959dbbdb39b387ac4dc68157cd58a1","fdf67a6fba0deae30912905a79fb5a9e83751a79"]},
  116: {"repo":"coolify","shas":["e1fe58639756cf7b232458eddd6978e4ed0031f5","98569e4edbfc316877c9e0d27ea89fab3c49e3bd","e1d4b4682efc898ba5aa3751b2da2072f89c7e24"]},
  129: {"repo":"argo","shas":["251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34","2727f3f701677d467dfb5e053c57237cbc752c3c","277e9cef0ad16d7eaaab253573d0695951a65dbd","358cc3968c8f06f1be0967e41df191088db0b662"]},
  153: {"repo":"misp","shas":["bc182d55dde5686a36ca2eb88fe6c2adabb9fad9","025f711506850aadb69cde1b57e5e5d57628c87f"]},
  154: {"repo":"omnifaces","shas":["aa42da361821ddfbb85b126564e71587347d2786","a52b92461cf39d983f51ce8724fe7e6b944073e4"]},
}

CLONES = [
"/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify",
"/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw",
"/home/hanqing/.cache/cve-analyzer/repos/tailot_taylored",
"/home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows",
"/home/hanqing/.cache/cve-analyzer/repos/misp_misp",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/coolify",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/openclaw",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/taylored",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/wacrm",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/argo-workflows",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/coolify",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/misp",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/omnifaces",
"/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw",
"/home/hanqing/.cache/ghsa200-worker-clones/redbase/clones/coolify",
"/home/hanqing/.cache/ghsa200-worker-clones/redbase/clones/MISP",
"/home/hanqing/.cache/ghsa200-worker-clones/redbase/clones/openclaw",
"/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/coolify",
"/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/openclaw",
"/home/hanqing/.cache/ghsa200-worker-clones/current-delta/repos/argoproj__argo-workflows",
"/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/omnifaces__omnifaces",
"/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/openclaw__openclaw",
"/home/hanqing/.cache/ghsa200-worker-clones/redbase-odd/clones/coolify",
"/home/hanqing/.cache/ghsa200-worker-clones/redbase-odd/clones/misp",
"/home/hanqing/.cache/ghsa200-worker-clones/redbase-odd/clones/openclaw",
]

def cat_file(repo, sha):
    r = subprocess.run(["git","-C",repo,"cat-file","-t",sha], capture_output=True, text=True)
    return r.returncode==0, (r.stdout or r.stderr).strip()

out = []
for clone in CLONES:
    if not os.path.isdir(clone):
        out.append({"clone":clone,"exists":False})
        continue
    hits = {}
    for ord_, spec in CASES.items():
        found = []
        for sha in spec["shas"]:
            ok, kind = cat_file(clone, sha)
            if ok:
                found.append({"sha":sha,"kind":kind})
        if found:
            hits[str(ord_)] = found
    out.append({"clone":clone,"exists":True,"hits":hits})

(OWN/"sha_hits.json").write_text(json.dumps(out, indent=2))
print("wrote", OWN/"sha_hits.json")
print("clones_existing", sum(1 for x in out if x.get("exists")))
print("clones_with_hits", sum(1 for x in out if x.get("hits")))
