#!/usr/bin/env python3
import hashlib, json, os, subprocess, sys
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale3-grok46-high")
FETCH = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")
DIFFDIR = OWN / "diffs"
DIFFDIR.mkdir(exist_ok=True)

need = [
    ("excalidraw/excalidraw", "bfd4af23673df9904a37b9f194c1823cd6e831b7"),
    ("cilium/cilium", "2c59ba7dfaa5065e3b71814b97be7d217e07cda3"),
    ("coredns/coredns", "12d9457e71461c6864eb4be5ed3e94de32c9aa9c"),
    ("traefik/traefik", "8ac8473554d758459ae4e99dab4be7dcbb167a07"),
    ("befeleme/pyp2spec", "04d9f499d38c7dfb981a55d6e1c0d3ec1094945f"),
    ("pyload/pyload", "23c48a5c3cddc37d16b9265d0d44e554eaea3918"),
    ("Jovancoding/Network-AI", "27b549f4d3a16c2a54a382d58b8ad01530f20b5d"),
    ("felippe-regazio/ssrfcheck", "43c9680baf6a712ff93e584c32acfdedd02bec7f"),
    ("YAFNET/YAFNET", "d2b474be09ac6e1a917668be379e07539e96f2a8"),
    ("tauri-apps/tauri", "001c8fe3d288802de9a8c29cfd2f46f9220d97c5"),
    ("HackingRepo/dssrf-js", "817c900ac2e080b8580a6688647c486bdddfc2f5"),
    ("sparklemotion/nokogiri", "3b4896953188a76a0da728d64027164c52be48ef"),
    ("brantburnett/Snappier", "96b68fd6f46c5693c5670fda97334ab50d752ced"),
    ("nearform/fast-jwt", "2181bf1e218088a8b174b1f32902ebcb1ae5e335"),
    ("shellhub-io/shellhub", "43bed23b24370ec787e838403cd6ae5e5e9f1603"),
]

def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout

results = []
for repo, sha in need:
    slug = repo.replace("/", "__")
    d = FETCH / slug
    rec = {"repo": repo, "sha": sha, "dir": str(d)}
    if not d.exists():
        d.mkdir(parents=True)
        code, out = run(["timeout", "30s", "git", "init", "--bare", str(d)])
        rec["init"] = {"code": code, "out": out[-400:]}
        code, out = run(["timeout", "30s", "git", "-C", str(d), "remote", "add", "origin", f"https://github.com/{repo}.git"])
        rec["remote"] = {"code": code, "out": out[-400:]}
    # check object
    code, _ = run(["timeout", "30s", "git", "-C", str(d), "cat-file", "-e", sha + "^{commit}"])
    rec["had"] = code == 0
    if code != 0:
        code, out = run(["timeout", "30s", "git", "-C", str(d), "fetch", "--filter=blob:none", "--depth=1", "origin", sha])
        rec["fetch"] = {"code": code, "out": (out or "")[-800:]}
        if code != 0:
            code2, out2 = run(["timeout", "30s", "git", "-C", str(d), "fetch", "--filter=blob:none", "--deepen=50", "origin", sha])
            rec["fetch2"] = {"code": code2, "out": (out2 or "")[-800:]}
            code = code2
    code, _ = run(["timeout", "30s", "git", "-C", str(d), "cat-file", "-e", sha + "^{commit}"])
    rec["have"] = code == 0
    if rec["have"]:
        code, meta = run(["timeout", "30s", "git", "-C", str(d), "show", "--format=fuller", "--stat", "--no-ext-diff", "--no-color", sha])
        code2, diff = run(["timeout", "30s", "git", "-C", str(d), "show", "--format=", "--no-ext-diff", "--no-color", sha])
        (DIFFDIR / f"{sha}.stat.txt").write_text(meta or "")
        (DIFFDIR / f"{sha}.diff").write_text(diff or "")
        rec["stat_bytes"] = len(meta or "")
        rec["diff_bytes"] = len(diff or "")
        rec["diff_sha256"] = hashlib.sha256((diff or "").encode()).hexdigest()
        rec["subject"] = (meta or "").splitlines()[4] if meta else ""
    results.append(rec)
    print(repo, sha[:12], "have="+str(rec.get("have")), "had="+str(rec.get("had")), "diff="+str(rec.get("diff_bytes")))

(OWN / "fetch-status.json").write_text(json.dumps(results, indent=2))
print("wrote fetch-status.json")
