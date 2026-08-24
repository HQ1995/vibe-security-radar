#!/usr/bin/env python3
"""Independent git probes. Writes notes/*.txt. Does not use sibling conclusions."""
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones/incomplete-rem-redteam")
CLONES = ROOT / "clones"
NOTES = ROOT / "notes"
NOTES.mkdir(parents=True, exist_ok=True)
GIT = [
    "git",
    "--no-optional-locks",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
]


def git(repo: str, args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        GIT + ["-C", str(CLONES / repo)] + args,
        text=True,
        capture_output=True,
        check=check,
    )


def dump(name: str, text: str) -> None:
    (NOTES / name).write_text(text)
    print("wrote", name, "bytes", len(text))


def section(title: str, body: str) -> str:
    return f"===== {title} =====\n{body.rstrip()}\n\n"


def ancestor(repo: str, commit: str, tag: str) -> str:
    r = git(repo, ["merge-base", "--is-ancestor", commit, tag])
    return f"is-ancestor {commit[:12]} {tag} rc={r.returncode}"


def show_msg(repo: str, sha: str) -> str:
    r = git(repo, ["log", "-1", "--format=%H%n%an <%ae>%n%cn <%ce>%n%s%n%n%b", sha])
    return r.stdout + r.stderr


def parents(repo: str, sha: str) -> list[str]:
    r = git(repo, ["rev-parse", f"{sha}^@"])
    return [x for x in r.stdout.split() if x]


# ---------- 127 / 128 PraisonAI ----------
prai = []
cand = "3cd664bf7b7db5f774c1e7e3123a1a24c68ba700"
fix = "179cab02dbec0c1e9b601507a65908e079876004"
prai.append(section("cand msg", show_msg("praisonai", cand)))
prai.append(section("fix msg", show_msg("praisonai", fix)))
prai.append(section("cand parents", "\n".join(parents("praisonai", cand))))
spider = "src/praisonai-agents/praisonaiagents/tools/spider_tools.py"
pytools = "src/praisonai-agents/praisonaiagents/tools/python_tools.py"
for label, spec in [
    ("parent spider exists", ["cat-file", "-e", f"{cand}^:{spider}"]),
    ("cand spider exists", ["cat-file", "-e", f"{cand}:{spider}"]),
    ("parent python exists", ["cat-file", "-e", f"{cand}^:{pytools}"]),
]:
    r = git("praisonai", spec)
    prai.append(section(label, f"rc={r.returncode} {r.stderr}"))
prai.append(section("parent spider grep", git("praisonai", ["grep", "-n", "-E", "_validate_url|localhost|0x7f|ipaddress", f"{cand}^", "--", spider]).stdout + git("praisonai", ["grep", "-n", "-E", "_validate_url|localhost|0x7f|ipaddress", f"{cand}^", "--", spider]).stderr))
prai.append(section("cand spider grep", git("praisonai", ["grep", "-n", "-E", "_validate_url|localhost|0x7f|ipaddress|blocked", cand, "--", spider]).stdout))
prai.append(section("v4.6.39 spider grep", git("praisonai", ["grep", "-n", "-E", "_validate_url|localhost|0x7f|ip_address|int\\(|hex", "v4.6.39", "--", spider]).stdout))
prai.append(section("v4.6.40 spider grep", git("praisonai", ["grep", "-n", "-E", "_validate_url|localhost|0x7f|ip_address|int\\(|from_int", "v4.6.40", "--", spider]).stdout))
prai.append(section("parent python grep", git("praisonai", ["grep", "-n", "-E", "safe_builtins|execute_code|__self__|__builtins__", f"{cand}^", "--", pytools]).stdout + git("praisonai", ["grep", "-n", "-E", "safe_builtins|execute_code|__self__", f"{cand}^", "--", pytools]).stderr))
prai.append(section("cand python grep", git("praisonai", ["grep", "-n", "-E", "safe_builtins|execute_code|__self__|__builtins__", cand, "--", pytools]).stdout))
prai.append(section("v4.6.39 python grep", git("praisonai", ["grep", "-n", "-E", "safe_builtins|__self__", "v4.6.39", "--", pytools]).stdout))
prai.append(section("v4.6.40 python grep", git("praisonai", ["grep", "-n", "-E", "safe_builtins|__self__", "v4.6.40", "--", pytools]).stdout))
prai.append(section("ancestry", "\n".join([
    ancestor("praisonai", cand, "v4.6.39"),
    ancestor("praisonai", fix, "v4.6.39"),
    ancestor("praisonai", cand, "v4.6.40"),
    ancestor("praisonai", fix, "v4.6.40"),
])))
prai.append(section("cand spider hunk", git("praisonai", ["diff", f"{cand}^", cand, "--", spider]).stdout[:12000]))
prai.append(section("cand python hunk", git("praisonai", ["diff", f"{cand}^", cand, "--", pytools]).stdout[:12000]))
prai.append(section("fix spider hunk", git("praisonai", ["diff", f"{fix}^", fix, "--", spider]).stdout[:8000]))
prai.append(section("fix python hunk", git("praisonai", ["diff", f"{fix}^", fix, "--", pytools]).stdout[:8000]))
dump("ord127-128.git.txt", "".join(prai))

# ---------- 130 fission ----------
fis = []
member = "2db76f65dbfe4f657b4a4efb506ed63b24623e92"
carrier = "e484df8460bb4e8026e24210120602aa7f181f64"
ffix = "2569b42bfadbcb7d78b55a00a60f77937e522699"
for sha, lab in [(member, "member"), (carrier, "carrier"), (ffix, "fix")]:
    fis.append(section(f"{lab} msg", show_msg("fission", sha)))
    fis.append(section(f"{lab} parents", "\n".join(parents("fission", sha))))
# find files
for sha in [member, carrier, ffix]:
    fis.append(section(f"files {sha[:12]}", git("fission", ["diff-tree", "--no-commit-id", "--name-only", "-r", sha]).stdout[:4000]))
fis.append(section("ancestry", "\n".join([
    ancestor("fission", member, "v1.24.0"),
    ancestor("fission", carrier, "v1.24.0"),
    ancestor("fission", ffix, "v1.24.0"),
    ancestor("fission", member, "v1.25.0"),
    ancestor("fission", carrier, "v1.25.0"),
    ancestor("fission", ffix, "v1.25.0"),
    ancestor("fission", member, "v1.23.0"),
    ancestor("fission", carrier, "v1.23.0"),
])))
# grep capabilities
for spec in [f"{carrier}^", carrier, "v1.23.0", "v1.24.0", "v1.25.0", ffix]:
    r = git("fission", ["grep", "-n", "-E", "dangerousCapabilities|SYS_TIME|SYS_ADMIN|ValidateContainerSafety", spec, "--", "*.go"])
    fis.append(section(f"grep {spec[:20]}", (r.stdout + r.stderr)[:6000]))
dump("ord130.git.txt", "".join(fis))

# ---------- 131 mcp-registry ----------
mcp = []
mm = "257eb178cfb05335c68f793a5b1fba16c32e3769"
cc = "1201cbd82b2cf6d4b56edfc05c763059a12f9fdb"
mfix = "f5f40bd98084466eaf18fe48ea62a0d534caa774"
for sha, lab in [(mm, "member"), (cc, "carrier"), (mfix, "fix")]:
    mcp.append(section(f"{lab} msg", show_msg("mcp-registry", sha)))
    mcp.append(section(f"{lab} files", git("mcp-registry", ["diff-tree", "--no-commit-id", "--name-only", "-r", sha]).stdout[:3000]))
mcp.append(section("ancestry", "\n".join([
    ancestor("mcp-registry", mm, "v1.7.5"),
    ancestor("mcp-registry", cc, "v1.7.5"),
    ancestor("mcp-registry", mfix, "v1.7.5"),
    ancestor("mcp-registry", mfix, "v1.7.6"),
    ancestor("mcp-registry", mfix, "v1.7.7"),
    ancestor("mcp-registry", mm, "v1.7.4") if git("mcp-registry", ["rev-parse", "v1.7.4"]).returncode == 0 else "no v1.7.4",
])))
# identify file
mcp.append(section("member files detailed", git("mcp-registry", ["show", "--stat", mm]).stdout[:4000]))
r = git("mcp-registry", ["grep", "-l", "isBlockedIP", mm])
mcp.append(section("isBlockedIP files member", r.stdout + r.stderr))
r2 = git("mcp-registry", ["grep", "-l", "isBlockedIP", f"{mm}^"])
mcp.append(section("isBlockedIP files parent", r2.stdout + f"rc={r2.returncode}\n" + r2.stderr))
for spec in [f"{mm}^", mm, cc, "v1.7.5", "v1.7.6", "v1.7.7", mfix]:
    r = git("mcp-registry", ["grep", "-n", "-E", "2002::|64:ff9b|fec0|isBlockedIP|RFC1918|safeDial", spec])
    mcp.append(section(f"grep {spec[:20]}", (r.stdout + r.stderr)[:5000]))
dump("ord131.git.txt", "".join(mcp))

# ---------- 134 clearancekit ----------
ck = []
ca = "a3d1733d2691a0d40209c48b01bf9291bf645207"
cfix = "6181c4a22eccbeca973c77f4bd023eb795c13786"
ck.append(section("cand msg", show_msg("clearancekit", ca)))
ck.append(section("fix msg", show_msg("clearancekit", cfix)))
ck.append(section("cand files", git("clearancekit", ["diff-tree", "--no-commit-id", "--name-only", "-r", ca]).stdout))
ck.append(section("fix files", git("clearancekit", ["diff-tree", "--no-commit-id", "--name-only", "-r", cfix]).stdout))
# tags
ck.append(section("tags", git("clearancekit", ["tag", "-l"]).stdout))
for spec in [f"{ca}^", ca, f"{cfix}", "v4.2.3-d488a1e", "v4.2.4-6181c4a"]:
    r = git("clearancekit", ["grep", "-n", "-E", "AUTH_CLONE|AUTH_EXCHANGEDATA|AUTH_OPEN|AUTH_RENAME|ES_EVENT_TYPE", spec])
    ck.append(section(f"grep {spec[:24]}", (r.stdout + r.stderr)[:6000]))
ck.append(section("ancestry", "\n".join([
    ancestor("clearancekit", ca, "v4.2.3-d488a1e") if git("clearancekit", ["rev-parse", "v4.2.3-d488a1e"]).returncode == 0 else "missing tag v4.2.3-d488a1e",
    ancestor("clearancekit", cfix, "v4.2.3-d488a1e") if git("clearancekit", ["rev-parse", "v4.2.3-d488a1e"]).returncode == 0 else "missing tag v4.2.3-d488a1e",
    ancestor("clearancekit", ca, "v4.2.4-6181c4a") if git("clearancekit", ["rev-parse", "v4.2.4-6181c4a"]).returncode == 0 else "missing tag v4.2.4-6181c4a",
    ancestor("clearancekit", cfix, "v4.2.4-6181c4a") if git("clearancekit", ["rev-parse", "v4.2.4-6181c4a"]).returncode == 0 else "missing tag v4.2.4-6181c4a",
])))
ck.append(section("cand diff AUTH", git("clearancekit", ["diff", f"{ca}^", ca]).stdout[:15000]))
ck.append(section("fix diff AUTH", git("clearancekit", ["diff", f"{cfix}^", cfix]).stdout[:8000]))
dump("ord134.git.txt", "".join(ck))

# ---------- GitPython shared ----------
gp_commits = {
    "138_cand": "701ce32fe5ba8cb622c0e0342a376a6beb47d738",
    "138_fix": "e8d0fbf774d1f6baa3b481adfe48bd262e43b453",
    "139_cand": "8ac5a30519b6f4af85398b9b9d7064ff4d452da2",
    "139_fix": "863417457a0633db7ea5aed4fd01e0b291a41162",
    "141_cand": "54538428f79b0c91ba52cda5229856a6edf7ac06",
    "141_fix": "1ed1b924f4e2d2ee7bab296df77b978af21853f1",
    "142_fix": "7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca",
    "143_fix": "38553b6fddc7f6a667cdb45a6762343a08fc72b2",
    "170_cand": "c9a26789d88b18f8b4620f37307df2976292d2a0",
    "170_fix": "56806080c1348749b07daa4a2024ce47b3cad285",
    "180_cand": "3af0c2516c5e18c829da30338614688f6b69b49c",
    "180_fix": "1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6",
}

gp = []
for lab, sha in gp_commits.items():
    gp.append(section(f"{lab} msg", show_msg("GitPython", sha)))
    gp.append(section(f"{lab} files", git("GitPython", ["diff-tree", "--no-commit-id", "--name-only", "-r", sha]).stdout))

# 138 option candidates
gp.append(section("138 parent _option_candidates", git("GitPython", ["grep", "-n", "_option_candidates", "701ce32fe5ba8cb622c0e0342a376a6beb47d738^"]).stdout + git("GitPython", ["grep", "-n", "_option_candidates", "701ce32fe5ba8cb622c0e0342a376a6beb47d738^"]).stderr))
gp.append(section("138 cand _option_candidates", git("GitPython", ["show", "701ce32fe5ba8cb622c0e0342a376a6beb47d738:git/cmd.py"]).stdout))
# too big - just the function
gp.append(section("138 cand grep option", git("GitPython", ["grep", "-n", "-n", "-E", "_option_candidates|unsafe_git_archive|unsafe_git_revision|check_unsafe", "701ce32fe5ba8cb622c0e0342a376a6beb47d738"]).stdout[:8000]))
gp.append(section("138 parent grep option", git("GitPython", ["grep", "-n", "-E", "_option_candidates|unsafe_git_archive|unsafe_git_revision|check_unsafe", "701ce32fe5ba8cb622c0e0342a376a6beb47d738^"]).stdout[:8000]))
gp.append(section("138 fix grep", git("GitPython", ["grep", "-n", "-E", "_option_candidates|value", "e8d0fbf774d1f6baa3b481adfe48bd262e43b453", "--", "git/cmd.py"]).stdout[:4000]))
gp.append(section("138 ancestry", "\n".join([
    ancestor("GitPython", "701ce32fe5ba8cb622c0e0342a376a6beb47d738", "3.1.53"),
    ancestor("GitPython", "e8d0fbf774d1f6baa3b481adfe48bd262e43b453", "3.1.53"),
    ancestor("GitPython", "e8d0fbf774d1f6baa3b481adfe48bd262e43b453", "3.1.54"),
])))

# 139 expand_vars
gp.append(section("139 cand grep", git("GitPython", ["grep", "-n", "expand_vars", "8ac5a30519b6f4af85398b9b9d7064ff4d452da2"]).stdout[:5000]))
gp.append(section("139 parent grep", git("GitPython", ["grep", "-n", "expand_vars", "8ac5a30519b6f4af85398b9b9d7064ff4d452da2^"]).stdout[:3000] + git("GitPython", ["grep", "-n", "expand_vars", "8ac5a30519b6f4af85398b9b9d7064ff4d452da2^"]).stderr))
gp.append(section("139 fix grep", git("GitPython", ["grep", "-n", "expand_vars", "863417457a0633db7ea5aed4fd01e0b291a41162"]).stdout[:5000]))
gp.append(section("139 ancestry", "\n".join([
    ancestor("GitPython", "8ac5a30519b6f4af85398b9b9d7064ff4d452da2", "3.1.54"),
    ancestor("GitPython", "863417457a0633db7ea5aed4fd01e0b291a41162", "3.1.54"),
    ancestor("GitPython", "863417457a0633db7ea5aed4fd01e0b291a41162", "3.1.55"),
])))

# 141 config
gp.append(section("141 cand grep", git("GitPython", ["grep", "-n", "-E", "_assure_config_name_safe|UNSAFE_CONFIG|\\]", "54538428f79b0c91ba52cda5229856a6edf7ac06", "--", "git/config.py"]).stdout[:5000]))
gp.append(section("141 parent grep", git("GitPython", ["grep", "-n", "-E", "_assure_config_name_safe|UNSAFE_CONFIG", "54538428f79b0c91ba52cda5229856a6edf7ac06^"]).stdout + git("GitPython", ["grep", "-n", "-E", "_assure_config_name_safe|UNSAFE_CONFIG", "54538428f79b0c91ba52cda5229856a6edf7ac06^"]).stderr))
gp.append(section("141 fix grep", git("GitPython", ["grep", "-n", "-E", "_assure_config_name_safe|UNSAFE_CONFIG|closing bracket", "1ed1b924f4e2d2ee7bab296df77b978af21853f1", "--", "git/config.py"]).stdout[:5000]))
gp.append(section("141 ancestry", "\n".join([
    ancestor("GitPython", "54538428f79b0c91ba52cda5229856a6edf7ac06", "3.1.52"),
    ancestor("GitPython", "1ed1b924f4e2d2ee7bab296df77b978af21853f1", "3.1.52"),
    ancestor("GitPython", "1ed1b924f4e2d2ee7bab296df77b978af21853f1", "3.1.53"),
])))

# 142 archive
gp.append(section("142 parent archive options", git("GitPython", ["grep", "-n", "unsafe_git_archive", "701ce32fe5ba8cb622c0e0342a376a6beb47d738^"]).stdout + git("GitPython", ["grep", "-n", "unsafe_git_archive", "701ce32fe5ba8cb622c0e0342a376a6beb47d738^"]).stderr))
gp.append(section("142 cand archive", git("GitPython", ["grep", "-n", "-E", "unsafe_git_archive|--add-file|--exec", "701ce32fe5ba8cb622c0e0342a376a6beb47d738"]).stdout[:4000]))
gp.append(section("142 fix archive", git("GitPython", ["grep", "-n", "-E", "unsafe_git_archive|--add-file|--add-virtual", "7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca"]).stdout[:4000]))
gp.append(section("142 ancestry", "\n".join([
    ancestor("GitPython", "701ce32fe5ba8cb622c0e0342a376a6beb47d738", "3.1.56"),
    ancestor("GitPython", "7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca", "3.1.56"),
    ancestor("GitPython", "7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca", "3.1.57"),
])))

# 143 count
gp.append(section("143 cand count/iter", git("GitPython", ["grep", "-n", "-E", "check_unsafe|unsafe_git_revision|def count|def iter_items", "701ce32fe5ba8cb622c0e0342a376a6beb47d738", "--", "git/objects/commit.py"]).stdout[:5000]))
gp.append(section("143 parent count/iter", git("GitPython", ["grep", "-n", "-E", "check_unsafe|unsafe_git_revision|def count|def iter_items", "701ce32fe5ba8cb622c0e0342a376a6beb47d738^", "--", "git/objects/commit.py"]).stdout[:5000]))
gp.append(section("143 fix count", git("GitPython", ["grep", "-n", "-E", "check_unsafe|unsafe_git_revision|def count", "38553b6fddc7f6a667cdb45a6762343a08fc72b2", "--", "git/objects/commit.py"]).stdout[:4000]))
gp.append(section("143 ancestry", "\n".join([
    ancestor("GitPython", "701ce32fe5ba8cb622c0e0342a376a6beb47d738", "3.1.55"),
    ancestor("GitPython", "38553b6fddc7f6a667cdb45a6762343a08fc72b2", "3.1.55"),
    ancestor("GitPython", "38553b6fddc7f6a667cdb45a6762343a08fc72b2", "3.1.56"),
])))

# 170 shlex
gp.append(section("170 cand diff repo base", git("GitPython", ["diff", "c9a26789d88b18f8b4620f37307df2976292d2a0^", "c9a26789d88b18f8b4620f37307df2976292d2a0", "--", "git/repo/base.py"]).stdout[:12000]))
gp.append(section("170 parent check_unsafe clone", git("GitPython", ["grep", "-n", "-E", "check_unsafe_options|shlex|multi_options", "c9a26789d88b18f8b4620f37307df2976292d2a0^", "--", "git/repo/base.py"]).stdout[:4000]))
gp.append(section("170 fix diff", git("GitPython", ["diff", "56806080c1348749b07daa4a2024ce47b3cad285^", "56806080c1348749b07daa4a2024ce47b3cad285"]).stdout[:12000]))
gp.append(section("170 ancestry", "\n".join([
    ancestor("GitPython", "c9a26789d88b18f8b4620f37307df2976292d2a0", "3.1.50"),
    ancestor("GitPython", "56806080c1348749b07daa4a2024ce47b3cad285", "3.1.50"),
    ancestor("GitPython", "56806080c1348749b07daa4a2024ce47b3cad285", "3.1.51"),
])))

# 180 tag
gp.append(section("180 cand diff tag.py", git("GitPython", ["diff", "3af0c2516c5e18c829da30338614688f6b69b49c^", "3af0c2516c5e18c829da30338614688f6b69b49c", "--", "git/refs/tag.py"]).stdout[:12000]))
gp.append(section("180 parent tag create", git("GitPython", ["grep", "-n", "-E", "def create|check_unsafe|--file", "3af0c2516c5e18c829da30338614688f6b69b49c^", "--", "git/refs/tag.py"]).stdout[:4000]))
gp.append(section("180 fix diff tag.py", git("GitPython", ["diff", "1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6^", "1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6", "--", "git/refs/tag.py"]).stdout[:8000]))
gp.append(section("180 ancestry", "\n".join([
    ancestor("GitPython", "3af0c2516c5e18c829da30338614688f6b69b49c", "3.1.58"),
    ancestor("GitPython", "1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6", "3.1.58"),
    ancestor("GitPython", "1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6", "3.1.59"),
])))
dump("ord-gitpython.git.txt", "".join(gp))

# ---------- 192 / 195 openclaw ----------
oc = []
s192 = "b75ad800a59009fc47eaa3471410f69046150e59"
f192 = "06047005ef7dedda5ea655f52117e8aaa1cca373"
s195 = "47eb2d48d43452afc4b0160e40a2630e4a38a0ff"
f195 = "3c6259ebb70c76523a7b3fb7cfdac2e40a7f7449"
for lab, sha in [("192cand", s192), ("192fix", f192), ("195cand", s195), ("195fix", f195)]:
    oc.append(section(f"{lab} msg", show_msg("openclaw", sha)))
    oc.append(section(f"{lab} files", git("openclaw", ["diff-tree", "--no-commit-id", "--name-only", "-r", sha]).stdout[:3000]))
oc.append(section("192 cand diff snapshot", git("openclaw", ["diff", f"{s192}^", s192]).stdout[:15000]))
oc.append(section("192 parent snapshot grep", git("openclaw", ["grep", "-n", "-E", "ssrf|current-tab|assertBrowser|navigate", f"{s192}^", "--", "extensions/browser/src/browser/routes/agent.snapshot.ts"]).stdout[:4000] + git("openclaw", ["grep", "-n", "ssrf", f"{s192}^", "--", "extensions/browser/src/browser/routes/agent.snapshot.ts"]).stderr))
oc.append(section("192 fix diff", git("openclaw", ["diff", f"{f192}^", f192]).stdout[:12000]))
oc.append(section("192 ancestry", "\n".join([
    ancestor("openclaw", s192, "v2026.5.22"),
    ancestor("openclaw", f192, "v2026.5.22"),
    ancestor("openclaw", f192, "v2026.5.26"),
    ancestor("openclaw", s192, "v2026.4.14") if git("openclaw", ["rev-parse", "v2026.4.14"]).returncode == 0 else "no v2026.4.14",
])))
oc.append(section("195 cand diff", git("openclaw", ["diff", f"{s195}^", s195]).stdout[:15000]))
oc.append(section("195 parent mcp-transport grep", git("openclaw", ["grep", "-n", "-E", "Authorization|redirect|STREAMABLE|SSE", f"{s195}^", "--", "src/agents/mcp-transport.ts"]).stdout[:5000] + git("openclaw", ["grep", "-n", "Authorization", f"{s195}^", "--", "src/agents/mcp-transport.ts"]).stderr))
oc.append(section("195 fix diff", git("openclaw", ["diff", f"{f195}^", f195]).stdout[:12000]))
oc.append(section("195 ancestry", "\n".join([
    ancestor("openclaw", s195, "v2026.6.1"),
    ancestor("openclaw", f195, "v2026.6.1"),
    ancestor("openclaw", f195, "v2026.6.5"),
])))
dump("ord192-195.git.txt", "".join(oc))
print("done")
