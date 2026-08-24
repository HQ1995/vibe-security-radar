#!/usr/bin/env python3
"""Independent red-team git probes. Writes notes only under this worker dir."""

from __future__ import annotations

import subprocess
from pathlib import Path

NOTES = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-red-upgrade-a/notes")
HA = "/tmp/ghsa200-worker-clones/red-upgrade-a/clones/ha-mcp"
CI = "/tmp/ghsa200-worker-clones/red-upgrade-a/clones/ciguard"
OC = "/tmp/ghsa200-worker-clones/red-upgrade-a/clones/openclaw"
GIT = ["git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]


def run(repo: str, *args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*GIT, "-C", repo, *args],
        text=True,
        capture_output=True,
        check=check,
    )


def out(repo: str, *args: str) -> str:
    p = run(repo, *args)
    return (p.stdout or "") + (("\nSTDERR\n" + p.stderr) if p.stderr else "")


def ancestor(repo: str, a: str, b: str) -> str:
    p = run(repo, "merge-base", "--is-ancestor", a, b)
    return "YES" if p.returncode == 0 else "NO"


def exists(repo: str, spec: str) -> str:
    p = run(repo, "cat-file", "-e", spec)
    return "YES" if p.returncode == 0 else "NO"


def write(name: str, text: str) -> None:
    (NOTES / name).write_text(text)


def ha_mcp() -> None:
    cand = "39806871c9720bf8afdcf3e061095c0dd63dea7f"
    fix = "dc8eaa16a8550f885614655f14b6fd9fe429b278"
    member = "aae7acba"
    lines = ["======== HA-MCP ========", out(HA, "log", "-1", "--format=%H%n%an <%ae>%n%cI%n%s%n%n%B", cand)]
    parent = run(HA, "rev-parse", f"{cand}^").stdout.strip()
    lines.append(f"parent {parent}")
    lines.append(out(HA, "log", "-1", "--format=%H %s", f"{cand}^"))
    lines.append("name-status cand\n" + out(HA, "diff-tree", "--no-commit-id", "--name-status", "-r", cand))
    lines.append("parent provider.py " + exists(HA, f"{cand}^:src/ha_mcp/auth/provider.py"))
    for t in ("v6.7.2", "v7.0.0"):
        sha = run(HA, "rev-parse", t).stdout.strip()
        lines.append(f"{t}={sha} cand_anc={ancestor(HA, cand, t)} fix_anc={ancestor(HA, fix, t)}")
    lines.append("member\n" + out(HA, "log", "-1", "--format=%H %s%n%B", member))
    lines.append(f"member ancestor v6.7.2 {ancestor(HA, member, 'v6.7.2')}")
    for spec in (
        f"{member}:src/ha_mcp/auth/provider.py",
        f"{cand}:src/ha_mcp/auth/provider.py",
        "v6.7.2:src/ha_mcp/auth/provider.py",
        "v7.0.0:src/ha_mcp/auth/provider.py",
    ):
        lines.append(f"blob {spec} {run(HA, 'rev-parse', spec).stdout.strip() or 'MISSING'}")
    lines.append("later provider.py\n" + out(HA, "log", "--format=%H %s", f"{cand}..v6.7.2", "--", "src/ha_mcp/auth/provider.py"))
    lines.append("fix\n" + out(HA, "log", "-1", "--format=%H %s%n%B", fix))
    lines.append("fix name-status\n" + out(HA, "diff-tree", "--no-commit-id", "--name-status", "-r", fix))
    lines.append("cand ha_url hunk\n" + out(HA, "grep", "-n", "ha_url", cand, "--", "src/ha_mcp/auth/provider.py"))
    lines.append("v6.7.2 ha_url\n" + out(HA, "grep", "-n", "ha_url", "v6.7.2", "--", "src/ha_mcp/auth/provider.py"))
    lines.append("v7.0.0 ha_url\n" + out(HA, "grep", "-n", "ha_url", "v7.0.0", "--", "src/ha_mcp/auth/provider.py"))
    lines.append("fix diff provider\n" + out(HA, "show", "--stat", "--", fix, "--", "src/ha_mcp/auth/provider.py"))
    lines.append("fix show provider excerpt\n" + out(HA, "show", f"{fix}:src/ha_mcp/auth/provider.py")[:4000])
    # other advisory paths
    lines.append("oauth token / websocket search at cand parent vs cand")
    for rev in (f"{cand}^", cand, "v6.7.2", "v7.0.0"):
        lines.append(f"--- {rev} ha_url files ---")
        lines.append(out(HA, "grep", "-l", "ha_url", rev, "--", "*.py"))
    write("ha-mcp.git.txt", "\n".join(lines))


def ciguard() -> None:
    cand = "d42195e10be0d7d9bfb4ec45fecfb83521d3fc67"
    osv = "f08e654974f208f90ef6015928ef651982f3224a"
    fix = "17a119fe43dd956ef463c1c575a463ffd9a8d95b"
    lines = ["======== CIGUARD ========", out(CI, "log", "-1", "--format=%H%n%an <%ae>%n%cI%n%s%n%n%B", cand)]
    lines.append("name-status cand\n" + out(CI, "diff-tree", "--no-commit-id", "--name-status", "-r", cand))
    lines.append("parent endoflife " + exists(CI, f"{cand}^:src/ciguard/analyzer/sca/endoflife.py"))
    lines.append("osv origin\n" + out(CI, "log", "-1", "--format=%H%n%an <%ae>%n%cI%n%s%n%n%B", osv))
    for t in ("v0.6.0", "v0.8.1", "v0.8.2"):
        sha = run(CI, "rev-parse", t).stdout.strip()
        lines.append(
            f"{t}={sha} cand_anc={ancestor(CI, cand, t)} osv_anc={ancestor(CI, osv, t)} fix_anc={ancestor(CI, fix, t)}"
        )
        lines.append("  endoflife " + exists(CI, f"{t}:src/ciguard/analyzer/sca/endoflife.py"))
        lines.append("  osv.py " + exists(CI, f"{t}:src/ciguard/analyzer/sca/osv.py"))
    lines.append("fix\n" + out(CI, "log", "-1", "--format=%H %s%n%B", fix))
    lines.append("fix name-status\n" + out(CI, "diff-tree", "--no-commit-id", "--name-status", "-r", fix))
    lines.append("cand endoflife read\n" + out(CI, "grep", "-n", "resp.read", cand, "--", "src/ciguard/analyzer/sca/endoflife.py"))
    lines.append("v0.6.0 endoflife read\n" + out(CI, "grep", "-n", "resp.read", "v0.6.0", "--", "src/ciguard/analyzer/sca/endoflife.py"))
    lines.append("v0.8.2 endoflife read\n" + out(CI, "grep", "-n", "resp.read", "v0.8.2", "--", "src/ciguard/analyzer/sca/endoflife.py"))
    if exists(CI, "v0.8.1:src/ciguard/analyzer/sca/osv.py") == "YES":
        lines.append("v0.8.1 osv read\n" + out(CI, "grep", "-n", "resp.read", "v0.8.1", "--", "src/ciguard/analyzer/sca/osv.py"))
        lines.append("v0.8.2 osv read\n" + out(CI, "grep", "-n", "resp.read", "v0.8.2", "--", "src/ciguard/analyzer/sca/osv.py"))
    write("ciguard.git.txt", "\n".join(lines))


def openclaw() -> None:
    c92 = "9a3800d8e6e69bc0a125dca5760d47515e746454"
    f92 = "7ade3553b74ee3f461c4acd216653d5ba411f455"
    m92 = "ce12b9092f03d85603f0b6b8193d512260a65dab"
    extra = "630f1479c44f78484dfa21bb407cbe6f171dac87"
    c93 = "49c60e9065d98a6848e62c717315eb91eeaa6038"
    f93 = "8a563d603b70ef6338915f0527bee87282c3bad5"
    m93 = "fbfe2f15fc316904972711b3391031d6c99682b4"
    lines = ["======== OPENCLAW 92 ========", out(OC, "log", "-1", "--format=%H%n%an <%ae>%n%cI%n%s%n%n%B", c92)]
    lines.append("name-status cand92\n" + out(OC, "diff-tree", "--no-commit-id", "--name-status", "-r", c92))
    client = "extensions/synology-chat/src/client.ts"
    handler = "extensions/synology-chat/src/webhook-handler.ts"
    lines.append("parent client " + exists(OC, f"{c92}^:{client}"))
    lines.append("parent resolveChatUserId\n" + out(OC, "grep", "-n", "resolveChatUserId", f"{c92}^", "--", client))
    lines.append("cand resolveChatUserId\n" + out(OC, "grep", "-n", "resolveChatUserId\\|byNickname\\|username", c92, "--", client))
    for t in ("v2026.3.2", "v2026.3.22", "v2026.3.23-2"):
        sha = run(OC, "rev-parse", t).stdout.strip()
        lines.append(
            f"{t}={sha} cand_anc={ancestor(OC, c92, t)} fix_anc={ancestor(OC, f92, t)} extra_anc={ancestor(OC, extra, t)}"
        )
    lines.append(f"member92 ancestor v2026.3.2 {ancestor(OC, m92, 'v2026.3.2')}")
    lines.append("member92\n" + out(OC, "log", "-1", "--format=%H %s%n%B", m92))
    for spec in (f"{m92}:{client}", f"{c92}:{client}", "v2026.3.2:" + client):
        lines.append(f"blob {spec} {run(OC, 'rev-parse', spec).stdout.strip() or 'MISSING'}")
    lines.append("fix92\n" + out(OC, "log", "-1", "--format=%H %s%n%B", f92))
    lines.append("fix92 name-status\n" + out(OC, "diff-tree", "--no-commit-id", "--name-status", "-r", f92))
    lines.append("fix92 show handler\n" + out(OC, "show", f92, "--", handler)[:5000])
    lines.append("extra 630f1479\n" + out(OC, "log", "-1", "--format=%H %s%n%B", extra))
    lines.append("extra name-status\n" + out(OC, "diff-tree", "--no-commit-id", "--name-status", "-r", extra))
    lines.append("======== OPENCLAW 93 ========")
    lines.append(out(OC, "log", "-1", "--format=%H%n%an <%ae>%n%cI%n%s%n%n%B", c93))
    lines.append("name-status cand93\n" + out(OC, "diff-tree", "--no-commit-id", "--name-status", "-r", c93))
    mh = "extensions/matrix/src/matrix/monitor/handler.ts"
    lines.append("parent ThreadStarter\n" + out(OC, "grep", "-n", "ThreadStarter\\|fetchEventSummary\\|thread", f"{c93}^", "--", mh))
    lines.append("cand ThreadStarter\n" + out(OC, "grep", "-n", "ThreadStarter\\|fetchEventSummary", c93, "--", mh))
    for t in ("v2026.2.12", "v2026.3.28", "v2026.3.31"):
        sha = run(OC, "rev-parse", t).stdout.strip()
        lines.append(f"{t}={sha} cand_anc={ancestor(OC, c93, t)} fix_anc={ancestor(OC, f93, t)}")
    lines.append(f"member93 ancestor v2026.2.12 {ancestor(OC, m93, 'v2026.2.12')}")
    lines.append("member93\n" + out(OC, "log", "-1", "--format=%H %s%n%B", m93))
    for spec in (f"{m93}:{mh}", f"{c93}:{mh}", "v2026.2.12:" + mh):
        lines.append(f"blob {spec} {run(OC, 'rev-parse', spec).stdout.strip() or 'MISSING'}")
    lines.append("fix93\n" + out(OC, "log", "-1", "--format=%H %s%n%B", f93))
    lines.append("fix93 name-status\n" + out(OC, "diff-tree", "--no-commit-id", "--name-status", "-r", f93))
    lines.append("fix93 show handler\n" + out(OC, "show", f93, "--", mh)[:6000])
    write("openclaw.git.txt", "\n".join(lines))


if __name__ == "__main__":
    NOTES.mkdir(exist_ok=True)
    ha_mcp()
    ciguard()
    openclaw()
    print("wrote notes")
