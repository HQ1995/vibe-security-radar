#!/usr/bin/env python3
"""Lightweight independent git probes for redbase-even."""

from __future__ import annotations

import subprocess
from pathlib import Path

NOTES = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-redbase-even/notes")
C = Path("/home/hanqing/.cache/ghsa200-worker-clones/redbase-even/clones")
GIT = ["git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]


def run(repo: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run([*GIT, "-C", repo, *args], text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "TIMEOUT")


def out(repo: str, *args: str, timeout: int = 60) -> str:
    p = run(repo, *args, timeout=timeout)
    return (p.stdout or "") + (("\nSTDERR\n" + p.stderr) if p.stderr else "")


def ancestor(repo: str, a: str, b: str) -> str:
    p = run(repo, "merge-base", "--is-ancestor", a, b)
    return "YES" if p.returncode == 0 else "NO"


def exists(repo: str, spec: str) -> str:
    p = run(repo, "cat-file", "-e", spec)
    return "YES" if p.returncode == 0 else "NO"


def blob(repo: str, spec: str) -> str:
    p = run(repo, "rev-parse", spec)
    return (p.stdout or "").strip() or "MISSING"


def write(name: str, text: str) -> None:
    (NOTES / name).write_text(text)


def probe(name: str, repo: str, cands: list[str], carriers: list[str], fixes: list[str], vul_tags: list[str], fix_tags: list[str], pickaxe: list[str]) -> None:
    lines = [f"======== {name} ========"]
    lines.append("HEAD " + out(repo, "log", "-1", "--format=%H %cI %s").strip())
    for sha in cands + carriers + fixes:
        lines.append(f"\n----- {sha} -----")
        lines.append(out(repo, "cat-file", "-t", sha).strip() or "MISSING")
        lines.append(out(repo, "log", "-1", "--format=%H%n%P%n%an <%ae>%n%cI%n%s%n%n%B", sha)[:3500])
        lines.append("stat\n" + out(repo, "show", "--stat", "--format=", sha)[:2500])
    for t in vul_tags + fix_tags:
        sha = blob(repo, t)
        lines.append(f"\nTAG {t}={sha}")
        for x in cands + carriers + fixes:
            lines.append(f"  anc {x[:12]}->{t}: {ancestor(repo, x, t)}")
    if pickaxe and "openclaw" not in repo and "gitea" not in repo and "budibase" not in repo:
        for s in pickaxe:
            lines.append(f"\nlog -S {s!r} --oneline (limit 15)")
            lines.append(out(repo, "log", "-S", s, "--oneline", "-n", "15", timeout=45)[:2000])
    write(f"{name}.git.txt", "\n".join(lines))
    print("wrote", name, flush=True)


def main() -> None:
    probe("ord2", str(C/"hermes-webui"),
          ["d2b27f6f1edb83634730f93dc8f19721d877bd07"],
          ["f21b088a14d63fb0ce459da7b8b304393ee94f7c"],
          ["88dc8bbe26a6055161d3251b70f5cd3d3c5831b0"],
          ["v0.24"], ["v0.50.12"],
          ["_reload_dotenv", "_loaded_profile_env_keys"])
    probe("ord6", str(C/"openclaw"),
          ["cc048a295e7e70684ca24654257e0ecf38e49153"],
          ["03586e3d0057b5975090d50dadcc5bc95b51f977"],
          ["0ee30361b8f6ef3f110f3a7b001da6dd3df96bb5"],
          ["v2026.2.22"], ["v2026.2.24"],
          ["checkUserAllowed"])
    probe("ord12", str(C/"budibase"),
          ["700ff33db7470d4d2dd9674e9e29dc5e6392daa4"], [],
          ["bca426de7dc36d680285295655dc640dea2aab21"],
          ["3.38.1"], ["3.39.25"],
          ["sanitizeAutomationTestResult", "oauth2"])
    probe("ord14", str(C/"filebrowser"),
          ["847d08bdd135e5c3659f2e6dea2f0cd36617af9b"], [],
          ["8503ba61ff51d48a7313896483d130eb6a5abfe0"],
          ["v2.63.6"], ["v2.63.17"],
          ["ReplaceAll"])
    probe("ord18", str(C/"clearancekit"),
          ["5a887953c45551879797fd9e11a2055cf9386d7e"], [],
          ["56d617b778c571e3c29b803636d9807940992daa"],
          ["v4.2.11-97eb073"], ["v4.2.14-56d617b"],
          ["updatePolicy"])
    probe("ord26", str(C/"ruflo"),
          ["29d52dfc22842b80928d058c88f446993ec4975c"], [],
          ["d00a0a40cd8bdbca877ac7f675f416bdc69accd1"],
          ["v3.16.2"], ["v3.16.3"],
          ["terminal_execute", "MCP_AUTH_TOKEN"])
    probe("ord32", str(C/"claw-orchestrator"),
          ["f82c783607ae0129386cc072160dfcfb151a31fe"], [],
          ["d0b02a800aa0689d9428cc4cc170e0b6589fb2c3"],
          ["v3.5.5"], ["v3.5.6"],
          ["EmbeddedServer"])
    probe("ord42-feishu", str(C/"clawdbot-feishu"),
          ["a604df8c83d179a6e9fc07987ebef610faaf4991"], [], [], [], [],
          ["feishu_img_"])
    probe("ord42-openclaw", str(C/"openclaw"),
          ["a604df8c83d179a6e9fc07987ebef610faaf4991"],
          ["2267d58afcc70fe19408b8f0dce108c340f3426d"],
          ["c821099157a9767d4df208c6b12f214946507871"],
          ["v2026.2.12"], ["v2026.2.19"],
          ["feishu_img_", "randomUUID"])
    probe("ord44", str(C/"orpc"),
          ["3e17621325a7b729ed486c3464a5a4a334f2ee8a"], [],
          ["4f0efa8a1d3fa8e8317a4b03cc3945a5dfd68add"],
          [], [], ["stringifyJSON"])
    probe("ord46", str(C/"openclaw"),
          ["06dd9b8ed864eb6668d42c497f0615e743da483a"], [],
          ["f865a5455ee03924a444e9ba0f1c4743d8fb6566"],
          [], [], ["downloadToFile"])
    probe("ord54", str(C/"openclaw"),
          ["079af0d0b02ca2c722f90b6c4e38e27ba16227b4"], [],
          ["ddcb2d79b17bf2a42c5037d8aeff1537a12b931e"],
          [], [], ["skipDeviceAuth"])
    probe("ord58-feishu", str(C/"clawdbot-feishu"),
          ["4286755f26bcfdd5c704cc4eb0cabfdc1b314e68", "822b5f37b76284d247823efea51c47e0b975e9d1"],
          [], [], [], [], ["sendMediaFeishu"])
    probe("ord58-openclaw", str(C/"openclaw"),
          ["4286755f26bcfdd5c704cc4eb0cabfdc1b314e68"],
          ["2267d58afcc70fe19408b8f0dce108c340f3426d"],
          ["5b4121d6011a48c71e747e3c18197f180b872c5d"],
          ["v2026.2.13"], ["v2026.2.14"],
          ["sendMediaFeishu"])
    probe("ord64", str(C/"9router"),
          ["706e6513c94803ac46a8c1c21ca8ac6775912e3a"], [],
          ["126aa244c5b51b74ab8c7594e3418fcf4437bf6f"],
          [], [], ["kiro"])
    probe("ord66-openclaw", str(C/"openclaw"),
          ["4286755f26bcfdd5c704cc4eb0cabfdc1b314e68"],
          ["2267d58afcc70fe19408b8f0dce108c340f3426d"],
          ["f45e5a6569aab1d58cc6de25b19f1dc4c8779b85"],
          ["v2026.3.28"], ["v2026.3.31"],
          ["quotedContent"])
    probe("ord76", str(C/"anchorr"),
          ["403ccf079be0ee5e6660f0ed2fa64174d76eff2f"], [],
          ["d5ae67e5b455241274ed0072cf2db43a6eb3f0b2"],
          [], [], ["innerHTML"])
    probe("ord106", str(C/"prompty"),
          ["a0e6108842a3bfc840a33db819a4415fbdac333d"], [],
          ["c27402da2487075be577f06aa79df627fb9d6853"],
          [], [], ["gray-matter"])
    probe("ord112", str(C/"bsv-ruby-sdk"),
          ["6a4d8984026dc8f533d408f8ea737af7f7b2713d", "d14dd19f976eb5e92e0ea6755e56864f5b1ae047"], [],
          ["db97de475518eef752ed52b25f49f09cbe24c187"],
          [], [], ["verify"])
    probe("ord118", str(C/"openclaw"),
          ["c74551c2ae0611f3ef0e691dc93a38372f366765"], [],
          ["a7534dc22382c42465f3676724536a014ce0cbf7"],
          [], [], ["gatewayUrl"])
    probe("ord148", str(C/"prospero-flow-crm"),
          ["52e5e1938ba7db9191ab75fc6f81d92cf667dd4d"], [],
          ["86a7d6557bd111518a221f4575ad6e36087e19d3"],
          [], [], ["permission"])
    probe("ord160", str(C/"fast-uri"),
          ["0542a216860fd70c062a4730e620576f62ded057"], [],
          ["f3c6c905f47831007490f466c5945012e905cc52"],
          [], [], ["backslash"])
    probe("ord162", str(C/"gitea"),
          ["1eced4a7c099459af42412bb32a83241650c0f8f", "e7fca90a780e4d35eb1fa67b1f377ebd54e74611"], [],
          ["f7fd51022495737cf960b8c4053a27d69148f664", "ab10e37acf7fabf7829a485cc3e13d118638a856"],
          ["v1.25.5", "v1.26.4"], ["v1.27.0"],
          ["GetAttachmentByUUID"])
    probe("ord164", str(C/"faraday"),
          ["a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc"], [],
          ["3f1280c69e93297d574e85a2d462d05ebadf1d09"],
          ["v2.14.1"], ["v2.14.2"],
          ["start_with?"])
    probe("ord166", str(C/"filebrowser"),
          ["847d08bdd135e5c3659f2e6dea2f0cd36617af9b"], [],
          ["64511ce45e3be379e965f7f4fb0929a068d5bb81"],
          ["v2.63.6"], [],
          ["symlink"])
    probe("ord176", str(C/"GitPython"),
          ["1ed1b924f4e2d2ee7bab296df77b978af21853f1"], [],
          ["a495ccd3b547ccd60b2187215823b72a9c0188bf"],
          [], [], ["option"])
    probe("ord182", str(C/"churchcrm"),
          ["f9afc3c5a961efbf600ac8f71ecc3da54ddef1b1"],
          ["18b211535fec3b09d1ab613af923e28080605101"],
          ["1bfc187ac41238a2488d58f06361d7377d3cdf11"],
          ["7.2.2"], ["7.3.1"],
          ["TwoFactor"])
    probe("ord210", str(C/"sipsorcery"),
          ["6edd60f593a467be6ac654c71f57284665f59df1"],
          ["dd767827e6005e653ec6e8ddc9a43eb1de84d865"],
          ["ccb0b5a845efa2fb131fd00de4f5321bae627f29"],
          ["v10.0.13"], ["v10.0.14"],
          ["TurnServer"])


if __name__ == "__main__":
    main()
