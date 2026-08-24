#!/usr/bin/env python3
"""Phase 6: cheap AI-marker recall sweep over remaining odd-partition candidates.

For every odd ID with fix-SHA refs not yet deep-reviewed, fetch the fix commit
(blobless, shallow), read the fix message + parent messages + advisory details,
and flag explicit AI markers (trailers / generated-by patterns). Flagged cases
are candidates for manual deep review; un-flagged cases stay UNKNOWN.
"""
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from build_delta import OWN, sha256_file  # noqa: E402
from deep_collect import NEW_BASE, AI_MSG_RE, AI_TRAILER_RE  # noqa: E402

REVIEWED = {
    "GHSA-2Q4P-G7HV-5RGV", "GHSA-2V37-7H3G-55P8", "GHSA-3CCP-42PG-HGV6",
    "GHSA-3WHF-VGF2-9W6G", "GHSA-6V4J-43GG-VJ32", "GHSA-8XCM-R25X-G524",
    "GHSA-MHVJ-JHPQ-885V", "GHSA-PM5P-7W5H-JM5Q", "GHSA-RM67-G9CH-VXFF",
    "GHSA-WFP6-F47H-HXC3", "GHSA-X83G-979R-F5FH", "GHSA-XR9X-R78C-5HRM",
    "GHSA-4J8X-X6V7-W9RQ", "GHSA-4JWF-M4WG-8P66", "GHSA-52FH-8V99-63C2",
    "GHSA-7835-87Q9-RGVV", "GHSA-C5PX-58J2-7FQP", "GHSA-GMFW-G93R-VG53",
    "GHSA-HC4M-Q9JH-XW4J", "GHSA-HFHX-W8P8-4HC7", "GHSA-HR7P-WG7R-HG9M",
    "GHSA-PGWH-4JJ4-QM8V", "GHSA-VQFP-P66C-XRP9", "GHSA-WG86-R78F-74MP",
    "GHSA-XRMJ-5G4G-8987",
}

REAL_TRAILER = re.compile(
    r"(co-?authored-?by|assisted-?by|generated (with|by)|authored by|written by|"
    r"created by|prompted by|via (copilot|claude|gpt|gemini|codex|aider))",
    re.IGNORECASE)
BOT_AI = re.compile(
    r"(copilot|claude|chatgpt|gpt-5|gpt-4|gemini|codex|aider|openclaw|cursor|qwen|"
    r"devin|windsurf|deepseek|sonnet|opus|anthropic|openai)",
    re.IGNORECASE)


def sweep_one(gid, row):
    result = {"ghsa": gid, "flags": []}
    shas = row["new"].get("ref_commit_shas") or []
    repos = row["new"].get("ref_repos") or []
    if not shas or not repos:
        return result
    repo = max(set(repos), key=lambda r: sum(1 for u in row["new"]["ref_urls"] if r in u))
    slug = repo.replace("/", "__")
    d = NEW_BASE / "repos" / slug
    d.mkdir(parents=True, exist_ok=True)
    if not (d / ".git").exists():
        subprocess.run(["git", "init", "-q", str(d)], capture_output=True)
        subprocess.run(["git", "-C", str(d), "remote", "add", "origin", f"https://github.com/{repo}.git"],
                       capture_output=True)
    for sha in shas[:3]:
        if not re.match(r"^[0-9a-f]{40}$", sha):
            continue
        subprocess.run(["git", "-C", str(d), "fetch", "-q", "--depth=6", "--filter=blob:none",
                        "origin", sha], capture_output=True, timeout=180)
        for spec in (sha, f"{sha}~1", f"{sha}~2"):
            out = subprocess.run(["git", "-C", str(d), "log", "-1", "--format=%H|%an|%ae|%s|%B", spec],
                                 capture_output=True, text=True, timeout=60)
            msg = out.stdout or ""
            if out.returncode == 0:
                for ln in msg.splitlines():
                    if REAL_TRAILER.search(ln) and BOT_AI.search(ln):
                        result["flags"].append({"spec": spec, "line": ln.strip()[:160]})
    if result["flags"]:
        result["repo"] = repo
        result["summary"] = row["new"].get("summary", "")
    return result


def main() -> int:
    odd = [l.strip() for l in open(OWN / "partition-odd.txt")]
    rows = {json.loads(l)["ghsa"]: json.loads(l) for l in (OWN / "reviewed-delta.jsonl").open()}
    targets = [(g, rows[g]) for g in odd
               if g not in REVIEWED and rows[g]["new"].get("ref_commit_shas")
               and rows[g]["new"].get("ref_repos")]
    print(f"sweeping {len(targets)} cases", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda t: sweep_one(*t), targets))
    flagged = [r for r in results if r["flags"]]
    out = OWN / "recall-sweep.json"
    out.write_text(json.dumps({"flagged": flagged, "swept": len(targets)}, indent=2) + "\n")
    print(f"flagged: {len(flagged)}")
    for r in flagged:
        print(f"  {r['ghsa']} | {r.get('repo')} | {r['summary'][:60]}")
        for f in r["flags"][:3]:
            print(f"     {f['spec'][:12]} | {f['line']}")
    print(f"recall-sweep.json sha256: {sha256_file(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
