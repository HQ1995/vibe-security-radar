#!/usr/bin/env python3
"""Extract first-party unreviewed advisory JSONs for the assigned slice."""
import json
import subprocess
import sys

ADB = "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"
SLICE = ("/home/hanqing/agents/ai-slop/autoresearch/"
         "orchestrator-260814-ghsa200-canvas/sweep/unr-adj2-slice-2.jsonl")


def main():
    rows = [json.loads(l) for l in open(SLICE)]
    out = []
    for r in rows:
        g = r["ghsa"]
        lg = "GHSA-" + g[5:].lower()
        y, m = r["published"][:4], r["published"][5:7]
        path = "advisories/unreviewed/" + y + "/" + m + "/" + lg + "/" + lg + ".json"
        raw = None
        for ref in ("origin/main", "HEAD"):
            res = subprocess.run(
                ["git", "-C", ADB, "show", ref + ":" + path],
                capture_output=True, text=True)
            if res.returncode == 0:
                raw = res.stdout
                break
        if raw is None:
            out.append({"ghsa": g, "error": res.stderr.strip()})
            continue
        adv = json.loads(raw)
        out.append({
            "ghsa": g,
            "repo": r["repo"],
            "published": r["published"],
            "aliases": adv.get("aliases", []),
            "details": adv.get("details", ""),
            "affected": adv.get("affected", []),
            "references": adv.get("references", []),
            "cwe_ids": adv.get("database_specific", {}).get("cwe_ids", []),
            "reviewed": adv.get("database_specific", {}).get("github_reviewed"),
        })
    json.dump(out, open(sys.argv[1], "w"), indent=1)
    print("wrote", len(out), "advisory summaries to", sys.argv[1])


if __name__ == "__main__":
    main()
