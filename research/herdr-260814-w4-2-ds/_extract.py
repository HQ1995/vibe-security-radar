#!/usr/bin/env python3
import json
import subprocess
import sys

ADB = "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"


def main(slice_path, out_path):
    rows = [json.loads(l) for l in open(slice_path)]
    out = []
    for r in rows:
        g = r["ghsa"]
        lg = "GHSA-" + g[5:].lower()
        y, m = r["published"][:4], r["published"][5:7]
        path = "advisories/unreviewed/" + y + "/" + m + "/" + lg + "/" + lg + ".json"
        raw = None
        err = ""
        for ref in ("origin/main", "HEAD"):
            res = subprocess.run(
                ["git", "-C", ADB, "show", ref + ":" + path],
                capture_output=True, text=True)
            if res.returncode == 0:
                raw = res.stdout
                break
            err = res.stderr.strip()
        if raw is None:
            out.append({"ghsa": g, "error": err})
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
        })
    json.dump(out, open(out_path, "w"), indent=1)
    print("wrote", len(out), "advisories; errors:",
          sum(1 for x in out if "error" in x))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
