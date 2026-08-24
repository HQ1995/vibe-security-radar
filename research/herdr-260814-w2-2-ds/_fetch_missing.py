#!/usr/bin/env python3
"""Fetch missing repos' candidate commits into the shared sweep pool (smart-HTTP)."""
import subprocess
import sys

ROOT = "/home/hanqing/.cache/ghsa200-sweep-fetch"
TARGETS = {
    "mealie-recipes/mealie": [
        "cee2c351a37c2af6321b75d7e27b063d0693cf9b",
        "874dc94d81055c9aac3678f9ff59dbefc76adb3a",
        "9247204f590a785abb40fbbcb8e5075b9a3b029b",
        "bd23896e34",
    ],
    "coze-dev/coze-studio": [
        "a21e41b89d",
        "d535136d91",
        "c5f052892a6b0646ffa42aa76329858e9a1930e1",
        "49abae400ddc20b20068185b76296ab39d8912d9",
        "91d6cdb430cf95c06d3fb6c7da69b22c766f038d",
    ],
    "davisking/dlib": [
        "20b217246953268e1e2d68040f017ca61ced9026",
        "d890f7d2c5bbbaaf2026937777f2e557ae163ac7",
        "7889cf3a2ad7e89ecfd067e7c99bc21ec7ee4b65",
        "79e2d1373add8d9e265d6a16c4952f5273600e97",
        "66be36e0fb7d4a80b1c8173bfa44f342cce62416",
    ],
    "root-project/root": [
        "4bcab64f9c7175933307d06c318e85938898de93",
        "c5822aab0516f2ca59dedd55e57d63187fef0850",
        "d2a42e05ede8b3b8e00d32da48dece244d136cba",
        "f8a2fae11cc4dc540c305551d2e798ad51429396",
    ],
}


def run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main():
    for repo, shas in TARGETS.items():
        key = repo.replace("/", "__")
        path = ROOT + "/" + key
        url = "https://github.com/" + repo + ".git"
        shas = [s for s in shas if len(s) >= 40]
        if not shas:
            print("SKIP", repo, "no full shas")
            continue
        import os
        if not os.path.isdir(path):
            run(["git", "--no-optional-locks", "init", "-q", "--bare", path], 30)
        r = run(
            ["git", "--no-optional-locks", "-C", path, "fetch", "-q",
             "--filter=blob:none", "--depth", "1", url] + shas,
            timeout=300)
        print(repo, "fetch rc", r.returncode, r.stderr.strip()[:200])
        for s in shas:
            chk = run(["git", "-C", path, "cat-file", "-e", s + "^{commit}"], 20)
            print("  ", s[:10], "present" if chk.returncode == 0 else "MISSING")


if __name__ == "__main__":
    main()
