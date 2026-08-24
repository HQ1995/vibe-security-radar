#!/usr/bin/env python3
import json, os, subprocess, sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "probe_out.json"

def run(cmd, timeout=30):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    return p.returncode, p.stdout

def git(repo, args, timeout=30):
    return run(["git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", repo] + args, timeout)

rows = []
# Coolify 35
repo = "/home/hanqing/.cache/ghsa200-worker-clones/redbase/clones/coolify"
sha = "473c32270d72252ee6753afc35c3ea4360d169e0"
rc, out = git(repo, ["log", "-1", "--format=%H%n%P%n%an%n%ae%n%s%n%b", sha])
rows.append({"k":"35.log", "rc":rc, "out":out[:4000]})
rc, out = git(repo, ["show", "--stat", "--format=", sha])
rows.append({"k":"35.stat", "rc":rc, "out":out[:4000]})
rc, out = git(repo, ["grep", "-n", "excludeCollection", "733c20fc9d4af7c109c711315e63bbd21623e62f", "--", "app/Jobs/DatabaseBackupJob.php"])
rows.append({"k":"35.parent.exclude", "rc":rc, "out":out[:2000]})
rc, out = git(repo, ["grep", "-n", "function create_backup", sha, "--", "app/Http/Controllers/Api/DatabasesController.php"])
rows.append({"k":"35.create_backup", "rc":rc, "out":out[:2000]})
rc, out = git(repo, ["merge-base", "--is-ancestor", sha, "v4.0.0-beta.436"])
rows.append({"k":"35.cand.in.436", "rc":rc, "out":out})
rc, out = git(repo, ["merge-base", "--is-ancestor", "b1de75a7c67ce6aee977bd788b41e61837dbe0b9", "v4.0.0-beta.436"])
rows.append({"k":"35.fix.in.436", "rc":rc, "out":out})
rc, out = git(repo, ["merge-base", "--is-ancestor", "b1de75a7c67ce6aee977bd788b41e61837dbe0b9", "v4.0.0-beta.471"])
rows.append({"k":"35.fix.in.471", "rc":rc, "out":out})
rc, out = git(repo, ["log", "-1", "--format=%H%n%P%n%an%n%s%n%b", "b1de75a7c67ce6aee977bd788b41e61837dbe0b9"])
rows.append({"k":"35.fix.log", "rc":rc, "out":out[:3000]})
rc, out = git(repo, ["log", "-1", "--format=%H%n%P%n%an%n%s%n%b", "99043600ee881fd8581185e7590604d9882382cd"])
rows.append({"k":"35.fixmember.log", "rc":rc, "out":out[:3000]})

OUT.write_text(json.dumps(rows, indent=2))
print("wrote", OUT, "n", len(rows))
