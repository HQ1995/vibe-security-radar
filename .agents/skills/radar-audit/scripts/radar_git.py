#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import threading
from urllib.parse import quote
from urllib.request import Request, urlopen
import zipfile

SCHEMA = "radar-git/v1"
ENV = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
       "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
LEADS = re.compile(
    r"(?i)(co-authored-by|generated (?:with|by)|created with|written with|assisted[- ]by|"
    r"ai[- ]assisted|\bllm\b|\bclaude\b|anthropic|\bcodex\b|openai|\bgpt[-0-9]|copilot|"
    r"\bcursor\b|\baider\b|gemini|\bjules\b|\bdevin\b|openhands|\bqwen|\bkimi\b|mistral|"
    r"devstral|\bwarp\b|roo ?code|roomote|qoder|opencode|windsurf|codeium|\[bot\])")
TRAILER = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.+)$")
PRERELEASE = re.compile(
    r"(?i)(?:alpha|beta|preview|canary|nightly|snapshot|[-.]rc|[-.]pre|[-.]dev|\d(?:a|b|rc)\d+$)")
MAX_MEMBER = 20 * 1024 * 1024
FETCH = None


class ToolError(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(repo, *args, input=None, check=True):
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=ENV,
                          input=input.encode() if isinstance(input, str) else input)
    if check and proc.returncode:
        raise ToolError(f"git {' '.join(args[:2])}: {proc.stderr.decode(errors='replace').strip()[:500]}")
    return proc.stdout.decode("utf-8", errors="replace")


def resolve(repo, names):
    result = []
    for start in range(0, len(names), 200000):
        chunk = names[start:start + 200000]
        out = git(repo, "cat-file", "--batch-check=%(objectname)", input="\n".join(chunk) + "\n").splitlines()
        result += [None if line.endswith((" missing", " ambiguous")) else line.strip() for line in out]
    return result


LOCAL = {}
FETCH_MISSING = False
SHARED_CLONES = "/.ai-slop/state/repos/"


def local_objects(repo):
    key = str(Path(repo).resolve())
    if FETCH_MISSING:
        return None
    if key not in LOCAL:
        partial = (git(repo, "config", "--get", "extensions.partialclone", check=False).strip()
                   or "true" in git(repo, "config", "--get-regexp", r"^remote\..*\.promisor$", check=False))
        LOCAL[key] = set(git(repo, "cat-file", "--batch-all-objects", "--unordered",
                             "--batch-check=%(objectname)").split()) if partial else None
    return LOCAL[key]


def allow_fetch(repo):
    global FETCH_MISSING
    if SHARED_CLONES in str(Path(repo or ".").resolve()) + "/":
        raise ToolError("--fetch-missing is only for your own scratch clone, not the shared product clones")
    FETCH_MISSING = True
    ENV["GIT_NO_LAZY_FETCH"] = "0"


def read_objects(repo, oids):
    present = local_objects(repo)
    found = {oid: None for oid in oids if present is not None and oid not in present}
    oids = [oid for oid in dict.fromkeys(oids) if oid not in found]
    for start in range(0, len(oids), 5000):
        chunk = oids[start:start + 5000]
        data = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch"], capture_output=True, env=ENV,
                              input=("\n".join(chunk) + "\n").encode()).stdout
        pos = 0
        for oid in chunk:
            end = data.index(b"\n", pos)
            parts = data[pos:end].decode().split()
            pos = end + 1
            if len(parts) != 3:
                found[oid] = None
                continue
            size = int(parts[2])
            found[oid] = data[pos:pos + size]
            pos += size + 1
    return found


def tree_entry(raw, name):
    pos = 0
    while pos < len(raw):
        space = raw.index(b" ", pos)
        nul = raw.index(b"\0", space)
        if raw[space + 1:nul] == name and raw[pos:space] not in (b"40000", b"160000"):
            return raw[nul + 1:nul + 21].hex()
        pos = nul + 21
    return None


def blob_at(repo, revs, path):
    directory, _, name = path.strip("/").rpartition("/")
    names = [f"{r}:{directory}" if directory else f"{r}^{{tree}}" for r in revs]
    trees = []
    for start in range(0, len(names), 200000):
        out = git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                  input="\n".join(names[start:start + 200000]) + "\n").splitlines()
        trees += [line.split()[0] if line.endswith(" tree") else None for line in out]
    raws = read_objects(repo, [t for t in set(trees) if t])
    entries = {t: None if raw is None else tree_entry(raw, name.encode()) for t, raw in raws.items()}
    return [entries.get(t) if t else None for t in trees]


def is_ancestor(repo, older, newer):
    proc = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", older, newer],
                          capture_output=True, env=ENV)
    if proc.returncode not in (0, 1):
        raise ToolError(f"merge-base {older} {newer}: {proc.stderr.decode(errors='replace').strip()[:300]}")
    return proc.returncode == 0


def commit_sha(repo, ref):
    oid = resolve(repo, [f"{ref}^{{commit}}"])[0]
    if not oid:
        raise ToolError(f"{ref} is not a commit in {repo}")
    return oid


def repo_state(repo):
    refs = git(repo, "for-each-ref", "--format=%(refname)").split()
    groups = Counter("/".join(r.split("/")[:3 if r.startswith("refs/remotes/") else 2]) for r in refs)
    objects = {}
    for line in git(repo, "count-objects", "-v").splitlines():
        key, _, value = line.partition(": ")
        objects[key] = int(value) if value.isdigit() else value
    return {"path": str(Path(repo).resolve()),
            "is_shallow": git(repo, "rev-parse", "--is-shallow-repository").strip() == "true",
            "partial_filter": git(repo, "config", "--get-all", "remote.origin.partialclonefilter",
                                  check=False).strip() or None,
            "head": git(repo, "rev-parse", "HEAD", check=False).strip() or None,
            "refs": dict(sorted(groups.items())), "objects": objects}


def identity(value):
    match = re.match(r"^(.*) <(.*)> (\d+) ([+-]\d{4})$", value or "")
    if not match:
        return {"raw": value}
    name, email, epoch, tz = match.groups()
    offset = (1 if tz[0] == "+" else -1) * (int(tz[1:3]) * 60 + int(tz[3:]))
    when = datetime.fromtimestamp(int(epoch), timezone(timedelta(minutes=offset)))
    return {"name": name, "email": email, "date": when.isoformat()}


def leads(where, text):
    return [{"where": where, "line": line.strip()} for line in text.splitlines() if LEADS.search(line)]


def describe(sha, raw):
    if raw is None:
        return {"sha": sha, "missing": True}
    text = raw.decode("utf-8", errors="replace")
    head, _, message = text.partition("\n\n")
    fields = {"parents": []}
    for line in head.split("\n"):
        key, _, value = line.partition(" ")
        if key == "parent":
            fields["parents"].append(value)
        elif key in ("tree", "author", "committer"):
            fields[key] = value
    paragraphs = message.rstrip("\n").split("\n\n")
    last = paragraphs[-1].splitlines() if len(paragraphs) > 1 else []
    trailers = [{"key": m[1], "value": m[2]} for m in map(TRAILER.match, last) if m]
    trailers += [{"key": m[1], "value": m[2]} for line in message.splitlines()
                 if (m := TRAILER.match(line.strip())) and m[1].lower() == "co-authored-by"
                 and {"key": m[1], "value": m[2]} not in trailers]
    author, committer = identity(fields.get("author")), identity(fields.get("committer"))
    found = leads("author", fields.get("author", "")) + leads("committer", fields.get("committer", ""))
    return {"sha": sha, "tree": fields.get("tree"), "parents": fields["parents"], "author": author,
            "committer": committer, "subject": message.split("\n", 1)[0], "message": message,
            "trailers": trailers, "marker_leads": found + leads("message", message)}


def commits(repo, shas):
    raws = read_objects(repo, shas)
    return [describe(sha, raws.get(sha)) for sha in shas]


def brief(info):
    return {"sha": info["sha"], "subject": info.get("subject"),
            "author": info.get("author"), "committer_date": (info.get("committer") or {}).get("date"),
            "parents": info.get("parents"), "marker_leads": info.get("marker_leads", [])}


def text_matches(pattern, blobs):
    matched, unreadable = set(), set()
    for oid, data in blobs.items():
        if data is None:
            unreadable.add(oid)
        elif pattern.search(data.decode("utf-8", errors="replace")):
            matched.add(oid)
    return matched, unreadable


def cmd_commit(args):
    shas = [commit_sha(args.repo, ref) for ref in args.sha]
    result = commits(args.repo, shas)
    summary = [{"sha": c["sha"], "author": c["author"], "subject": c["subject"],
                "trailers": c["trailers"], "marker_leads": c["marker_leads"]} for c in result]
    return {"commits": result}, None, summary


def cmd_parent_diff(args):
    sha = commit_sha(args.repo, args.sha)
    info = commits(args.repo, [sha])[0]
    parents = info["parents"] or [None]
    comparisons, raw = [], []
    for parent in parents:
        if args.path:
            paths = args.path
        else:
            listing = git(args.repo, "diff-tree", "-r", "--root", "--no-commit-id", "--name-only",
                          *([parent, sha] if parent else [sha]))
            paths = [p for p in listing.splitlines() if p]
        child = [blob_at(args.repo, [sha], p)[0] for p in paths]
        before = [blob_at(args.repo, [parent], p)[0] for p in paths] if parent else [None] * len(paths)
        comparisons.append({"parent": parent, "paths": [
            {"path": p, "in_parent": b is not None, "in_child": c is not None,
             "parent_blob": b, "child_blob": c, "changed": b != c}
            for p, b, c in zip(paths, before, child)]})
        try:
            diff = (git(args.repo, "diff", parent, sha, "--", *args.path) if parent
                    else git(args.repo, "diff-tree", "-p", "--root", sha, "--", *args.path))
        except ToolError as exc:
            diff = (f"(diff unavailable: {exc}; the blobs are not local - rerun with --fetch-missing "
                    "in your own scratch clone)\n")
            comparisons[-1]["diff_unavailable"] = True
        raw.append(f"### {parent or '(root)'} -> {sha}\n{diff}")
    summary = [{"parent": c["parent"], "paths": [{k: p[k] for k in ("path", "in_parent", "in_child", "changed")}
                                                for p in c["paths"]]} for c in comparisons]
    return {"commit": brief(info), "comparisons": comparisons}, "\n".join(raw), summary


def branch_tip(repo, name):
    for ref in (name, f"refs/heads/{name}", f"refs/remotes/origin/{name}"):
        oid = resolve(repo, [f"{ref}^{{commit}}"])[0]
        if oid:
            return ref, oid
    raise ToolError(f"branch {name} not found in {repo}")


def first_content(repo, chain, path, target, pattern):
    oids = blob_at(repo, chain, path)
    if pattern:
        matched, unreadable = text_matches(pattern, read_objects(repo, [o for o in set(oids) if o]))
    else:
        matched, unreadable = {target} if target else set(), set()
    for index, oid in enumerate(oids):
        if oid in matched:
            return index, oid, sorted(unreadable), sum(1 for o in oids[:index] if o in unreadable)
    return None, None, sorted(unreadable), sum(1 for o in oids if o in unreadable)


def pattern_specificity(repo, sha, path, pattern):
    info = commits(repo, [sha])[0]
    parent = (info.get("parents") or [None])[0]
    child = blob_at(repo, [sha], path)[0]
    before = blob_at(repo, [parent], path)[0] if parent else None
    blobs = read_objects(repo, [b for b in (child, before) if b])

    def matches(blob):
        if blob is None:
            return False
        data = blobs.get(blob)
        return None if data is None else bool(pattern.search(data.decode("utf-8", errors="replace")))
    result = {"commit_matches": matches(child), "parent": parent, "parent_matches": matches(before)}
    if result["parent_matches"]:
        result["warning"] = "the pattern already matches the parent, so it does not isolate this change"
    elif result["commit_matches"] is False:
        result["warning"] = "the pattern does not match the commit itself"
    return result


def cmd_landing(args):
    sha = commit_sha(args.repo, args.sha)
    pattern = re.compile(args.pattern) if args.pattern else None
    targets = {p: blob_at(args.repo, [sha], p)[0] for p in args.path}
    results = []
    for name in args.branch:
        ref, tip = branch_tip(args.repo, name)
        chain = git(args.repo, "rev-list", "--first-parent", "--reverse", tip).split()
        entry = {"branch": name, "ref": ref, "tip": tip, "first_parent_length": len(chain),
                 "on_first_parent": sha in set(chain), "ancestry_landing": None, "content_landing": []}
        if not entry["on_first_parent"] and is_ancestor(args.repo, sha, tip):
            lo, hi = 0, len(chain) - 1
            while lo < hi:
                mid = (lo + hi) // 2
                if is_ancestor(args.repo, sha, chain[mid]):
                    hi = mid
                else:
                    lo = mid + 1
            landing = commits(args.repo, [chain[lo]])[0]
            entry["ancestry_landing"] = {**brief(landing), "first_parent_index": lo,
                                         "first_parent_contains": False if lo == 0 else
                                         is_ancestor(args.repo, sha, landing["parents"][0])}
        for path in args.path:
            index, oid, unreadable, unknown = first_content(args.repo, chain, path, targets[path], pattern)
            found = {"path": path, "match": "pattern" if pattern else "child_blob",
                     "target_blob": None if pattern else targets[path], "unreadable_blobs": unreadable,
                     "unreadable_states_before": unknown,
                     "landing": None}
            if pattern:
                found["pattern_check"] = pattern_specificity(args.repo, sha, path, pattern)
            if index is not None:
                found["landing"] = {**brief(commits(args.repo, [chain[index]])[0]),
                                    "first_parent_index": index, "blob": oid}
            entry["content_landing"].append(found)
        results.append(entry)
    summary = [{"branch": e["branch"], "on_first_parent": e["on_first_parent"],
                "ancestry_landing": (e["ancestry_landing"] or {}).get("sha"),
                "content_landing": {c["path"]: (c["landing"] or {}).get("sha") for c in e["content_landing"]}}
               for e in results]
    return {"commit": sha, "branches": results}, None, summary


def boundaries(rows, key):
    lines = defaultdict(list)
    for row in rows:
        lines[row["line"]].append(row)
    out = {}
    for line, members in lines.items():
        first = next((i for i, r in enumerate(members) if r[key]), None)
        before = members if first is None else members[:first]
        known = [r for r in before if r[key] is False]
        out[line] = {"tags": len(members), "latest": members[-1]["tag"],
                     "first_with": None if first is None else members[first]["tag"],
                     "last_without": known[-1]["tag"] if known else None,
                     "unknown": [r["tag"] for r in members if r[key] is None],
                     "without_after_first": [] if first is None else
                     [r["tag"] for r in members[first + 1:] if r[key] is False]}
    return out


def cmd_releases(args):
    sha = commit_sha(args.repo, args.commit) if args.commit else None
    pattern = re.compile(args.pattern) if args.pattern else None
    listing = git(args.repo, "for-each-ref", "--sort=version:refname",
                  "--format=%(refname:short)%09%(creatordate:iso-strict)", "refs/tags").splitlines()
    tags = [line.split("\t") for line in listing if line]
    peeled = resolve(args.repo, [f"refs/tags/{t}^{{commit}}" for t, _ in tags])
    contains = set(git(args.repo, "for-each-ref", "--contains", sha, "--format=%(refname:short)",
                       "refs/tags").split()) if sha else set()
    blob = args.blob or (blob_at(args.repo, [sha], args.path)[0] if sha and args.path else None)
    content = {}
    unreadable = []
    if args.path:
        found = iter(blob_at(args.repo, [c for c in peeled if c], args.path))
        oids = [next(found) if c else None for c in peeled]
        if pattern:
            matched, unreadable = text_matches(pattern, read_objects(args.repo, [o for o in set(oids) if o]))
        else:
            matched = {blob} if blob else set()
        content = {t: (oid, None if oid in unreadable else oid in matched) for (t, _), oid in zip(tags, oids)}
    published = {}
    if args.github:
        for item in run_gh(["api", f"repos/{args.github}/releases", "--paginate", "--jq",
                            ".[] | {tag_name, prerelease, draft, published_at, created_at}"], lines=True):
            published[item["tag_name"]] = item
    rows = []
    for (tag, created), commit in zip(tags, peeled):
        nums = re.findall(r"\d+", tag)
        row = {"tag": tag, "commit": commit, "created": created, "line": ".".join(nums[:args.line_depth]) or tag,
               "prerelease": bool(PRERELEASE.search(tag)), "contains_commit": tag in contains if sha else None}
        if args.path:
            row["blob"], row["carries"] = content[tag]
        if args.github:
            row["github_release"] = published.get(tag)
        rows.append(row)
    result = {"commit": sha, "path": args.path, "blob": None if pattern else blob,
              "pattern": args.pattern, "unreadable_blobs": sorted(unreadable), "tags": rows}
    summary = {}
    if sha and pattern and args.path:
        result["pattern_check"] = summary["pattern_check"] = pattern_specificity(args.repo, sha, args.path, pattern)
    if sha:
        result["by_ancestry"] = summary["by_ancestry"] = boundaries(rows, "contains_commit")
    if args.path:
        result["by_content"] = summary["by_content"] = boundaries(rows, "carries")
    return result, None, summary


def discover_paths(repo, universe, blobs):
    proc = subprocess.Popen(["git", "-C", str(repo), "log", "--no-walk", "--stdin", "--root", "--no-renames",
                             "--diff-merges=separate", "--raw", "--no-abbrev", "--format="],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    feeder = threading.Thread(target=lambda: (proc.stdin.write(("\n".join(universe) + "\n").encode()),
                                                            proc.stdin.close()))
    feeder.start()
    targets = {b.encode() for b in blobs}
    paths = set()
    for line in proc.stdout:
        if line.startswith(b":"):
            meta, _, path = line.rstrip(b"\n").partition(b"\t")
            if targets & set(meta.split()[2:4]):
                paths.add(path.decode("utf-8", errors="replace"))
    feeder.join()
    error = proc.stderr.read().decode(errors="replace")
    if proc.wait():
        raise ToolError(f"git log --raw: {error.strip()[:500]}")
    return paths


def cmd_carriers(args):
    blobs = list(dict.fromkeys(args.blob))
    for blob in blobs:
        if not SHA40.match(blob):
            raise ToolError(f"--blob needs a full 40-hex object id: {blob}")
    if not blobs and not (args.pattern and args.path):
        raise ToolError("give --blob, or --pattern with --path")
    pattern = re.compile(args.pattern) if args.pattern else None
    listing = git(args.repo, "cat-file", "--batch-all-objects", "--unordered",
                  "--batch-check=%(objectname) %(objecttype)")
    universe = [line.split()[0] for line in listing.splitlines() if line.endswith(" commit")]
    reachable = set(git(args.repo, "rev-list", "--all").split())
    discovered = discover_paths(args.repo, universe, blobs) if blobs else set()
    paths = list(dict.fromkeys([*args.path, *sorted(discovered)]))
    hits = []
    for path in paths:
        hits += [(c, path, oid) for c, oid in zip(universe, blob_at(args.repo, universe, path)) if oid]
    matched, unreadable = set(blobs), set()
    if pattern:
        found, unreadable = text_matches(pattern, read_objects(args.repo, [o for o in {h[2] for h in hits} if o not in matched]))
        matched |= found
    carriers = [(c, p, oid) for c, p, oid in hits if oid in matched]
    info = {c["sha"]: c for c in commits(args.repo, list(dict.fromkeys(c for c, _, _ in carriers)))}
    rows = []
    for commit, path, oid in carriers:
        meta = info[commit]
        rows.append({"commit": commit, "path": path, "blob": oid,
                     "match": "exact" if oid in blobs else "pattern", "reachable": commit in reachable,
                     "tree": meta.get("tree"), "parents": meta.get("parents"), "author": meta.get("author"),
                     "committer": meta.get("committer"), "subject": meta.get("subject"),
                     "trailers": meta.get("trailers"), "marker_leads": meta.get("marker_leads")})
    rows.sort(key=lambda r: ((r["committer"] or {}).get("date") or "", r["commit"], r["path"]))
    by_tree = defaultdict(set)
    for row in rows:
        by_tree[row["tree"]].add(row["commit"])
    state = repo_state(args.repo)
    gaps = []
    if state["is_shallow"]:
        gaps.append("shallow clone: commits beyond the shallow boundary are not local")
    if unreadable:
        gaps.append(f"{len(unreadable)} blobs at these paths are not local, so the pattern could not be read")
    gaps.append("covers local objects only; an object this clone never fetched (for example a "
                "pre-force-push PR head the host no longer serves) is outside the inventory")
    result = {"blobs": blobs, "pattern": args.pattern, "paths": {"given": args.path, "discovered": sorted(discovered)},
              "universe": {"commits": len(universe), "reachable": len(reachable & set(universe)),
                           "unreachable": len(set(universe) - reachable)},
              "carriers": rows, "commits_by_root_tree": {t: sorted(c) for t, c in sorted(by_tree.items())},
              "unreadable_blobs": sorted(unreadable),
              "completeness": {"complete_for_local_objects": not state["is_shallow"] and not unreadable,
                               "limits": gaps}}
    summary = {"universe": result["universe"], "paths": result["paths"],
               "carrier_commits": len({r["commit"] for r in rows}),
               "carriers": [{"commit": r["commit"][:12], "path": r["path"], "match": r["match"],
                             "reachable": r["reachable"], "author": (r["author"] or {}).get("name"),
                             "marker_leads": len(r["marker_leads"] or [])} for r in rows],
               "completeness": result["completeness"]}
    return result, None, summary


def run_gh(argv, lines=False):
    proc = subprocess.run(["gh", *argv], capture_output=True, text=True)
    if proc.returncode:
        raise ToolError(f"gh {' '.join(argv[:2])}: {proc.stderr.strip()[:300]}")
    if lines:
        return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def cmd_github(args):
    responses = {}
    if args.what == "pr":
        numbers = list(args.number)
        if args.commit:
            pulls = run_gh(["api", f"repos/{args.slug}/commits/{args.commit}/pulls"])
            responses[f"commits/{args.commit}/pulls"] = pulls
            numbers += [p["number"] for p in pulls or [] if p["number"] not in numbers]
        prs = []
        for number in numbers:
            pull = run_gh(["api", f"repos/{args.slug}/pulls/{number}"])
            members = run_gh(["api", f"repos/{args.slug}/pulls/{number}/commits", "--paginate", "--jq",
                              ".[] | {sha, login: .author.login, author: .commit.author, "
                              "committer: .commit.committer, message: .commit.message}"], lines=True)
            responses[f"pulls/{number}"], responses[f"pulls/{number}/commits"] = pull, members
            body = pull.get("body") or ""
            prs.append({"number": number, "title": pull.get("title"), "state": pull.get("state"),
                        "user": (pull.get("user") or {}).get("login"), "created_at": pull.get("created_at"),
                        "merged_at": pull.get("merged_at"), "merge_commit_sha": pull.get("merge_commit_sha"),
                        "base": (pull.get("base") or {}).get("ref"), "head": (pull.get("head") or {}).get("ref"),
                        "body": body, "body_leads": leads("body", body) + leads("title", pull.get("title") or ""),
                        "members": [{"sha": m["sha"], "login": m.get("login"), "author": m.get("author"),
                                     "subject": (m.get("message") or "").split("\n", 1)[0],
                                     "marker_leads": leads("message", m.get("message") or "")} for m in members]})
        result = {"slug": args.slug, "commit": args.commit, "pulls": prs}
        summary = [{"number": p["number"], "merged_at": p["merged_at"], "merge_commit_sha": p["merge_commit_sha"],
                    "members": len(p["members"]), "body_leads": p["body_leads"]} for p in prs]
    else:
        keep = ("{ghsa_id, cve_id, summary, state, severity, published_at, updated_at, withdrawn_at, "
                "html_url, vulnerabilities}")
        repo_advisories = run_gh(["api", f"repos/{args.slug}/security-advisories", "--paginate",
                                  "--jq", f".[] | {keep}"], lines=True)
        responses["security-advisories"] = repo_advisories
        global_advisories = []
        if args.package:
            ecosystem, _, name = args.package.partition(":")
            global_advisories = run_gh(["api", "-X", "GET", "advisories", "-f", f"ecosystem={ecosystem}",
                                        "-f", f"affects={name}", "-f", "per_page=100", "--paginate",
                                        "--jq", f".[] | {keep}"], lines=True)
            responses["advisories"] = global_advisories
        result = {"slug": args.slug, "repository_advisories": repo_advisories,
                  "global_advisories": global_advisories}
        summary = [{"ghsa_id": a.get("ghsa_id"), "cve_id": a.get("cve_id"), "published_at": a.get("published_at"),
                    "withdrawn_at": a.get("withdrawn_at"), "summary": a.get("summary")}
                   for a in [*repo_advisories, *global_advisories]]
    return result, json.dumps(responses, indent=1, ensure_ascii=False), summary


def fetch_url(url):
    if FETCH:
        return FETCH(url)
    with urlopen(Request(url, headers={"User-Agent": "radar-git"}), timeout=120) as response:
        return response.read()


def registry_files(registry, package, version):
    if registry == "pypi":
        meta = json.loads(fetch_url(f"https://pypi.org/pypi/{package}/{version}/json"))
        return [{"filename": f["filename"], "url": f["url"], "kind": f["packagetype"],
                 "published": f.get("upload_time_iso_8601"), "algorithm": "sha256",
                 "expected": f["digests"]["sha256"]} for f in meta["urls"]]
    if registry == "npm":
        meta = json.loads(fetch_url(f"https://registry.npmjs.org/{quote(package, safe='@')}/{version}"))
        dist = meta["dist"]
        algorithm, _, value = dist["integrity"].partition("-")
        return [{"filename": dist["tarball"].rsplit("/", 1)[1], "url": dist["tarball"], "kind": "tarball",
                 "published": None, "algorithm": algorithm,
                 "expected": base64.b64decode(value).hex()}]
    meta = json.loads(fetch_url(f"https://rubygems.org/api/v2/rubygems/{package}/versions/{version}.json"))
    platform = meta.get("platform") or "ruby"
    filename = f"{package}-{version}.gem" if platform == "ruby" else f"{package}-{version}-{platform}.gem"
    return [{"filename": filename, "url": f"https://rubygems.org/downloads/{filename}", "kind": "gem",
             "published": meta.get("created_at"), "algorithm": "sha256", "expected": meta["sha"]}]


def archive_members(filename, data):
    if filename.endswith((".whl", ".zip", ".egg")):
        archive = zipfile.ZipFile(io.BytesIO(data))
        return [(i.filename, i.file_size, lambda i=i: archive.read(i)) for i in archive.infolist() if not i.is_dir()]
    archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    if filename.endswith(".gem"):
        inner = archive.extractfile("data.tar.gz").read()
        archive = tarfile.open(fileobj=io.BytesIO(inner), mode="r:gz")
    return [(m.name, m.size, lambda m=m: archive.extractfile(m).read()) for m in archive.getmembers() if m.isfile()]


def cmd_artifact(args):
    pattern = re.compile(args.pattern) if args.pattern else None
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    versions = []
    for version in args.version:
        files = []
        for item in registry_files(args.registry, args.package, version):
            if args.kind != "all" and item["kind"] != args.kind:
                continue
            data = fetch_url(item["url"])
            (dest / item["filename"]).write_bytes(data)
            actual = hashlib.new(item["algorithm"], data).hexdigest()
            members = archive_members(item["filename"], data)
            selected = [m for m in members if not args.glob or any(fnmatch.fnmatch(m[0], g) for g in args.glob)]
            matches = []
            if pattern:
                for name, size, read in selected:
                    if size > MAX_MEMBER:
                        continue
                    text = read().decode("utf-8", errors="replace")
                    lines = [n for n, line in enumerate(text.splitlines(), 1) if pattern.search(line)]
                    if lines:
                        matches.append({"member": name, "lines": lines[:50]})
            files.append({**item, "saved": str(dest / item["filename"]), "size": len(data),
                          "actual": actual, "digest_ok": actual == item["expected"],
                          "members_total": len(members), "glob_matches": [m[0] for m in selected] if args.glob else None,
                          "pattern_matches": matches if pattern else None})
        versions.append({"version": version, "files": files})
    summary = [{"version": v["version"], "files": [
        {"filename": f["filename"], "digest_ok": f["digest_ok"],
         "glob_matches": None if f["glob_matches"] is None else len(f["glob_matches"]),
         "pattern_members": None if f["pattern_matches"] is None else [m["member"] for m in f["pattern_matches"]]}
        for f in v["files"]]} for v in versions]
    return {"registry": args.registry, "package": args.package, "glob": args.glob,
            "pattern": args.pattern, "versions": versions}, None, summary


def write_receipt(out, name, body, raw):
    out.mkdir(parents=True, exist_ok=True)
    path, n = out / f"{name}.json", 1
    while path.exists():
        n += 1
        path = out / f"{name}-{n}.json"
    if raw is not None:
        raw_path = path.with_suffix(".txt")
        raw_path.write_text(raw, encoding="utf-8")
        body["raw"] = {"path": raw_path.name, "sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest()}
    path.write_text(json.dumps(body, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", required=True, type=Path, help="directory for the receipt (your evidence/)")
    common.add_argument("--name", help="receipt file name without extension")
    common.add_argument("--fetch-missing", action="store_true",
                        help="let git fetch objects a partial clone lacks; only in your own scratch clone")
    top = argparse.ArgumentParser(description="Deterministic history, release, carrier, PR and package queries with receipts")
    sub = top.add_subparsers(dest="command", required=True)

    p = sub.add_parser("commit", parents=[common], help="full metadata, trailers and AI-marker leads of commits")
    p.add_argument("--repo", required=True)
    p.add_argument("sha", nargs="+")

    p = sub.add_parser("parent-diff", parents=[common], help="compare a commit with each parent")
    p.add_argument("--repo", required=True)
    p.add_argument("--path", action="append", default=[])
    p.add_argument("sha")

    p = sub.add_parser("landing", parents=[common], help="first first-parent commit of a branch that carries a commit")
    p.add_argument("--repo", required=True)
    p.add_argument("--branch", action="append", required=True)
    p.add_argument("--path", action="append", default=[], help="also match content at this path (squash, cherry-pick)")
    p.add_argument("--pattern", help="content regex instead of the commit's exact blob")
    p.add_argument("sha")

    p = sub.add_parser("releases", parents=[common], help="which tags contain a commit or carry content")
    p.add_argument("--repo", required=True)
    p.add_argument("--commit")
    p.add_argument("--path")
    p.add_argument("--blob")
    p.add_argument("--pattern")
    p.add_argument("--line-depth", type=int, default=2)
    p.add_argument("--github", metavar="OWNER/REPO", help="add GitHub release metadata")

    p = sub.add_parser("carriers", parents=[common], help="every local commit whose tree carries a blob or pattern")
    p.add_argument("--repo", required=True)
    p.add_argument("--blob", action="append", default=[])
    p.add_argument("--path", action="append", default=[])
    p.add_argument("--pattern")

    p = sub.add_parser("github", parents=[common], help="read-only GitHub PR and advisory queries")
    p.add_argument("what", choices=["pr", "advisories"])
    p.add_argument("--slug", required=True, metavar="OWNER/REPO")
    p.add_argument("--commit")
    p.add_argument("--number", type=int, action="append", default=[])
    p.add_argument("--package", metavar="ECOSYSTEM:NAME")

    p = sub.add_parser("artifact", parents=[common], help="download a published package, verify it, list members")
    p.add_argument("--registry", required=True, choices=["pypi", "npm", "rubygems"])
    p.add_argument("--package", required=True)
    p.add_argument("--version", action="append", required=True)
    p.add_argument("--dest", required=True, help="scratch directory for the downloaded files")
    p.add_argument("--kind", default="all")
    p.add_argument("--glob", action="append", default=[])
    p.add_argument("--pattern")
    return top


HANDLERS = {"commit": cmd_commit, "parent-diff": cmd_parent_diff, "landing": cmd_landing,
            "releases": cmd_releases, "carriers": cmd_carriers, "github": cmd_github, "artifact": cmd_artifact}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    args = parser().parse_args(argv)
    started = utc_now()
    keys = {"commit": lambda: args.sha[0], "parent-diff": lambda: args.sha, "landing": lambda: args.sha,
            "releases": lambda: args.commit or args.path or "tags",
            "carriers": lambda: (args.blob or [args.pattern or "pattern"])[0],
            "github": lambda: f"{args.what}-{args.commit or args.slug}", "artifact": lambda: args.package}
    key = re.sub(r"[^A-Za-z0-9._-]+", "-", str(keys[args.command]()))[:24]
    name = args.name or f"{args.command}-{key}-{started.replace(':', '').replace('-', '')}"
    body = {"schema": SCHEMA, "command": args.command, "argv": ["radar_git.py", *argv],
            "captured_utc": started, "repository": None, "exit": 0}
    try:
        if args.fetch_missing:
            allow_fetch(getattr(args, "repo", None))
        if getattr(args, "repo", None):
            body["repository"] = repo_state(args.repo)
        result, raw, summary = HANDLERS[args.command](args)
        body["summary"] = summary
        body["result"] = result
    except (ToolError, OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as exc:
        body.update(exit=1, error=f"{type(exc).__name__}: {exc}", summary=None)
        raw, summary = None, None
    body["finished_utc"] = utc_now()
    path = write_receipt(args.out, name, body, raw)
    print(json.dumps({"receipt": str(path), "exit": body["exit"], "error": body.get("error"),
                      "summary": summary}, indent=1, ensure_ascii=False))
    return body["exit"]


if __name__ == "__main__":
    sys.exit(main())
