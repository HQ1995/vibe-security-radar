#!/usr/bin/env python3
"""Independent git/advisory probe for redbase-odd. Does not assign verdicts."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

CACHE = Path("/home/hanqing/.cache/ghsa200-worker-clones/redbase-odd")
CLONES = CACHE / "clones"
PAGES = CACHE / "pages"
NOTES = CACHE / "notes"
HYPO = Path(
    "/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-redbase-odd/hypotheses"
)
AI_RE = re.compile(
    r"co-authored-by:.*(claude|copilot|codex|gpt|cursor|gemini|anthropic)|"
    r"generated with (claude|copilot|cursor)|"
    r"Made-with:\s*Cursor|"
    r"openai|copilot-swe-agent|github-copilot",
    re.I,
)


def run(repo: Path, args: list[str], timeout: int = 60) -> tuple[int, str]:
    r = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    return r.returncode, out.strip()


def short(text: str, n: int = 4000) -> str:
    return text if len(text) <= n else text[:n] + "\n...[truncated]..."


def ancestor(repo: Path, commit: str, spec: str) -> str | None:
    if not commit or not spec:
        return None
    code, _ = run(repo, ["merge-base", "--is-ancestor", commit, spec])
    if code == 0:
        return "yes"
    if code == 1:
        return "no"
    return f"err:{code}"


def tag_sha(repo: Path, tag: str) -> str:
    code, out = run(repo, ["rev-parse", tag])
    return out if code == 0 else f"MISSING:{out}"


def commit_meta(repo: Path, sha: str) -> dict:
    code, out = run(
        repo,
        [
            "show",
            "--no-patch",
            "--format=%H%n%an <%ae>%n%cn <%ce>%n%ad%n%s%n%b",
            sha,
        ],
    )
    if code != 0:
        return {"error": out, "sha": sha}
    lines = out.splitlines()
    body = "\n".join(lines[5:])
    return {
        "sha": lines[0] if lines else sha,
        "author": lines[1] if len(lines) > 1 else "",
        "committer": lines[2] if len(lines) > 2 else "",
        "date": lines[3] if len(lines) > 3 else "",
        "subject": lines[4] if len(lines) > 4 else "",
        "body": body[:2500],
        "ai_marker": bool(AI_RE.search(out)),
        "ai_hits": sorted(set(AI_RE.findall(out)))[:12],
    }


def stat(repo: Path, sha: str) -> str:
    _, out = run(repo, ["show", "--stat", "--format=", sha])
    return short(out, 2500)


CASES = [
    {
        "ordinal": 19,
        "clone": "ebay-mcp",
        "files": ["src/utils.ts", "src/index.ts"],
        "vuln": "v1.7.2",
        "fixed": "v1.7.3",
        "grep": r"updateEnvFile|dotenv.parse",
    },
    {
        "ordinal": 23,
        "clone": "openclaw",
        "files": [],
        "vuln": "v2026.2.24",
        "fixed": "v2026.2.25",
        "grep": r"trustedProxyAuthOk|operator",
    },
    {
        "ordinal": 27,
        "clone": "zeptoclaw",
        "files": ["src/channels/webhook.rs"],
        "vuln": "v0.7.5",
        "fixed": "v0.7.6",
        "grep": r"WebhookPayload|auth_token|payload.sender",
    },
    {
        "ordinal": 39,
        "clone": "coolify",
        "files": ["app/Livewire/Settings/Index.php"],
        "vuln": "v4.0.0-beta.447",
        "fixed": "v4.0.0-beta.474",
        "grep": r"buildHelperImage|dev_helper_version",
    },
    {
        "ordinal": 43,
        "clone": "agentic-flow",
        "files": [],
        "vuln": None,
        "fixed": None,
        "grep": r"execSync",
        "npm_vuln": "2.0.13",
        "npm_fixed": "2.0.14",
    },
    {
        "ordinal": 49,
        "clone": "zae-limiter",
        "files": [],
        "vuln": "v0.10.0",
        "fixed": "v0.10.1",
        "grep": r"partition|entity",
    },
    {
        "ordinal": 57,
        "clone": "mail-mcp-bridge",
        "files": [],
        "vuln": "v1.1.0",
        "fixed": "1.3.4",
        "grep": r"message_id|rmtree|strip",
    },
    {
        "ordinal": 63,
        "clone": "openclaw",
        "files": [],
        "vuln": "v2026.2.13",
        "fixed": "v2026.2.14",
        "grep": r"add-generic-password|execSync|security ",
    },
    {
        "ordinal": 65,
        "clone": "openclaw",
        "upstream": "clawdbot-feishu",
        "files": ["extensions/feishu/src/bot.ts", "src/bot.ts"],
        "vuln": "v2026.2.17",
        "fixed": "v2026.2.19",
        "grep": r"new RegExp|escapeRegExp|stripBotMention",
    },
    {
        "ordinal": 73,
        "clone": "misp",
        "files": [],
        "vuln": "v2.5.37",
        "fixed": "v2.5.39",
        "grep": r"EventTemplateImporter|overwrite",
    },
    {
        "ordinal": 81,
        "clone": "openclaw",
        "files": [],
        "vuln": "v2026.2.1",
        "fixed": "v2026.2.2",
        "grep": r"hasTokenAuth|sharedAuthOk",
    },
    {
        "ordinal": 111,
        "clone": "bsv-ruby-sdk",
        "files": [],
        "vuln": "v0.8.1",
        "fixed": "v0.8.2",
        "grep": r"INVALID|MALFORMED|ORPHAN|ARC",
    },
    {
        "ordinal": 119,
        "clone": "openclaw",
        "files": [],
        "vuln": "v2026.1.20",
        "fixed": "v2026.2.24",
        "grep": r"workspaceOnly|detectAndLoadPromptImages|loadImageFromRef",
    },
    {
        "ordinal": 135,
        "clone": "fireshare",
        "files": [],
        "vuln": "v1.5.2",
        "fixed": "v1.5.3",
        "grep": r"checkSum|secure_filename",
    },
    {
        "ordinal": 137,
        "clone": "vm2",
        "files": [],
        "vuln": "v3.11.3",
        "fixed": "v3.11.4",
        "grep": r"nesting|require",
    },
    {
        "ordinal": 147,
        "clone": "n8n-mcp",
        "files": ["src/utils/ssrf-protection.ts"],
        "vuln": "v2.47.13",
        "fixed": "v2.47.14",
        "grep": r"validateUrlSync|IPv6",
    },
    {
        "ordinal": 161,
        "clone": "locutus",
        "files": ["src/php/strings/parse_str.js"],
        "vuln": "v2.0.39",
        "fixed": "v3.0.25",
        "grep": r"__proto__|RegExp.prototype|parse_str",
    },
    {
        "ordinal": 163,
        "clone": "scriban",
        "files": [],
        "vuln": "7.2.0",
        "fixed": "7.2.1",
        "grep": r"LoopLimit|TryEvaluate",
    },
    {
        "ordinal": 167,
        "clone": "scriban",
        "files": [],
        "vuln": "7.2.0",
        "fixed": "7.2.1",
        "grep": r"EnterExpression|ExpressionDepthLimit",
    },
    {
        "ordinal": 171,
        "clone": "GitPython",
        "files": ["git/config.py"],
        "vuln": "3.1.49",
        "fixed": "3.1.50",
        "grep": r"_value_to_string_safe|section",
    },
    {
        "ordinal": 179,
        "clone": "GitPython",
        "files": ["git/repo/base.py"],
        "vuln": "3.1.58",
        "fixed": "3.1.59",
        "grep": r"unsafe_git_revision_options|--contents|blame",
    },
    {
        "ordinal": 185,
        "clone": "churchcrm",
        "files": [],
        "vuln": "7.5.1",
        "fixed": "7.6.0",
        "grep": r"data-person_name|escapeHtml",
    },
]


def main() -> None:
    NOTES.mkdir(parents=True, exist_ok=True)
    for spec in CASES:
        o = spec["ordinal"]
        hypo = json.loads((HYPO / f"ordinal-{o}.json").read_text())
        repo = CLONES / spec["clone"]
        cands = hypo["candidate_set"] or []
        carriers = hypo["carrier_set"] or []
        fixes = hypo["minimum_fix_set"] or []
        rec: dict = {
            "ordinal": o,
            "clone": spec["clone"],
            "head": run(repo, ["rev-parse", "HEAD", "--abbrev-ref", "HEAD"])[1],
            "candidates": {},
            "carriers": {},
            "fixes": {},
            "ancestry": {},
            "tags": {},
        }
        for sha in cands:
            rec["candidates"][sha] = {
                "meta": commit_meta(repo, sha),
                "stat": stat(repo, sha),
            }
            if spec.get("upstream"):
                urepo = CLONES / spec["upstream"]
                rec["candidates"][sha]["upstream_meta"] = commit_meta(urepo, sha)
                rec["candidates"][sha]["upstream_stat"] = stat(urepo, sha)
        for sha in carriers:
            rec["carriers"][sha] = {
                "meta": commit_meta(repo, sha),
                "stat": stat(repo, sha),
            }
        for sha in fixes:
            rec["fixes"][sha] = {
                "meta": commit_meta(repo, sha),
                "stat": stat(repo, sha),
            }
        vuln = spec.get("vuln")
        fixed = spec.get("fixed")
        if vuln:
            rec["tags"]["vuln"] = {"name": vuln, "sha": tag_sha(repo, vuln)}
        if fixed:
            rec["tags"]["fixed"] = {"name": fixed, "sha": tag_sha(repo, fixed)}
        for label, shas in (
            ("cand", cands),
            ("carrier", carriers),
            ("fix", fixes),
        ):
            for sha in shas:
                if vuln:
                    rec["ancestry"][f"{label}:{sha[:8]} in {vuln}"] = ancestor(
                        repo, sha, vuln
                    )
                if fixed:
                    rec["ancestry"][f"{label}:{sha[:8]} in {fixed}"] = ancestor(
                        repo, sha, fixed
                    )
        # parent of first candidate
        if cands:
            sha = cands[0]
            probe_repo = CLONES / spec["upstream"] if spec.get("upstream") else repo
            _, parent = run(probe_repo, ["rev-parse", f"{sha}^"])
            rec["candidate_parent"] = parent
            grep = spec.get("grep")
            if grep:
                _, g1 = run(probe_repo, ["grep", "-nE", grep, sha])
                rec["grep_candidate"] = short(g1, 3000)
                if parent and not parent.startswith("fatal"):
                    _, g0 = run(probe_repo, ["grep", "-nE", grep, parent])
                    rec["grep_parent"] = short(g0, 2000)
            if spec.get("files"):
                for f in spec["files"]:
                    _, pblob = run(probe_repo, ["rev-parse", f"{parent}:{f}"])
                    _, cblob = run(probe_repo, ["rev-parse", f"{sha}:{f}"])
                    rec.setdefault("blobs", {})[f] = {
                        "parent": pblob,
                        "candidate": cblob,
                    }
        # extra: list tags matching versions for npm cases
        if spec.get("npm_vuln"):
            _, tags = run(repo, ["tag", "--list", f"*{spec['npm_vuln']}*"])
            rec["npm_tag_guess"] = tags
        outp = NOTES / f"probe-{o}.json"
        outp.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n")
        print("wrote", outp, "ai", [
            rec["candidates"][s]["meta"].get("ai_marker")
            or rec["candidates"][s].get("upstream_meta", {}).get("ai_marker")
            for s in rec["candidates"]
        ])


if __name__ == "__main__":
    main()
