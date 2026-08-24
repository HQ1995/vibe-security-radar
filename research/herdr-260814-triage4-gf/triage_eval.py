import json
import re

slice_path = "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-triage-slice-4.jsonl"
out_jsonl = "autoresearch/herdr-260814-triage4-gf/triage.jsonl"
out_summary = "autoresearch/herdr-260814-triage4-gf/summary.txt"

with open(slice_path, "r", encoding="utf-8") as f:
    rows = [json.loads(line) for line in f if line.strip()]

SEC_RE = re.compile(
    r"(security|vuln|auth|token|jwt|session|cookie|cors|csrf|sanitiz|escape|inject|exec|command|shell|"
    r"path|traversal|ssrf|xss|sql|leak|secret|crypto|cipher|password|permission|acl|bypass|privilege|"
    r"overflow|rce|upload|deserialize|eval|cert|ssl|tls|proxy|boundary|untrusted|redirect|sandbox|"
    r"gateway|header|filter|check|verify|validat|parser|endpoint|route|access|exposure|unauthorized)",
    re.I
)

TRIVIAL_RE = re.compile(
    r"^(chore|docs|doc|bump|ci|style|format|formatting|typo|translation|i18n|l10n|test|tests|refactor(types)|trivial)",
    re.I
)

results = []
counts = {"KEEP": 0, "DROP": 0, "UNCERTAIN": 0}

for r in rows:
    ghsa = r["ghsa"]
    repo = r["repo"]
    summary = r.get("summary", "").strip()
    commits = r.get("recent_ai_commits", [])
    
    candidate_shas = []
    reasons = []
    
    if summary:
        summary_words = set(re.findall(r"w{4,}", summary.lower()))
        for c in commits:
            subj = c.get("subject", "")
            files_str = " ".join(c.get("files", []))
            combined_text = f"{subj} {files_str}".lower()
            overlap = [w for w in summary_words if w in combined_text]
            if overlap or SEC_RE.search(subj):
                candidate_shas.append(c["sha"])
                overlap_str = ",".join(overlap[:3])
                reasons.append(f"{c['sha'][:8]}: overlaps summary keywords ({overlap_str})")
        if candidate_shas:
            verdict = "KEEP"
            reason = f"Candidate commits overlap advisory mechanism: {reasons[0]}"
        else:
            verdict = "DROP"
            reason = "No candidate commits overlap summary mechanism."
    else:
        for c in commits:
            subj = c.get("subject", "")
            files_str = " ".join(c.get("files", []))
            if SEC_RE.search(subj) or SEC_RE.search(files_str):
                candidate_shas.append(c["sha"])
                reasons.append(f"{c['sha'][:8]}: touches security/auth/validation/routing ({subj[:40]})")
        
        if candidate_shas:
            verdict = "KEEP"
            reason = reasons[0]
        else:
            non_trivial = []
            for c in commits:
                subj = c.get("subject", "").strip()
                files = [f.lower() for f in c.get("files", [])]
                is_trivial_files = all(
                    f.startswith((".github", "docs", "doc/", "readme", "license", "changes", ".gitignore", "test", "tests"))
                    for f in files
                )
                is_trivial_subj = bool(TRIVIAL_RE.search(subj))
                if not (is_trivial_files or is_trivial_subj):
                    non_trivial.append(c)
            
            if not non_trivial:
                verdict = "DROP"
                reason = "All commits are maintenance/docs/CI/tests or trivial refactoring."
            else:
                verdict = "UNCERTAIN"
                candidate_shas = [c["sha"] for c in non_trivial[:3]]
                reason = f"No summary provided; non-trivial changes in {non_trivial[0]['sha'][:8]} ({non_trivial[0]['subject'][:40]})."
                
    counts[verdict] += 1
    results.append({
        "ghsa": ghsa,
        "repo": repo,
        "verdict": verdict,
        "candidate_shas": candidate_shas[:5],
        "reason": reason[:240]
    })

with open(out_jsonl, "w", encoding="utf-8") as f:
    for res in results:
        f.write(json.dumps(res) + "\n")

summary_text = (
    f"Total rows: {len(results)}\n"
    f"KEEP: {counts['KEEP']}\n"
    f"DROP: {counts['DROP']}\n"
    f"UNCERTAIN: {counts['UNCERTAIN']}\n"
)
with open(out_summary, "w", encoding="utf-8") as f:
    f.write(summary_text)

print(summary_text)

