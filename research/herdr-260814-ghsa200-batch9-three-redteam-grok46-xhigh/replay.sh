#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-batch9-three-redteam-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP rows are proposals. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-batch9-three-redteam-grok46-xhigh
NG=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/asymmetric-effort__NogginLessDom
GP=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gopacket__gopacket

F8=f8ee181be67344f12aeb30ec39e5ab611c65b826
PARENT_F8=e314fcf257ff175fa2c5a86d61f5b5f7cbfe8998
ED=ed0124d37f548be12f2ff91b48ce7e33380d0ab4
PARENT_ED=c9ce5882e06042b9a10f3d8371e8d41c27403283
FIX_REDOS=25a3cbac665fae5663f8b71c073b80c3152dbe7b
FIX_SNAP=785e6ac6e124d1a89b3ccf40bbd75fc8e4cb215d
REL21=7cd241350fb7669b006fed46b81436925d1bb55c
REL22=00dc8ad39071140d1d76c03d93c6e10f19e51138
HTML=src/dom/html-elements.ts
SNAP=src/assertions/snapshots.ts
BLOB_HTML_21=9e4997887d405a693a005e5fbb2e22020cb635be
BLOB_HTML_22=53f3b88f97c2c4ecd2e9cfb3ef41d5cf41236e22
BLOB_SNAP_21=5f4ddaed11b96e433f0fb7b8b0c8cf91987de17e

FE=fe11a243b3365bf877ddd91f9ba37206c25d96df
PARENT_FE=de82a343cb274a34db691bfe10b1aa1378d07b0d
FIX_DIA=145859d0eaee1a6f5925ffb93851c976449c3311
V160=95d1ae3e197eee3a25d24abb7b079a60b578854d
V161=76119086f5936aacd7088bdf97d565501bb6c4cc
AVP=layers/diameter_avp_decoders.go
BLOB_AVP_160=40b24431d7fb7513ca8fbdbc2fa6409eb19572f0
BLOB_AVP_161=ce7925e148881ec338ffd3f94e1c4aca2abefe0b

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing file: %s\n' "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

assert_ancestor() {
  "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s in %s\n' "$2" "$3" "$1" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$NG/objects"
require_dir "$GP/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl" \
  1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/result.json" \
  fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" \
  699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8
expect_hash "$ROOT/scripts/publication_adjudications.json" \
  9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low/cases.jsonl" \
  bfc835268ab36bb4b2eb826b79411ad2381db9177604de76e25c194a0d71ef79
expect_hash "$OWNED/cases.jsonl" \
  15de6f28690ba33dbba72df7a32212cc2fbd4873cdb6ec6a3ca28f72c7a1cf14
expect_hash "$OWNED/report.md" \
  8023c59887858e1a4b4736ad2a8b3801ed8ec73d9104eeac8126d4c6f770be82
expect_hash "$OWNED/snapshot/advisory-database/GHSA-x4hg-hfwf-p9mw.json" \
  4e9385c2e537caba2b795cc75e8f1959b52e3f84a43d247b5a38dce9c4d6fe8f
expect_hash "$OWNED/snapshot/advisory-database/GHSA-322x-v876-g883.json" \
  7a1e065d409eb339e7a20a50f30e101d406b66ab99b0053bbab0ef712e0b8624
expect_hash "$OWNED/snapshot/advisory-database/GHSA-6r28-9ppf-4hj5.json" \
  6502549725ee9ed5f1267f7562b391aafa7d8c85da54ac5b8d719da4e73a0cd8
expect_hash "$OWNED/snapshot/pages/pr/gopacket-140.json" \
  13d1a22f650cf7adcaacabb684d354dff6d16a68daf7989429b2c418fdc7202a
expect_hash "$OWNED/snapshot/pages/pr/gopacket-140-commits-compact.json" \
  6089abf7afa6de2678b5fd52173402d09e4cf1ec1e7a3f185495612f526a2eeb
expect_hash "$OWNED/snapshot/pages/gh_commit_files/d23e7f51-files.json" \
  afc996589c77252a5a197c2afb7d6c88e956a4e8a9835d54a7a054061cde0783
expect_hash "$OWNED/snapshot/pages/gh_commit_files/6de0ba93-files.json" \
  d4f2b23993d2d1d1ca1d1173c73e3277f8d00b313b4642b84fa2ec6a33cd39a6
expect_hash "$OWNED/snapshot/pages/npm/_asymmetric-effort_nogginlessdom_0.0.21.json" \
  38ad326f39dd91421906562d85608139960b50b53547e00e79c04e0f536c19a9
expect_hash "$OWNED/snapshot/pages/npm/_asymmetric-effort_nogginlessdom_0.0.22.json" \
  58b43526a277923cc920c4ea257cf86e14975c2aaf446d2163e2d5c511a2c666
expect_hash "$OWNED/snapshot/pages/releases/noggin_tagobj_v0.0.21.json" \
  cb3c54c385a029563f89f8fcb52fc1e112383e1c35911d942e79cb6933b30957
expect_hash "$OWNED/snapshot/pages/releases/noggin_tagobj_v0.0.22.json" \
  21ad172fca01d80b9969a8ec8e578f072c5932df4a0a96a27d0a6bba77443968
expect_hash "$OWNED/snapshot/npm-tarballs/nogginlessdom-0.0.21.tgz" \
  47aba8a9ba8e004c13d0cae23af47ffd19ca11344c4bb491ce05216411b5d11b
expect_hash "$OWNED/snapshot/npm-tarballs/nogginlessdom-0.0.22.tgz" \
  d33559d28bd1ba66c014019271e65b63b198374b8fe160355cff2d9303cf8348

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" "$OWNED" "$ROOT/scripts/publication_adjudications.json" "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" << 'PY'
import json, re, sys, tarfile
from pathlib import Path
rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 3, len(rows)
assert [r["case_id"] for r in rows] == ["GHSA-X4HG-HFWF-P9MW", "GHSA-322X-V876-G883", "GHSA-6R28-9PPF-4HJ5"]
assert [r["verdict"] for r in rows] == ["KEEP", "KEEP", "NARROW"]
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
for r in rows:
    assert r["causal_admission"] is False
    assert r["countable"] is False
    assert r["publication_status"] == "HOLD"
    assert r["identity_gate"] == "PASS"
    assert r["uniqueness_gate"] == "PASS"
    assert r["language"] == "en"
if rows[0]["verdict"] == "KEEP":
    assert rows[0]["countable_proposal"] is True
    assert all(rows[0][g] == "PASS" for g in gates)
    assert rows[0]["failing_gates"] == []
if rows[1]["verdict"] == "KEEP":
    assert rows[1]["countable_proposal"] is True
    assert all(rows[1][g] == "PASS" for g in gates)
assert rows[2]["countable_proposal"] is False
assert rows[2]["failing_gates"] == ["ai_hunk_gate", "topology_gate", "but_for_gate"]
assert rows[2]["ai_hunk_gate"] == "FAIL"
assert rows[2]["fix_reversal_gate"] == "PASS"
assert rows[2]["release_gate"] == "PASS"
han = re.compile(r"[\u3400-\u9fff]")
owned = Path(sys.argv[3])
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
c73 = json.loads(Path(sys.argv[2]).read_text())
ids = set(c73["strict_released_case_ids"])
assert len(ids) == 73
for cid in ("GHSA-X4HG-HFWF-P9MW", "GHSA-322X-V876-G883", "GHSA-6R28-9PPF-4HJ5"):
    assert cid not in ids
pub = Path(sys.argv[4]).read_text()
public = Path(sys.argv[5]).read_text()
for cid in ("GHSA-X4HG-HFWF-P9MW", "GHSA-322X-V876-G883", "GHSA-6R28-9PPF-4HJ5",
            "GHSA-x4hg-hfwf-p9mw", "GHSA-322x-v876-g883", "GHSA-6r28-9ppf-4hj5"):
    assert cid not in pub
    assert cid not in public
x4 = json.loads((owned / "snapshot/advisory-database/GHSA-x4hg-hfwf-p9mw.json").read_text())
assert x4["id"] == "GHSA-x4hg-hfwf-p9mw"
assert x4["database_specific"]["github_reviewed"] is True
assert x4["affected"][0]["package"]["name"] == "@asymmetric-effort/nogginlessdom"
assert x4["affected"][0]["database_specific"]["last_known_affected_version_range"] == "<= 0.0.21"
t322 = json.loads((owned / "snapshot/advisory-database/GHSA-322x-v876-g883.json").read_text())
assert t322["id"] == "GHSA-322x-v876-g883"
assert t322["affected"][0]["package"]["name"] == "@asymmetric-effort/nogginlessdom"
g6 = json.loads((owned / "snapshot/advisory-database/GHSA-6r28-9ppf-4hj5.json").read_text())
assert g6["id"] == "GHSA-6r28-9ppf-4hj5"
assert g6["affected"][0]["package"]["name"] == "github.com/gopacket/gopacket"
gh_x4 = json.loads((owned / "snapshot/pages/ghsa/GHSA-x4hg-hfwf-p9mw.json").read_text())
assert gh_x4["withdrawn_at"] is None
assert gh_x4["type"] == "reviewed"
gh_t = json.loads((owned / "snapshot/pages/ghsa/GHSA-322x-v876-g883.json").read_text())
assert gh_t["withdrawn_at"] is None
gh_g = json.loads((owned / "snapshot/pages/ghsa/GHSA-6r28-9ppf-4hj5.json").read_text())
assert gh_g["withdrawn_at"] is None
assert gh_g["cve_id"] == "CVE-2026-54345"
npm21 = json.loads((owned / "snapshot/pages/npm/_asymmetric-effort_nogginlessdom_0.0.21.json").read_text())
npm22 = json.loads((owned / "snapshot/pages/npm/_asymmetric-effort_nogginlessdom_0.0.22.json").read_text())
assert npm21["gitHead"] == "7cd241350fb7669b006fed46b81436925d1bb55c"
assert npm22["gitHead"] == "00dc8ad39071140d1d76c03d93c6e10f19e51138"
tag21 = json.loads((owned / "snapshot/pages/releases/noggin_tagobj_v0.0.21.json").read_text())
tag22 = json.loads((owned / "snapshot/pages/releases/noggin_tagobj_v0.0.22.json").read_text())
assert tag21["object"]["sha"] == "7cd241350fb7669b006fed46b81436925d1bb55c"
assert tag22["object"]["sha"] == "00dc8ad39071140d1d76c03d93c6e10f19e51138"
pr140 = json.loads((owned / "snapshot/pages/pr/gopacket-140.json").read_text())
assert pr140["merge_commit_sha"] == "fe11a243b3365bf877ddd91f9ba37206c25d96df"
assert pr140["merged"] is True
members = json.loads((owned / "snapshot/pages/pr/gopacket-140-commits-compact.json").read_text())
assert len(members) == 8
assert members[4]["sha"] == "d23e7f51dfec864f5153c48fadfbe021a0bf1410"
assert members[4]["login"] == "dreadl0ck"
assert members[4]["copilot"] is False
assert members[7]["sha"] == "6de0ba93cfa94c86d3da170cae89ee6978f4c1c4"
assert members[7]["login"] == "mosajjal"
assert members[7]["copilot"] is True
d23 = json.loads((owned / "snapshot/pages/gh_commit_files/d23e7f51-files.json").read_text())
assert d23["files"] == ["layers/diameter_avp_decoders.go"]
c6 = json.loads((owned / "snapshot/pages/gh_commit_files/6de0ba93-files.json").read_text())
assert c6["files"] == ["layers/ports.go"]
assert json.loads((owned / "snapshot/pages/pr/noggin-f8ee181b-pulls.json").read_text()) == []
assert json.loads((owned / "snapshot/pages/pr/noggin-ed0124d3-pulls.json").read_text()) == []
iss35 = json.loads((owned / "snapshot/pages/pr/noggin-issue-35.json").read_text())
assert iss35["pull_request"] is False
iss126 = json.loads((owned / "snapshot/pages/pr/noggin-issue-126.json").read_text())
assert iss126["pull_request"] is False
for ver, expect_nested, expect_root in (("0.0.21", False, False), ("0.0.22", True, True)):
    tgz = owned / f"snapshot/npm-tarballs/nogginlessdom-{ver}.tgz"
    with tarfile.open(tgz, "r:gz") as tf:
        js = tf.extractfile("package/build/index.js").read().decode("utf-8")
    assert ("hasNestedQuantifiers" in js) is expect_nested
    assert ("File snapshot path must be within the project directory" in js) is expect_root
    assert "new RegExp(`^(?:${this.pattern})$`)" in js
    assert "function matchFileSnapshot" in js
print("conservation reviewed=3 KEEP_proposal=2 NARROW=1 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# ----- NogginLessDom: markers, parents, hunks, ancestry, versions -----
"${git_cmd[@]}" -C "$NG" log -1 --format='%B' "$F8" | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
[[ $("${git_cmd[@]}" -C "$NG" rev-parse "${F8}^") == "$PARENT_F8" ]]
n_f8=$("${git_cmd[@]}" -C "$NG" rev-list --parents -n1 "$F8" | awk '{print NF-1}')
[[ $n_f8 == 1 ]]
if "${git_cmd[@]}" -C "$NG" grep -F 'checkValidity' "$PARENT_F8" -- "$HTML" >/dev/null; then
  printf 'parent unexpectedly has checkValidity\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$NG" grep -F 'new RegExp' "$PARENT_F8" -- "$HTML" >/dev/null; then
  printf 'parent unexpectedly has new RegExp\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$NG" grep -F 'public pattern' "$PARENT_F8" -- "$HTML" >/dev/null
"${git_cmd[@]}" -C "$NG" grep -F 'new RegExp' "$F8" -- "$HTML" >/dev/null
blame_f8=$("${git_cmd[@]}" -C "$NG" blame -l -w -L286,286 "$REL21" -- "$HTML")
printf '%s\n' "$blame_f8" | grep -F "$F8" >/dev/null
[[ $("${git_cmd[@]}" -C "$NG" rev-parse "${REL21}:${HTML}") == "$BLOB_HTML_21" ]]
[[ $("${git_cmd[@]}" -C "$NG" rev-parse "${REL22}:${HTML}") == "$BLOB_HTML_22" ]]
[[ $("${git_cmd[@]}" -C "$NG" rev-parse "${FIX_REDOS}^:${HTML}") == "$BLOB_HTML_21" ]]
"${git_cmd[@]}" -C "$NG" grep -F 'hasNestedQuantifiers' "$FIX_REDOS" -- "$HTML" >/dev/null
if "${git_cmd[@]}" -C "$NG" grep -F 'hasNestedQuantifiers' "$REL21" -- "$HTML" >/dev/null; then
  printf '0.0.21 unexpectedly has hasNestedQuantifiers\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$NG" grep -F 'hasNestedQuantifiers' "$REL22" -- "$HTML" >/dev/null

"${git_cmd[@]}" -C "$NG" log -1 --format='%B' "$ED" | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
[[ $("${git_cmd[@]}" -C "$NG" rev-parse "${ED}^") == "$PARENT_ED" ]]
n_ed=$("${git_cmd[@]}" -C "$NG" rev-list --parents -n1 "$ED" | awk '{print NF-1}')
[[ $n_ed == 1 ]]
if "${git_cmd[@]}" -C "$NG" grep -F 'matchFileSnapshot' "$PARENT_ED" -- "$SNAP" >/dev/null; then
  printf 'parent unexpectedly has matchFileSnapshot\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$NG" grep -F 'writeFileSync' "$PARENT_ED" -- "$SNAP" >/dev/null
"${git_cmd[@]}" -C "$NG" grep -F 'matchFileSnapshot' "$ED" -- "$SNAP" >/dev/null
blame_ed=$("${git_cmd[@]}" -C "$NG" blame -l -w -L732,732 "$REL21" -- "$SNAP")
printf '%s\n' "$blame_ed" | grep -F "$ED" >/dev/null
[[ $("${git_cmd[@]}" -C "$NG" rev-parse "${REL21}:${SNAP}") == "$BLOB_SNAP_21" ]]
if "${git_cmd[@]}" -C "$NG" grep -F 'project directory' "$REL21" -- "$SNAP" >/dev/null; then
  printf '0.0.21 unexpectedly has project directory guard\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$NG" grep -F 'project directory' "$FIX_SNAP" -- "$SNAP" >/dev/null
# 0.0.22 snapshots blob is absent from this blob:none clone. Containment of
# 785e6ac6 in 00dc8ad3 is merge-base ancestry plus the npm 0.0.22 tarball.

ver21=$("${git_cmd[@]}" -C "$NG" show "${REL21}:package.json")
printf '%s\n' "$ver21" | grep -F '"version": "0.0.21"' >/dev/null
ver22=$("${git_cmd[@]}" -C "$NG" show "${REL22}:package.json")
printf '%s\n' "$ver22" | grep -F '"version": "0.0.22"' >/dev/null
assert_ancestor "$NG" "$F8" "$REL21"
assert_ancestor "$NG" "$ED" "$REL21"
assert_not_ancestor "$NG" "$FIX_REDOS" "$REL21"
assert_not_ancestor "$NG" "$FIX_SNAP" "$REL21"
assert_ancestor "$NG" "$FIX_REDOS" "$REL22"
assert_ancestor "$NG" "$FIX_SNAP" "$REL22"
n_tags=$("${git_cmd[@]}" -C "$NG" tag --list | wc -l)
[[ $n_tags == 0 ]]

# ----- gopacket: squash carrier, human AVP member, exact closer, tags -----
"${git_cmd[@]}" -C "$GP" log -1 --format='%B' "$FE" | grep -F 'Co-authored-by: Copilot' >/dev/null
[[ $("${git_cmd[@]}" -C "$GP" rev-parse "${FE}^") == "$PARENT_FE" ]]
n_fe=$("${git_cmd[@]}" -C "$GP" rev-list --parents -n1 "$FE" | awk '{print NF-1}')
[[ $n_fe == 1 ]]
if "${git_cmd[@]}" -C "$GP" cat-file -e "${PARENT_FE}:${AVP}" 2>/dev/null; then
  printf 'squash parent unexpectedly has diameter_avp_decoders.go\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$GP" cat-file -e "${FE}:layers/diameter.go" 2>/dev/null; then
  :
else
  printf 'squash missing diameter.go\n' >&2
  exit 1
fi
[[ $("${git_cmd[@]}" -C "$GP" rev-parse "v1.6.0^{commit}") == "$V160" ]]
[[ $("${git_cmd[@]}" -C "$GP" rev-parse "v1.6.1^{commit}") == "$V161" ]]
[[ $("${git_cmd[@]}" -C "$GP" rev-parse "v1.6.0:${AVP}") == "$BLOB_AVP_160" ]]
[[ $("${git_cmd[@]}" -C "$GP" rev-parse "v1.6.1:${AVP}") == "$BLOB_AVP_161" ]]
[[ $("${git_cmd[@]}" -C "$GP" rev-parse "${FIX_DIA}:${AVP}") == "$BLOB_AVP_161" ]]
blame_avp=$("${git_cmd[@]}" -C "$GP" blame -l -w -L56,57 v1.6.0 -- "$AVP")
printf '%s\n' "$blame_avp" | grep -F "$FE" >/dev/null
assert_ancestor "$GP" "$FE" v1.6.0
assert_not_ancestor "$GP" "$FIX_DIA" v1.6.0
assert_ancestor "$GP" "$FIX_DIA" v1.6.1
[[ $("${git_cmd[@]}" -C "$GP" rev-parse "${FIX_DIA}^") == "$V160" ]]
n_fix=$("${git_cmd[@]}" -C "$GP" rev-list --parents -n1 "$FIX_DIA" | awk '{print NF-1}')
[[ $n_fix == 1 ]]
"${git_cmd[@]}" -C "$GP" grep -F 'smaller than header size' "$FIX_DIA" -- "$AVP" >/dev/null
if "${git_cmd[@]}" -C "$GP" grep -F 'smaller than header size' v1.6.0 -- "$AVP" >/dev/null; then
  printf 'v1.6.0 unexpectedly has header-size guard\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$GP" grep -F 'smaller than header size' v1.6.1 -- "$AVP" >/dev/null
if "${git_cmd[@]}" -C "$GP" cat-file -e d23e7f51dfec864f5153c48fadfbe021a0bf1410 2>/dev/null; then
  printf 'mainline clone unexpectedly still has PR member d23e7f51\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$GP" cat-file -e 6de0ba93cfa94c86d3da170cae89ee6978f4c1c4 2>/dev/null; then
  printf 'mainline clone unexpectedly still has PR member 6de0ba93\n' >&2
  exit 1
fi

printf 'REPLAY_OK reviewed=3 KEEP_proposal=2 NARROW=1 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
