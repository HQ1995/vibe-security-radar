#!/usr/bin/env zsh
set -euo pipefail
export GIT_NO_LAZY_FETCH=1
export GIT_OPTIONAL_LOCKS=0
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

Z=/home/hanqing/.cache/cve-analyzer/repos/zitadel_zitadel
V=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja
VW=/home/hanqing/.cache/ghsa200-w3-fetch/go-vikunja__vikunja
D=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/koxudaxi__datamodel-code-generator
DW=/home/hanqing/.cache/ghsa200-w3-fetch/koxudaxi__datamodel-code-generator

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

# Zitadel squash + parent IsVerified + not in v2.71.0
z_parents=$("${git_cmd[@]}" -C "$Z" rev-list --parents -n 1 8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f)
[[ "$z_parents" == "8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f e2a61a60029783f9a29bf7b71f2ac3d8fd39bb78" ]] || fail "zitadel parents"
"${git_cmd[@]}" -C "$Z" show -s --format='%an' 8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f | grep -qx 'Elio Bischof' || fail "zitadel author"
"${git_cmd[@]}" -C "$Z" show -s --format='%B' 8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f | grep -q 'Co-authored-by: Livio Spring' || fail "zitadel livio"
"${git_cmd[@]}" -C "$Z" grep -q 'GetIsVerified' e2a61a60029783f9a29bf7b71f2ac3d8fd39bb78 -- internal/api/grpc/user/v2/user.go || fail "zitadel parent IsVerified"
if "${git_cmd[@]}" -C "$Z" merge-base --is-ancestor 8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f v2.71.0; then fail "zitadel cand in v2.71.0"; fi
"${git_cmd[@]}" -C "$Z" merge-base --is-ancestor 8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f v4.0.0 || fail "zitadel cand not in v4.0.0"
peel4111=$("${git_cmd[@]}" -C "$Z" rev-parse 'v4.11.1^{commit}')
[[ "$peel4111" == "288f064e3ca990fde195e9a7ab363616e4fccdf1" ]] || fail "zitadel v4.11.1 peel"

# Vikunja grammar vs overdue
v_parents=$("${git_cmd[@]}" -C "$V" rev-list --parents -n 1 5f795bb531eefb1ada2d4597a47074af0e8fbc90)
[[ "$v_parents" == "5f795bb531eefb1ada2d4597a47074af0e8fbc90 d5a46310a7b84c4ff9add156994d9f5e213d566e" ]] || fail "vikunja parents"
"${git_cmd[@]}" -C "$V" show -s --format='%an' 5f795bb531eefb1ada2d4597a47074af0e8fbc90 | grep -qx 'Copilot' || fail "vikunja author"
if "${git_cmd[@]}" -C "$V" diff --no-renames 5f795bb531eefb1ada2d4597a47074af0e8fbc90^ 5f795bb531eefb1ada2d4597a47074af0e8fbc90 -- pkg/models/notifications.go | grep -q overdueLine; then fail "vikunja candidate touched overdueLine"; fi
unesc=$("${git_cmd[@]}" -C "$VW" show 'v2.2.2:pkg/models/notifications.go' | grep overdueLine | grep -c EscapeMarkdown || true)
[[ "$unesc" == "0" ]] || fail "v2.2.2 overdue already escaped"
"${git_cmd[@]}" -C "$VW" show 'v2.2.2:pkg/models/notifications.go' | grep overdueLine | grep -q 'task.Title' || fail "v2.2.2 unescaped overdue"
"${git_cmd[@]}" -C "$VW" show 'v2.3.0:pkg/models/notifications.go' | grep overdueLine | grep -q 'EscapeMarkdown(task.Title)' || fail "v2.3.0 escaped overdue"
if "${git_cmd[@]}" -C "$VW" merge-base --is-ancestor 0f3730d045f20e261e3cdfc6d93c325653395b64 v2.2.2; then fail "fix in v2.2.2"; fi
"${git_cmd[@]}" -C "$VW" merge-base --is-ancestor 0f3730d045f20e261e3cdfc6d93c325653395b64 v2.3.0 || fail "fix not in v2.3.0"

# Datamodel incomplete rem vs shared fetcher
d_parents=$("${git_cmd[@]}" -C "$D" rev-list --parents -n 1 f6d4cbd3440a84e801566fa758ab2bf483322082)
[[ "$d_parents" == "f6d4cbd3440a84e801566fa758ab2bf483322082 7e1a5c751b7b4b07aaf7d860d93162f1a75822b7" ]] || fail "datamodel parents"
"${git_cmd[@]}" -C "$D" show -s --format='%B' f6d4cbd3440a84e801566fa758ab2bf483322082 | grep -q 'file:// URLs are still allowed' || fail "datamodel file exemption message"
"${git_cmd[@]}" -C "$D" show 'f6d4cbd3440a84e801566fa758ab2bf483322082:src/datamodel_code_generator/parser/jsonschema.py' | grep -q 'if not resolved_ref.startswith("file://")' || fail "cand missing file skip"
if "${git_cmd[@]}" -C "$DW" merge-base --is-ancestor f6d4cbd3440a84e801566fa758ab2bf483322082 0.55.0; then fail "cand in 0.55.0"; fi
"${git_cmd[@]}" -C "$DW" merge-base --is-ancestor f6d4cbd3440a84e801566fa758ab2bf483322082 0.56.0 || fail "cand not in 0.56.0"
if "${git_cmd[@]}" -C "$DW" merge-base --is-ancestor 2ff4a72b4550a2b2069754c5b075b1655067e5fb 0.61.0; then fail "8359 fix in 0.61.0"; fi
"${git_cmd[@]}" -C "$DW" merge-base --is-ancestor 2ff4a72b4550a2b2069754c5b075b1655067e5fb 0.62.0 || fail "8359 fix not in 0.62.0"
if "${git_cmd[@]}" -C "$DW" merge-base --is-ancestor 5fdba4a09f2d7a9996a504975b7ef7d63e3715bb 0.60.2; then fail "954p fix in 0.60.2"; fi
"${git_cmd[@]}" -C "$DW" merge-base --is-ancestor 5fdba4a09f2d7a9996a504975b7ef7d63e3715bb 0.61.0 || fail "954p fix not in 0.61.0"
"${git_cmd[@]}" -C "$DW" show '0.61.0:src/datamodel_code_generator/parser/jsonschema.py' | grep -q 'if not resolved_ref.startswith("file://")' || fail "0.61.0 still has file skip"
"${git_cmd[@]}" -C "$DW" show '0.62.0:src/datamodel_code_generator/parser/jsonschema.py' | grep -q '_resolve_local_ref_path' || fail "0.62.0 missing local confinement"
"${git_cmd[@]}" -C "$DW" show '0.60.2:src/datamodel_code_generator/http.py' | grep -q 'follow_redirects=True' || fail "0.60.2 still follow_redirects"
"${git_cmd[@]}" -C "$DW" show '0.61.0:src/datamodel_code_generator/http.py' | grep -q '_validate_url_for_fetch' || fail "0.61.0 missing url validate"

echo "REPLAY_OK reviewed=4 KEEP_proposal=1 REJECT=3 UNKNOWN=0 BLOCKED=0"
