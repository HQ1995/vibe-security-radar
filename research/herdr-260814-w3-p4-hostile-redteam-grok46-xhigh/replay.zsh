#!/usr/bin/env zsh
set -euo pipefail
export GIT_NO_LAZY_FETCH=1
export GIT_OPTIONAL_LOCKS=0
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

E=/home/hanqing/.cache/cve-analyzer/repos/electron_electron
M=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mermaid-js__mermaid
V=/home/hanqing/.cache/ghsa200-worker-clones/recovery20i-260814/vllm-project__vllm
F=/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2/FlowiseAI__Flowise
U=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nodejs__undici
S=/home/hanqing/.cache/cve-analyzer/repos/seaweedfs_seaweedfs
O=/home/hanqing/.cache/cve-analyzer/repos/open-webui_open-webui
MX=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/matrix-org__matrix-rust-sdk
N=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/netty__netty
K=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/keycloak__keycloak
EK=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lf-edge__ekuiper
N8=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/n8n-io__n8n
G=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs

# Electron: true parent, old dock_state_, listed parent is trop fix parent
e_parents=$("${git_cmd[@]}" -C "$E" rev-list --parents -n 1 fe477ce3aa65316f4e63b0907d117723a1d4c8bc)
[[ "$e_parents" == "fe477ce3aa65316f4e63b0907d117723a1d4c8bc bab6bd3dae351d8f49203a26468d58482f754c84" ]] || fail "electron true parent"
fix_par=$("${git_cmd[@]}" -C "$E" rev-list --parents -n 1 04614eed17986bddc43eb509ec870424ee6a47d1)
[[ "$fix_par" == "04614eed17986bddc43eb509ec870424ee6a47d1 964cf07e190093a3f473e31437f7afb5864fb10e" ]] || fail "electron listed parent is fix parent"
"${git_cmd[@]}" -C "$E" grep -F -q 'dock_state_' fe477ce3aa65316f4e63b0907d117723a1d4c8bc^ -- shell/browser/ui/inspectable_web_contents.cc || fail "parent missing dock_state_"
"${git_cmd[@]}" -C "$E" grep -q 'ShowItemInFolder' fe477ce3aa65316f4e63b0907d117723a1d4c8bc^ -- shell/browser/ui/inspectable_web_contents.cc || fail "parent missing ShowItemInFolder"
"${git_cmd[@]}" -C "$E" merge-base --is-ancestor fe477ce3aa65316f4e63b0907d117723a1d4c8bc v41.2.0 || fail "cand not in v41.2.0"

# Mermaid: true parent != listed; no assignWithDepth in cand diff
m_parents=$("${git_cmd[@]}" -C "$M" rev-list --parents -n 1 dea0572457f903295d41c92efcaf1f52a6a377d9)
[[ "$m_parents" == "dea0572457f903295d41c92efcaf1f52a6a377d9 980db3f8510d007c0941aee2c8f3356aa49eba62" ]] || fail "mermaid true parent"
mf_par=$("${git_cmd[@]}" -C "$M" rev-list --parents -n 1 2cd6dcf735533b323507e3e889ffdea870540b43)
[[ "$mf_par" == "2cd6dcf735533b323507e3e889ffdea870540b43 630aa7e5dd417e1f56bff2a1ce8df2c5ad08d289" ]] || fail "mermaid listed parent is fix parent"
if "${git_cmd[@]}" -C "$M" diff --name-only dea0572457f903295d41c92efcaf1f52a6a377d9^ dea0572457f903295d41c92efcaf1f52a6a377d9 | grep -q assignWithDepth; then fail "mermaid cand touched assignWithDepth"; fi
"${git_cmd[@]}" -C "$M" cat-file -e 'dea0572457f903295d41c92efcaf1f52a6a377d9^:packages/mermaid/src/assignWithDepth.ts' || fail "parent missing assignWithDepth.ts"

# vLLM fingerprint vs prompt bound
v_parents=$("${git_cmd[@]}" -C "$V" rev-list --parents -n 1 ebf862c351dc4bcaf65de34c3caebe6df6e9e214)
[[ "$v_parents" == "ebf862c351dc4bcaf65de34c3caebe6df6e9e214 8d8062d0a7014b4cde064024ae5d5a8715a833b3" ]] || fail "vllm true parent"
"${git_cmd[@]}" -C "$V" diff ebf862c351dc4bcaf65de34c3caebe6df6e9e214^ ebf862c351dc4bcaf65de34c3caebe6df6e9e214 -- vllm/entrypoints/openai/completion/protocol.py | grep -q system_fingerprint || fail "vllm missing fingerprint hunk"
if "${git_cmd[@]}" -C "$V" diff ebf862c351dc4bcaf65de34c3caebe6df6e9e214^ ebf862c351dc4bcaf65de34c3caebe6df6e9e214 -- vllm/entrypoints/openai/completion/protocol.py | grep -q 'prompt list'; then fail "vllm cand bounded prompt list"; fi
"${git_cmd[@]}" -C "$V" merge-base --is-ancestor ebf862c351dc4bcaf65de34c3caebe6df6e9e214 v0.25.0 || fail "vllm cand not in v0.25.0"
if "${git_cmd[@]}" -C "$V" merge-base --is-ancestor 675f4295cdfe0d870471c2b51bfeca3a68a9569e v0.25.0; then fail "vllm fix in v0.25.0"; fi
"${git_cmd[@]}" -C "$V" merge-base --is-ancestor 675f4295cdfe0d870471c2b51bfeca3a68a9569e v0.26.0 || fail "vllm fix not in v0.26.0"

# Flowise: true parent != listed; only CustomMCP name
f_parents=$("${git_cmd[@]}" -C "$F" rev-list --parents -n 1 b5f7fac0155a13122fe85e6ee46f6204d087cb27)
[[ "$f_parents" == "b5f7fac0155a13122fe85e6ee46f6204d087cb27 ca22160361e642e5e50393367f825f18077c29a7" ]] || fail "flowise true parent"
ff_par=$("${git_cmd[@]}" -C "$F" rev-list --parents -n 1 a4c4e4988cded15edf725e762560575b889ae351)
[[ "$ff_par" == "a4c4e4988cded15edf725e762560575b889ae351 746d203a5cf517b86e983be0f2c52e06caa40f37" ]] || fail "flowise listed parent is fix parent"
"${git_cmd[@]}" -C "$F" merge-base --is-ancestor b5f7fac0155a13122fe85e6ee46f6204d087cb27 'flowise@3.1.2' || fail "flowise cand not in 3.1.2"
if "${git_cmd[@]}" -C "$F" merge-base --is-ancestor a4c4e4988cded15edf725e762560575b889ae351 'flowise@3.1.2'; then fail "flowise fix in 3.1.2"; fi
"${git_cmd[@]}" -C "$F" merge-base --is-ancestor a4c4e4988cded15edf725e762560575b889ae351 'flowise@3.1.3' || fail "flowise fix not in 3.1.3"

# undici TTL vs OWS parser
u_parents=$("${git_cmd[@]}" -C "$U" rev-list --parents -n 1 90775009148e5956ac58ace0eb493001db8b2b7c)
[[ "$u_parents" == "90775009148e5956ac58ace0eb493001db8b2b7c 1c5dc1ad36c886aa11d025cf6381c5ea1fff0ca4" ]] || fail "undici true parent"
if "${git_cmd[@]}" -C "$U" diff --name-only 90775009148e5956ac58ace0eb493001db8b2b7c^ 90775009148e5956ac58ace0eb493001db8b2b7c | grep -q 'lib/util/cache.js'; then fail "undici cand touched cache.js parser"; fi
"${git_cmd[@]}" -C "$U" diff --name-only 85a240551c9feb8b8a0ecc56c84b2b3015add8a9^ 85a240551c9feb8b8a0ecc56c84b2b3015add8a9 | grep -q 'lib/util/cache.js' || fail "undici fix missed cache.js"

# seaweed SkipClean pre-exists; GetObject pre-exists
s_parents=$("${git_cmd[@]}" -C "$S" rev-list --parents -n 1 10a30a83e1bdfca25c19506ef4d0d39d22e17628)
[[ "$s_parents" == "10a30a83e1bdfca25c19506ef4d0d39d22e17628 9e26d6f5dd6f32ac84cf47a4463f3461944f8c7d" ]] || fail "seaweed true parent"
"${git_cmd[@]}" -C "$S" grep -q 'SkipClean(true)' 10a30a83e1bdfca25c19506ef4d0d39d22e17628^ -- weed/command/s3.go || fail "parent missing SkipClean"
"${git_cmd[@]}" -C "$S" grep -q 'GetObjectHandler' 10a30a83e1bdfca25c19506ef4d0d39d22e17628^ -- weed/s3api/s3api_server.go || fail "parent missing GetObject"
"${git_cmd[@]}" -C "$S" diff --name-only 10a30a83e1bdfca25c19506ef4d0d39d22e17628^ 10a30a83e1bdfca25c19506ef4d0d39d22e17628 | grep -q s3api_object_handlers_attributes.go || fail "cand missing attributes handler"
if "${git_cmd[@]}" -C "$S" diff --name-only 10a30a83e1bdfca25c19506ef4d0d39d22e17628^ 10a30a83e1bdfca25c19506ef4d0d39d22e17628 | grep -q 'weed/command/s3.go'; then fail "cand touched s3.go SkipClean"; fi

# open-webui log-level only on auths/oauth
o_parents=$("${git_cmd[@]}" -C "$O" rev-list --parents -n 1 823b9a6dd96e51d6bbb5e162d13ae043fcf59408)
[[ "$o_parents" == "823b9a6dd96e51d6bbb5e162d13ae043fcf59408 d65116282cc9744506d16985afd01ff9c1a962ec" ]] || fail "openwebui true parent"
"${git_cmd[@]}" -C "$O" diff 823b9a6dd96e51d6bbb5e162d13ae043fcf59408^ 823b9a6dd96e51d6bbb5e162d13ae043fcf59408 -- backend/open_webui/models/auths.py | grep -q SRC_LOG_LEVELS || fail "openwebui auths not log-level"

# kind2: assigned SHAs are changelog or human fixes, no AI trailer
mx_files=$("${git_cmd[@]}" -C "$MX" diff --name-only ce3b67f801446387972ff120e907ca828a9f1207^ ce3b67f801446387972ff120e907ca828a9f1207)
[[ "$mx_files" == "bindings/matrix-sdk-ffi/CHANGELOG.md" ]] || fail "matrix not changelog-only"
"${git_cmd[@]}" -C "$N" show -s --format='%an' 1782e8c2060a244c4d4e6f9d9112d5517ca05120 | grep -q 'DepthFirst' || fail "netty author"
"${git_cmd[@]}" -C "$K" show -s --format='%s' 754c070cf8ca187dcc71f0f72ff3130ff2195328 | grep -q 'LDAP URL' || fail "keycloak subject"
"${git_cmd[@]}" -C "$EK" show -s --format='%s' 58362b089c76f08c400fe0dbb3667e6e871eaffd | grep -q 'path validation' || fail "ekuiper subject"
"${git_cmd[@]}" -C "$N8" show -s --format='%s' ae0669a736cc496beeb296e115267862727ae838 | grep -q 'package version' || fail "n8n subject"
"${git_cmd[@]}" -C "$G" show -s --format='%s' 71a72a72ad1c8cea7940c9d7e4cbdfbc0fc3d401 | grep -q 'mermaid' || fail "gogs subject"
if "${git_cmd[@]}" -C "$G" merge-base --is-ancestor 71a72a72ad1c8cea7940c9d7e4cbdfbc0fc3d401 v0.13.3; then fail "gogs fix in v0.13.3"; fi
"${git_cmd[@]}" -C "$G" merge-base --is-ancestor 71a72a72ad1c8cea7940c9d7e4cbdfbc0fc3d401 v0.13.4 || fail "gogs fix not in v0.13.4"

echo "REPLAY_OK reviewed=14 KEEP=0 REJECT=3 UNKNOWN=11 BLOCKED=0"
