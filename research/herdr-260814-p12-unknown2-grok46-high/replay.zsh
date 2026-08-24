#!/usr/bin/env zsh
set -euo pipefail
OWN="$(cd -- "$(dirname -- "$0")" && pwd)"
export GIT_NO_LAZY_FETCH=1
G=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)
WORKDIR="$OWN/work/clones"
mkdir -p "$WORKDIR"

clone_fetch() {
  local name="$1" src="$2" url="$3"
  shift 3
  local dest="$WORKDIR/$name"
  if [[ ! -d "$dest/.git" ]]; then
    "${G[@]}" clone --no-checkout --shared "$src" "$dest"
    "${G[@]}" -C "$dest" remote add github "$url" 2>/dev/null || true
  fi
  "${G[@]}" -C "$dest" fetch --no-tags --no-recurse-submodules github "$@"
}

clone_fetch babylon \
  /home/hanqing/.cache/cve-analyzer/repos/babylonlabs-io_babylon \
  https://github.com/babylonlabs-io/babylon.git \
  pull/1707/head:refs/pull/1707/head \
  pull/1731/head:refs/pull/1731/head \
  pull/1755/head:refs/pull/1755/head \
  pull/1890/head:refs/pull/1890/head

clone_fetch soroban \
  /home/hanqing/.cache/cve-analyzer/repos/stellar_rs-soroban-sdk \
  https://github.com/stellar/rs-soroban-sdk.git \
  pull/1615/head:refs/pull/1615/head \
  pull/1667/head:refs/pull/1667/head \
  pull/1750/head:refs/pull/1750/head

BAB="$WORKDIR/babylon"
SOR="$WORKDIR/soroban"
FILE_B=x/costaking/keeper/hooks_finality.go
FILE_S=soroban-sdk/src/crypto/bn254.rs

fail() { print -r -- "REPLAY_FAIL: $*"; exit 1; }

[[ "$("${G[@]}" -C "$BAB" rev-parse 2bd9585607bd7b1c0905d21b92bcdb6d4c03bf36^)" == 4bfae6d85240af95e4ab37d64c12f331e3c2f91a ]] || fail babylon_parent
[[ "$("${G[@]}" -C "$BAB" rev-parse f0f7d0d7448945f0384a6e0884090994ae0ad04d:${FILE_B})" == 759879ec82c9e0d39ed3c23ec6bebe643e06e596 ]] || fail babylon_f0_blob
[[ "$("${G[@]}" -C "$BAB" rev-parse a7c9a2828f213e8157ba60501dfcc0e43233f77e:${FILE_B})" == 4fe8df8ea7ae81812a4af1a9434dd576df4e8a25 ]] || fail babylon_1731_squash_blob
[[ "$("${G[@]}" -C "$BAB" rev-parse 2bd9585607bd7b1c0905d21b92bcdb6d4c03bf36:${FILE_B})" == c8e6db4afac8e1afd076c6f3723265d2f3bce752 ]] || fail babylon_cand_blob
[[ "$("${G[@]}" -C "$BAB" rev-parse v4.0.0:${FILE_B})" == c8e6db4afac8e1afd076c6f3723265d2f3bce752 ]] || fail babylon_v400
[[ "$("${G[@]}" -C "$BAB" rev-parse v4.2.0:${FILE_B})" == 2243b3ef4500ae9ea526e57ce105955dd6977718 ]] || fail babylon_v420
if "${G[@]}" -C "$BAB" merge-base --is-ancestor f0f7d0d7448945f0384a6e0884090994ae0ad04d 2bd9585607bd7b1c0905d21b92bcdb6d4c03bf36; then fail babylon_member_is_ancestor; fi
if "${G[@]}" -C "$BAB" log -1 --format='%B' f0f7d0d7448945f0384a6e0884090994ae0ad04d | rg -q 'Copilot'; then fail babylon_f0_has_copilot; fi
if "${G[@]}" -C "$BAB" log -1 --format='%B' a7c9a2828f213e8157ba60501dfcc0e43233f77e | rg -q 'Copilot'; then fail babylon_1731_has_copilot; fi
"${G[@]}" -C "$BAB" grep -q '!isFpActiveInPrevSet || !isFpActiveInCurrSet' f0f7d0d7448945f0384a6e0884090994ae0ad04d -- "$FILE_B" || fail babylon_pred
"${G[@]}" -C "$BAB" grep -q '!isFpActiveInPrevSet' e65c3a55a398a403103f1b089cf76f0d4befc7a0 -- "$FILE_B" || fail babylon_fix
if "${G[@]}" -C "$BAB" grep -q '!isFpActiveInCurrSet' e65c3a55a398a403103f1b089cf76f0d4befc7a0 -- "$FILE_B"; then fail babylon_fix_still_curr; fi

[[ "$("${G[@]}" -C "$SOR" rev-parse ecad5addcae1dfc3b9bd9865ea5977aef5f16843^)" == a60b7e8f8464e6bd6ffea4a5d7b9843a76deeb71 ]] || fail soroban_parent
[[ "$("${G[@]}" -C "$SOR" rev-parse 7e886f151f4e6a9427f2a9858c9b047f1dcfe689:${FILE_S})" == 956829138309539bf4c2eedda068d9d798a8cc65 ]] || fail soroban_first_blob
[[ "$("${G[@]}" -C "$SOR" rev-parse ecad5addcae1dfc3b9bd9865ea5977aef5f16843:${FILE_S})" == 142655a1bc7e669d6a33ced6f909d36e22922801 ]] || fail soroban_cand_blob
[[ "$("${G[@]}" -C "$SOR" rev-parse v25.0.0:${FILE_S})" == 142655a1bc7e669d6a33ced6f909d36e22922801 ]] || fail soroban_v250
[[ "$("${G[@]}" -C "$SOR" rev-parse 082424b30bf22ea7fb8c79f16ccd135e0ae9f3db:${FILE_S})" == 09f50852680bb8ee51c3283671c79324a4284fd5 ]] || fail soroban_fix_blob
if "${G[@]}" -C "$SOR" merge-base --is-ancestor 7e886f151f4e6a9427f2a9858c9b047f1dcfe689 ecad5addcae1dfc3b9bd9865ea5977aef5f16843; then fail soroban_member_is_ancestor; fi
if "${G[@]}" -C "$SOR" log -1 --format='%B' 7e886f151f4e6a9427f2a9858c9b047f1dcfe689 | rg -q 'Copilot'; then fail soroban_first_has_copilot; fi
if "${G[@]}" -C "$SOR" log -1 --format='%B' 3cf10a984dba03f68b4f2ed653b715063e983bba | rg -q 'Copilot'; then fail soroban_1615_has_copilot; fi
"${G[@]}" -C "$SOR" cat-file -p "$("${G[@]}" -C "$SOR" rev-parse 7e886f151f4e6a9427f2a9858c9b047f1dcfe689:${FILE_S})" | rg -q 'Self\(value\)' || fail soroban_unreduced
"${G[@]}" -C "$SOR" cat-file -p "$("${G[@]}" -C "$SOR" rev-parse 082424b30bf22ea7fb8c79f16ccd135e0ae9f3db:${FILE_S})" | rg -q 'rem_euclid' || fail soroban_fix_reduce

print -r -- "REPLAY_OK reviewed=2 KEEP_proposal=0 REJECT=2 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=84"
