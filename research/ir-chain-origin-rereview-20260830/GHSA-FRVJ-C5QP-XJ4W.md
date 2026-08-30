# GHSA-FRVJ-C5QP-XJ4W: earlier-flaw origin re-review

Reviewed 2026-08-30 against the complete first-party `open-webui/open-webui` Git history, the vendor advisory for [GHSA-R2WG-2MCR-66RV](https://github.com/open-webui/open-webui/security/advisories/GHSA-r2wg-2mcr-66rv), the [CVE-2026-54017 CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-54017), first-party commits, and release tags.

## Verdict

The original terminal-proxy flaw BIC is **`4737e1f11847d057859ec78892fa89e24cbcd83b`** (`feat: open terminal integration`). It created `backend/open_webui/routers/terminals.py` and first connected the non-admin-controlled route parameter `path` to the outbound `aiohttp` request without path confinement. Its immediate parent has neither the file nor an equivalent backend terminal proxy.

| IR-chain field | Resolved value |
|---|---|
| `original_sha` | `4737e1f11847d057859ec78892fa89e24cbcd83b` |
| `original_author_name` | `Timothy Jaeryang Baek` |
| `original_author_kind` | `HUMAN` |
| Immediate parent | `7ea6afdf958cda36d8a8207869ea6066283e0322` |
| AI marker on BIC | Absent |
| Confidence | High |

The intervening commit **`f9d38a073fae32032ed44073cf2817cba20210bb`** is important but is not the root BIC. It added the one-pass `unquote`/`posixpath.normpath` mitigation that left the advisory's second, double-encoded vector. Treating that mitigation as the original flaw would invert the lifecycle.

## Advisory scope and causal chain

The vendor advisory explicitly consolidates two vectors in the same earlier advisory:

1. the original raw-path forwarding / single-encoded traversal; and
2. the double-encoded `%252e%252e` bypass of the subsequently added `_sanitize_proxy_path` mitigation.

The single-valued `ir_chain.original_sha` should identify the root of that lifecycle, not the later mitigation layer. The complete public sequence is:

```text
4737e1f11847  raw vulnerable terminal proxy created
    |
f9d38a073fae  one-pass unquote/normpath mitigation; double-encoded residual remains
    |
035477591796  AI-assisted cap-8 decode remediation for CVE-2026-54017
    |
05098d25a58d  fail-closed check for the cap-8 residual reported as GHSA-FRVJ
```

The official GHSA describes the source as the authenticated user's `path` route parameter and the impact as escaping the intended terminal-server path or policy scope, including SSRF-style reach where that server routes onward. The [global reviewed advisory](https://github.com/advisories/GHSA-r2wg-2mcr-66rv) and CVE CNA record both give the affected boundary as versions before `0.9.6` and identify `0.9.6` as fixed.

## BIC and source-to-sink proof

[Commit `4737e1f11847d057859ec78892fa89e24cbcd83b`](https://github.com/open-webui/open-webui/commit/4737e1f11847d057859ec78892fa89e24cbcd83b) adds the file as blob `f8a03a9e3c84452c71c43f73f2da316f91ceb82b`. In that first blob:

- source: `@router.api_route("/{server_id}/{path:path}", ...)` binds attacker-controlled `path` at lines 45-50;
- flawed propagation: line 67 writes `target_url = f"{base_url}/{path}"` with no decode, normalization, or traversal rejection;
- sink: lines 98-104 call `aiohttp.ClientSession.request(..., url=target_url, ...)`.

The access check at lines 59-61 does not make `path` trusted: the vendor advisory explicitly says the attacker is a non-admin user who has been granted access to that terminal connection.

This is causal closure, not advisory-SHA inference: the BIC itself writes the route, vulnerable join, and outbound request in one public Git object.

## Immediate-parent absence and atomicity

The BIC has exactly one parent, `7ea6afdf958cda36d8a8207869ea6066283e0322`.

- `git cat-file -e 7ea6afdf...:backend/open_webui/routers/terminals.py` exits `128`: the path does not exist.
- `git ls-tree 7ea6afdf... backend/open_webui/routers/terminals.py` returns no entry.
- A parent-tree search finds no `proxy_terminal`, `TERMINAL_SERVER_CONNECTIONS`, `api/v1/terminals`, or equivalent `base_url}/{path` backend route.
- `git log --all --diff-filter=A -- backend/open_webui/routers/terminals.py` identifies only `4737e1f...` as the file creator.
- `git log --all --follow` reaches `4737e1f...` and stops; no rename or earlier carrier appears.

`4737e1f...` is broad (15 files) but it is not a merge commit or a squash aggregate in the public Git topology. No finer publicly reachable member first-writing this path exists. Under the audit protocol, it is therefore the smallest surviving public BIC.

## Why `f9d38a0...` is not the root BIC

[Commit `f9d38a073fae32032ed44073cf2817cba20210bb`](https://github.com/open-webui/open-webui/commit/f9d38a073fae32032ed44073cf2817cba20210bb) changes an already vulnerable proxy. Its parent still has the raw joins:

```python
target_url = f"{base_url}/{path}"
target_url = f"{base_url}/p/{policy_id}/{path}"
```

The commit replaces those values with `safe_path` and adds:

```python
decoded = unquote(path)
normalized = posixpath.normpath(decoded)
cleaned = normalized.lstrip("/")
if cleaned.startswith("..") or cleaned == ".":
    return None
```

That closes a once-decoded traversal but lets `%252e%252e/secret` become `%2e%2e/secret`, which does not begin with literal `..` and is forwarded for upstream decoding. A pickaxe search shows `f9d38a0...` first adds `decoded = unquote(path)` and [`03547759179672d216d2e1376dd1ae4fdad76a94`](https://github.com/open-webui/open-webui/commit/03547759179672d216d2e1376dd1ae4fdad76a94) later removes it in favor of the capped decode loop.

Thus `f9d38a0...` is the introducer of the **specific single-unquote mitigation design**, but it is a remediation layer over the root flaw first written by `4737e1f...`. It belongs in the displayed lifecycle, not in `original_sha`.

## Direct fix and release cross-check

The earlier advisory's direct fix is the first-party [PR #25157](https://github.com/open-webui/open-webui/pull/25157), landed on main as `03547759179672d216d2e1376dd1ae4fdad76a94`. Its patch replaces one `unquote(path)` with a decode-until-stable loop capped at eight iterations. Its commit message names the precise bypass: `%252e%252e` survives the single pass as `%2e%2e` and the upstream server decodes it to `..`.

Release ancestry matches the official advisory boundary:

| Boundary | Git result | First-party release evidence |
|---|---|---|
| `v0.8.5` | does not contain `4737e1f...` | [v0.8.5](https://github.com/open-webui/open-webui/releases/tag/v0.8.5) |
| `v0.8.6` | first version-sorted release tag containing `4737e1f...` | [v0.8.6](https://github.com/open-webui/open-webui/releases/tag/v0.8.6) |
| `v0.8.10` | contains raw proxy, not `f9d38a0...` | [v0.8.10](https://github.com/open-webui/open-webui/releases/tag/v0.8.10) |
| `v0.8.11` | first release tag containing the single-decode mitigation | [v0.8.11](https://github.com/open-webui/open-webui/releases/tag/v0.8.11) |
| `v0.9.5` | does not contain `03547759...` | [v0.9.5](https://github.com/open-webui/open-webui/releases/tag/v0.9.5) |
| `v0.9.6` | contains `03547759...` | [v0.9.6](https://github.com/open-webui/open-webui/releases/tag/v0.9.6) |

For the later GHSA-FRVJ residual, `03547759...` is the attempted remediation and [`05098d25a58d03738e01c4e85e8852c3b4ad849c`](https://github.com/open-webui/open-webui/commit/05098d25a58d03738e01c4e85e8852c3b4ad849c) is the fail-closed closure. That does not change the earlier-flaw BIC.

## Authorship and AI-marker check

Raw Git object metadata for `4737e1f...`:

```text
author    Timothy Jaeryang Baek <tim@openwebui.com> 1772219339 -0600
committer Timothy Jaeryang Baek <tim@openwebui.com> 1772219339 -0600

feat: open terminal integration
```

The official GitHub commit API maps both roles to the `tjbck` account of type `User`. The full commit body contains only the subject: no `Co-authored-by`, AI-agent/bot identity, `Generated with`, model name, or other causal AI marker. `f9d38a0...` has the same human author and committer and likewise has no AI marker.

Protocol result for the BIC: **human public commit attribution; causal AI marker absent**. This supports `original_author_kind = HUMAN`. It does not claim knowledge of unrecorded private tooling; it records the first-party Git evidence available for attribution.

The Claude trailer on `03547759...` belongs to the later attempted remediation, not the BIC, and must not be propagated backward to the original flaw.

## Recommended page data

```json
{
  "original_sha": "4737e1f11847d057859ec78892fa89e24cbcd83b",
  "original_author_kind": "HUMAN",
  "original_author_name": "Timothy Jaeryang Baek"
}
```

Recommended lifecycle copy: `4737e1f... created the raw vulnerable proxy; f9d38a0... added an imperfect single-decode mitigation; 03547759... replaced it with an AI-assisted cap-8 loop; 05098d25... finally failed closed when that cap was exceeded.`

## Replay commands

The clone was fetched with all branches/tags on 2026-08-30, reported `false` for `--is-shallow-repository`, and passed `git fsck --connectivity-only --no-dangling`. At review time `origin/main` was `d3e8bf3405e848cfba377814d0aa7ba7290e414d` and `origin/dev` was `0e65c65cc7cde9af6469c6be36fe48cdecd5f3d9`.

```bash
repo=/home/hanqing/agents/ai-slop/.ai-slop/state/repos/open-webui_open-webui

numactl --cpunodebind=1 --membind=1 git -C "$repo" fetch --all --tags --prune
numactl --cpunodebind=1 --membind=1 git -C "$repo" rev-parse --is-shallow-repository
numactl --cpunodebind=1 --membind=1 git -C "$repo" fsck --connectivity-only --no-dangling

numactl --cpunodebind=1 --membind=1 git -C "$repo" show --format=fuller \
  4737e1f11847d057859ec78892fa89e24cbcd83b -- backend/open_webui/routers/terminals.py
numactl --cpunodebind=1 --membind=1 git -C "$repo" cat-file -e \
  7ea6afdf958cda36d8a8207869ea6066283e0322:backend/open_webui/routers/terminals.py
numactl --cpunodebind=1 --membind=1 git -C "$repo" log --all --follow \
  -- backend/open_webui/routers/terminals.py
numactl --cpunodebind=1 --membind=1 git -C "$repo" log --all --reverse -p \
  -S 'target_url = f"{base_url}/{path}"' -- backend/open_webui/routers/terminals.py
numactl --cpunodebind=1 --membind=1 git -C "$repo" log --all --reverse -p \
  -S 'decoded = unquote(path)' -- backend/open_webui/routers/terminals.py

numactl --cpunodebind=1 --membind=1 git -C "$repo" show --format=fuller \
  f9d38a073fae32032ed44073cf2817cba20210bb -- backend/open_webui/routers/terminals.py
numactl --cpunodebind=1 --membind=1 git -C "$repo" show --format=fuller \
  03547759179672d216d2e1376dd1ae4fdad76a94 -- backend/open_webui/routers/terminals.py

numactl --cpunodebind=1 --membind=1 git -C "$repo" merge-base --is-ancestor \
  4737e1f11847d057859ec78892fa89e24cbcd83b v0.8.6
numactl --cpunodebind=1 --membind=1 git -C "$repo" merge-base --is-ancestor \
  03547759179672d216d2e1376dd1ae4fdad76a94 v0.9.6
```

The `cat-file -e` parent check is expected to fail with exit `128`; that failure is the asserted path-absence evidence.

## Evidence boundary

- This report resolves only the missing earlier-flaw origin fields for GHSA-FRVJ's IR chain. It does not mutate the ledger or publication data.
- The vendor advisory does not itself name the BIC. The BIC mapping comes from complete first-party Git lineage, parent absence, source-to-sink inspection, and release ancestry.
- GHSA-R2WG deliberately consolidates two vectors. `4737e1f...` is the root/raw-forwarding BIC; `f9d38a0...` is preserved as the later single-decode mitigation introducer so the second vector is not erased.
