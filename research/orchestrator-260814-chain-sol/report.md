# Backward chain adjudication

## Verdict

All six assigned chains terminate at human, non-AI vulnerable-hunk origins: `BIC_AI=NO` for 6, `YES` for 0, and `UNKNOWN` for 0. The seven causal gates are `NOT_OPENED_BIC_AI_NO` in every row because `CHAIN-SPEC.md` requires them only for `BIC_AI=YES`. All rows are terminal. File Browser is the critical negative control: the first backward hit is a Claude-marked incomplete security remediation, but one more hop reaches the older human BIC, so the AI fix is not relabeled as origin.

The queue contains two repository/fix routing defects. Faraday is assigned to `rubysec/ruby-advisory-db`, although its source and fix are in `lostisland/faraday`; Langroid is assigned to `pypa/advisory-database` with a null fix, although the first-party advisory identifies `langroid/langroid` and local product history resolves the 0.63.0 remediation. These were resolved from the advisory objects and local Git pools, not from secondary or API data.

## Six-row verdict table

| # | GHSA | Resolved backward chain | BIC evidence | Depth | Verdict / gates |
|---:|---|---|---|---:|---|
| 1 | `GHSA-33MH-2634-FWR2` | `a6d3a3a0` -> `d8bfca25` | ykrods; no AI identity | 1 | `BIC_AI=NO`; terminal; gates not opened |
| 2 | `GHSA-RXRV-835Q-V5MH` | `042af9ca` -> `f2868ae0` | huntr-helper plus two human co-authors; no AI identity | 1 | `BIC_AI=NO`; terminal; gates not opened |
| 3 | `GHSA-RPM5-65CW-6HJ4` | `14219588` + `43d92dec` -> `e6108c79` | Santos Gallegos; no AI identity | 1 | `BIC_AI=NO`; terminal; gates not opened |
| 4 | `GHSA-MXFR-6HCW-J9RQ` | inferred 0.63.0 fix `60933b48` -> `434db35a` | Rithwik Babu plus human co-author; no AI identity | 1 | `BIC_AI=NO`; terminal; gates not opened |
| 5 | `GHSA-239W-M3H6-CH8V` | `7c2c0a11` -> AI security hop `847d08bd` -> `8650d2ff` | Oleg Lobanov; no AI identity | 2 | `BIC_AI=NO`; terminal; gates not opened |
| 6 | `GHSA-3F7W-8RR8-F37F` | `3af0c251` -> `{0ef1f89a, 1047b41e}` | Sebastian Thiel on both; no AI identity | 1 | `BIC_AI=NO`; terminal; gates not opened |

## Chain narratives

### 1. Faraday protocol-relative host override

- Advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-33mh-2634-fwr2/GHSA-33mh-2634-fwr2.json` (`CVE-2026-25765`). Product pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/lostisland__faraday`.
- The supplied fix `a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc` amends `build_exclusive_url` so the relative-URL prefix is also applied when the input begins with `//`. Bounded pickaxe of the exact preimage guard reaches `d8bfca25fa57c4a807f4a488f087387583c861fe`, subject `Merge relative url without escaping (#1569)`.
- `d8bfca25` introduced this guard:

```ruby
url = "./#{url}" if url.respond_to?(:start_with?) &&
                  !url.start_with?('http://', 'https://', '/', './', '../')
```

  Because `/` was exempted, `//evil` still reached `uri = base + url`. Author ykrods has no AI author, trailer, or generated-with marker. The later closure has a Claude trailer, which does not transfer backward.
- Topology is closed: `d8bfca25` is an ancestor of `a6d3a3a0` at distance 61. The candidate is followed by the 2.9.2 version bump and is contained in the 2.14.0 carrier; the fix is followed by the 2.14.1 carrier. The separate 1.10.5 backport object is absent locally, but this does not affect BIC provenance.
- Counterevidence: `d8bfca25^` already combined protocol-relative input with the base URI, and deeper sink blame reaches the shallow boundary `626d68f6` whose parent is absent. Thus `d8bfca25` is the exact non-AI guard origin reversed by the final fix, while the logically earliest host-override sink remains older than the available boundary. No positive AI-origin claim can be made from that gap.

### 2. Locutus prototype-pollution guard bypass

- Advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-rxrv-835q-v5mh/GHSA-rxrv-835q-v5mh.json` (`CVE-2026-25521`). Pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/locutusjs__locutus`.
- Final `042af9ca7fde2ff599120783e720a17f335bb01c` replaces a hijackable `String.prototype.includes` denylist with a regular-expression check. Bounded pickaxe, verified against the hit's own diff, identifies `f2868ae0ecc55eff2644eb61f44c1df5cbc63fe9`, `fixed prototype pollution (#418)`, as the commit that added the bypassed boundary:

```javascript
if (key.includes('__proto__') || key.includes('constructor') || key.includes('prototype')) {
  break
}
```

- The BIC author is `huntr-helper`; the only trailers name Asjid Kalam and Jamie Slome. There is no explicit AI identity. The final fix's Claude trailer cannot be transferred to the 2020 guard.
- `f2868ae0` is an ancestor of the closure. `v2.0.12` and vulnerable `v2.0.38` contain the guard, while `v2.0.39` contains `042af9ca`. The prior security report is identified locally only as issue/PR `#418`, not as a separate GHSA.
- Counterevidence: older assignment code is also human-authored; for example, `e4e7d58611a4bc03ec51a6d75fce5575373eae6d` replaced `eval()` with key-controlled object traversal in 2012. The chain already terminates under the spec's explicit non-AI stop rule at `f2868ae0`.

### 3. GitPython underscored unsafe-option bypass

- Advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-rpm5-65cw-6hj4/GHSA-rpm5-65cw-6hj4.json` (`CVE-2026-42215`). Pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/gitpython-developers__GitPython`.
- The null queue fix is stale. Local history resolves minimum fix `142195888e713542189533a52cdfc333f05c3af6`, followed by hardening `43d92dec4683568d11495956dd556161f17c3ea8` and release carrier `0f68db0710f9125762fca5dbc2328593537ae923`.
- The fix canonicalizes Python kwarg names before comparison, making `upload_pack` match blocked `upload-pack`. Pickaxe of the preimage validator resolves to `e6108c7997f5c8f7361b982959518e982b973230`, `Block unsafe options and protocols by default`, whose own diff introduced the raw-name loop:

```python
for option in options:
    for unsafe_option, bare_option in zip(unsafe_options, bare_options):
        if option.startswith(unsafe_option) or option == bare_option:
            raise UnsafeOptionError(...)
```

- Santos Gallegos authored `e6108c79`; its message and trailers have no AI marker. It follows the also-human `fbf9c7e72218e44bc29eb4907d5c00118370376b` command-injection fix lineage. Formatting-only pickaxe hits were inspected and rejected.
- `3.1.30` and vulnerable `3.1.46` contain `e6108c79`; `3.1.47` contains the two-part closure. The chain terminates at the first non-AI boundary origin as required.

### 4. Langroid unrestricted LLM-generated SQL

- Advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/05/GHSA-mxfr-6hcw-j9rq/GHSA-mxfr-6hcw-j9rq.json` (`CVE-2026-25879`). Product pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/langroid__langroid`.
- The advisory has no commit reference, but it names `langroid/langroid` and fixed version `0.63.0`. Local tag ancestry resolves `60933b4860a8952894b31caa0dd3f9dcba512c8e`, `Add SQL query validation to mitigate CVE-2026-25879`, as the Claude-marked remediation contained in `0.63.0`.
- Pickaxe of the pre-validation `run_query` sink, following its file move, reaches `434db35a3005a67f241331aa438aff001c8da067`, `sql_chat_agent and example (#197)`, whose own diff added:

```python
query = msg.query
query_result = session.execute(text(query))
session.commit()
```

- Rithwik Babu authored the BIC, with only Prasad Chalasani as a human co-author. There is no AI marker. `434db35a` is an ancestor of `60933b48`; `0.62.0` contains the unrestricted sink without the fix, and `0.63.0` contains the remediation.
- Counterevidence: `60933b48` is AI-authored, but it is the security fix rather than the original vulnerable hunk. The later `GHSA-PMCH-G965-GRMR` residual concerns omissions in that new denylist; it does not make the 2023 SQL execution origin AI-authored.

### 5. File Browser symlink scope escape

- Advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/06/GHSA-239w-m3h6-ch8v/GHSA-239w-m3h6-ch8v.json` (`CVE-2026-54094`). Pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/filebrowser__filebrowser`.
- Final `7c2c0a11b31b2bb214d741005a0b02b1764208b3` replaces handler-specific containment checks with `ScopedFs`, enforcing resolved-target containment at every filesystem operation.
- The first backward security hop is `847d08bdd135e5c3659f2e6dea2f0cd36617af9b`, which explicitly names this GHSA and has `Co-Authored-By: Claude Opus 4.8`. It added `WithinScope` only around selected final-component read/write paths. It is an incomplete AI remediation, not the original BIC.
- Repeating bounded pickaxe across `847d08bd^` reaches human `8650d2ffe7a29cbafa800efcecbf6a61598a9f0c`, `fix: failure on broken symlink deletion`. That commit's own diff added `stat()`, recorded `IsSymlink`, returned regular leaves early, and otherwise followed the path:

```go
if file != nil && !file.IsSymlink {
    return file, nil
}
info, err := opts.Fs.Stat(opts.Path)
```

  A leaf reached through a symlinked ancestor is reported as regular and takes the early return; a final symlink is followed by `Stat`. Oleg Lobanov authored this 2021 non-security fix, with no AI marker. The still older `f1a89f5ec49717f767587b8d561c3de7befd19fc` BasePathFs scope construction is also human-authored.
- Release chronology is preserved: Claude remediation `847d08bd` is carried by the 2.63.6 release commit; later human additions cover share/copy/move and the ancestor-symlink gap, with `3471ec2` carried by 2.63.11 and still present in vulnerable 2.63.13. Human `3406d3d` follows 2.63.13, and the advisory identifies `7c2c0a11` in fixed 2.63.14.
- Counterevidence: counting `847d08bd` as BIC would confuse incomplete remediation with original authorship. The second hop is mandatory and changes the verdict from an apparent `YES` to the correct `NO`.

### 6. GitPython unguarded option forwarding

- Advisory: `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/08/GHSA-3f7w-8rr8-f37f/GHSA-3f7w-8rr8-f37f.json` (no CVE alias). Pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/gitpython-developers__GitPython`.
- Final `3af0c2516c5e18c829da30338614688f6b69b49c` is authored by `GPT 5.6 <codex@openai.com>` and adds per-method checks for `checkout-index --prefix` and `git tag -F/--file`. That is fix-side AI, not BIC evidence.
- The advisory has two independent sinks, so a single SHA would be fabricated. Pickaxe with file-split continuation resolves:

  - `0ef1f89abe5b2334705ee8f1a6da231b0b6c9a50` (Sebastian Thiel, 2009), which introduced `IndexFile.checkout(..., **kwargs)` and forwarded those kwargs into both `checkout_index` calls.
  - `1047b41e2e925617474e2e7c9927314f71ce7365` (Sebastian Thiel, 2009), which implemented `TagReference.create(..., **kwargs)` and forwarded them into `repo.git.tag`.

```python
def checkout(self, paths=None, force=False, **kwargs):
    self.repo.git.checkout_index(*args, **kwargs)

def create(cls, repo, path, ref='HEAD', message=None, force=False, **kwargs):
    repo.git.tag(*args, **kwargs)
```

- Later file-split commits `af32b6e0` and `dec46631` were rejected as carriers and traced to the two logical introductions above. Both BICs are human, have no AI marker, and are ancestors of the fix.
- Releases `3.1.55` and vulnerable `3.1.56` contain both BICs without `3af0c251`; fixed `3.1.57` contains the remediation.

## Reproduction commands

All commands are bounded to 30 seconds, replay solely against the local pools,
and suppress lazy network fetching. Each pickaxe hit must be paired with the
following `show` inspection; the hit alone is not attribution evidence.

```sh
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/lostisland__faraday \
  log --max-count=20 -S"url.start_with?('http://', 'https://', '/', './', '../')" \
  a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc^ -- lib/faraday/connection.rb
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/lostisland__faraday \
  show d8bfca25fa57c4a807f4a488f087387583c861fe -- lib/faraday/connection.rb

timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/locutusjs__locutus \
  log --follow --max-count=20 -S"key.includes('__proto__')" \
  042af9ca7fde2ff599120783e720a17f335bb01c^ -- src/php/strings/parse_str.js
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/locutusjs__locutus \
  show f2868ae0ecc55eff2644eb61f44c1df5cbc63fe9 -- src/php/strings/parse_str.js

timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/gitpython-developers__GitPython \
  log --follow --max-count=20 -S'def check_unsafe_options' \
  142195888e713542189533a52cdfc333f05c3af6^ -- git/cmd.py
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/gitpython-developers__GitPython \
  show e6108c7997f5c8f7361b982959518e982b973230 -- git/cmd.py

timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/langroid__langroid \
  log --follow --max-count=20 -S'session.execute(text(query))' \
  60933b4860a8952894b31caa0dd3f9dcba512c8e^ -- langroid/agent/special/sql/sql_chat_agent.py
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/langroid__langroid \
  show 434db35a3005a67f241331aa438aff001c8da067 -- langroid/agent/special/sql_chat_agent.py

timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/filebrowser__filebrowser \
  show 847d08bdd135e5c3659f2e6dea2f0cd36617af9b -- files/file.go http/resource.go
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/filebrowser__filebrowser \
  log --follow --max-count=20 -S'if file != nil && !file.IsSymlink' \
  847d08bdd135e5c3659f2e6dea2f0cd36617af9b^ -- files/file.go
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/filebrowser__filebrowser \
  show 8650d2ffe7a29cbafa800efcecbf6a61598a9f0c -- files/file.go

timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/gitpython-developers__GitPython \
  log --follow --max-count=20 -S'git.checkout_index' \
  af32b6e0ad4ab244dc70a5ade0f8a27ab45942f8^ -- lib/git/index.py
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/gitpython-developers__GitPython \
  log --follow --max-count=20 -S'repo.git.tag' \
  dec4663129f72321a14efd6de63f14a7419e3ed2^ -- lib/git/refs.py
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/gitpython-developers__GitPython \
  show 0ef1f89abe5b2334705ee8f1a6da231b0b6c9a50 -- lib/git/index.py
timeout 30s env GIT_NO_LAZY_FETCH=1 git -C /home/hanqing/.cache/ghsa200-sweep-fetch/gitpython-developers__GitPython \
  show 1047b41e2e925617474e2e7c9927314f71ce7365 -- lib/git/refs.py
```

## Controls and limitations

- Input SHA-256: `16f969cea3d449260c43ea21d644fd0f6639e134e4e82a2a58f1bf673e6f6703`. `CHAIN-SPEC.md` SHA-256: `c4bfd46b8887e8235eb205f727e0259e7e00f9d5fdef5dd0c0c69d4b30f7fee0`.
- First-party advisory objects came from the local `commit-gn` advisory-database clone. Commit messages, diffs, bounded pickaxe walks, limited orienting blame, ancestry, and release carriers came from the local product pools.
- Missing promised history objects were obtained only through permitted Git smart-HTTP. No GitHub API was used.
- Faraday's deepest historical sink parent and its 1.10.5 backport remain unavailable. Those gaps are recorded without turning them into AI evidence; the exact guard BIC required by the supplied fix remains a closed non-AI result.
- Worker verdicts are proposals. No canonical ledger or publication artifact was edited.
