# Command record

All commands ran from `/home/hanqing/agents/ai-slop`. Git reads used `-c gc.auto=0 -c maintenance.auto=false`. Commands were sequential; no build or runtime test was run.

```sh
mkdir -p autoresearch/herdr-260812-b2-unknown-r25-36/{snapshot,clones,tmp}
cp autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl autoresearch/herdr-260812-b2-unknown-r25-36/snapshot/unresolved-inventory.jsonl
jq -c 'select(.resolvability_rank >= 25 and .resolvability_rank <= 36)' autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl > autoresearch/herdr-260812-b2-unknown-r25-36/snapshot/ranks-25-36.jsonl
sha256sum autoresearch/herdr-260812-b2-unknown-r25-36/snapshot/{unresolved-inventory,ranks-25-36}.jsonl
git -c gc.auto=0 -c maintenance.auto=false rev-parse HEAD
git -c gc.auto=0 -c maintenance.auto=false status --porcelain=v1 -z | sha256sum
```

The slice command actually read the frozen source path `autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl`; the output was saved as `snapshot/ranks-25-36.jsonl`. The command above preserves the selection predicate; validation below is authoritative for its contents.

Missing repositories were cloned only under the owned directory:

```sh
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout https://github.com/absinthe-graphql/absinthe.git autoresearch/herdr-260812-b2-unknown-r25-36/clones/absinthe
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout https://github.com/JasonLovesDoggo/caddy-defender.git autoresearch/herdr-260812-b2-unknown-r25-36/clones/caddy-defender
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout https://github.com/SWivid/F5-TTS.git autoresearch/herdr-260812-b2-unknown-r25-36/clones/f5-tts
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout https://github.com/Jovancoding/Network-AI.git autoresearch/herdr-260812-b2-unknown-r25-36/clones/network-ai
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout https://github.com/Alfredredbird/tookie-osint.git autoresearch/herdr-260812-b2-unknown-r25-36/clones/tookie-osint
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout https://github.com/libexpat/libexpat.git autoresearch/herdr-260812-b2-unknown-r25-36/clones/libexpat
git -c gc.auto=0 -c maintenance.auto=false clone --filter=blob:none --no-checkout https://github.com/dedecms/DedeCMS.git autoresearch/herdr-260812-b2-unknown-r25-36/clones/dedecms
```

The same bounded read patterns were applied per target path/ref:

```sh
git -c gc.auto=0 -c maintenance.auto=false -C REPO show -s --format='%H%n%P%n%aI%n%an <%ae>%n%B' REF
git -c gc.auto=0 -c maintenance.auto=false -C REPO show --name-status --format='' REF
git -c gc.auto=0 -c maintenance.auto=false -C REPO log --all --format='%H%x09%aI%x09%an%x09%s' -S 'MECHANISM_TOKEN' -- TARGET_PATH
git -c gc.auto=0 -c maintenance.auto=false -C REPO log --all --regexp-ignore-case --extended-regexp --grep='(co-authored-by:.*(copilot|claude|chatgpt|gemini|cursor|openai|anthropic)|generated[- ]by|generated with.*claude)' --format='%H%x09%aI%x09%s' -- TARGET_PATH
git -c gc.auto=0 -c maintenance.auto=false -C REPO blame FIX^ -L START,END -- TARGET_PATH
git -c gc.auto=0 -c maintenance.auto=false -C REPO merge-base --is-ancestor ORIGIN FIX
git -c gc.auto=0 -c maintenance.auto=false -C REPO merge-base --is-ancestor FIX RELEASE_TAG
git -c gc.auto=0 -c maintenance.auto=false -C REPO rev-parse 'RELEASE_TAG^{commit}'
```

Negative control: four unauthenticated calls to `https://api.github.com/advisories?cve_id=...` returned HTTP 403; no response files or credentials were retained. Exact public URLs used after that failure are listed row-by-row in `recommendation-ledger.jsonl`.

Terminal validation:

```sh
jq -e . autoresearch/herdr-260812-b2-unknown-r25-36/result.json
jq -s -e 'length == 12 and ([.[].rank] == [25,26,27,28,29,30,31,32,33,34,35,36])' autoresearch/herdr-260812-b2-unknown-r25-36/recommendation-ledger.jsonl
jq -s -e 'length == 12 and ([.[].resolvability_rank] == [25,26,27,28,29,30,31,32,33,34,35,36])' autoresearch/herdr-260812-b2-unknown-r25-36/snapshot/ranks-25-36.jsonl
sha256sum autoresearch/herdr-260812-b2-unknown-r25-36/report.md autoresearch/herdr-260812-b2-unknown-r25-36/recommendation-ledger.jsonl autoresearch/herdr-260812-b2-unknown-r25-36/snapshot/source-snapshot.json
```
