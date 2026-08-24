#!/usr/bin/env python3
import json, re
markers = [
    r'co-authored-by:', r'assisted-by:', r'generated with claude', r'generated with codex',
    r'generated with copilot', r'claude code', r'claude opus', r'claude sonnet',
    r'github copilot', r'cursor', r'devin', r'jules', r'rovo',
    r'qwen code', r'openwork', r'qoder', r'coderabbit', r'kimi',
    r'grok', r'trae', r'ai-assisted', r'ai-generated',
]
pat = re.compile('|'.join(markers), re.I)
data = json.load(open('autoresearch/orchestrator-260814-ghsa200-canvas/wave2/directroot-fetch-scan.json'))
hits = [r for r in data if pat.search(r.get('msg', ''))]
print('marker hits:', len(hits), 'of', len(data))
for r in hits:
    print('HIT', r['key'], r['sha'][:10], r['msg'].splitlines()[0][:75])
for r in data:
    r['marker'] = bool(pat.search(r.get('msg', '')))
json.dump(data, open('autoresearch/orchestrator-260814-ghsa200-canvas/wave2/directroot-fetch-scan.json', 'w'), indent=1)

