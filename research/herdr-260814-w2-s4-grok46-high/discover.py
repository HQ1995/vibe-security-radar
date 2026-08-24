from pathlib import Path
print('cwd', Path('.').resolve())
print('owned', Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s4-grok46-high').exists())
print('slice', Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/slice-04.jsonl').exists())
print('cache', Path('/home/hanqing/.cache/ghsa200-worker-clones').exists())
print('advdb', Path('/home/hanqing/.cache/cve-analyzer/advisory-database').exists())
