import json, os
from pathlib import Path
owned = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s3-grok46-high')
root = Path('/home/hanqing/agents/ai-slop/autoresearch')
clone_root = Path('/home/hanqing/.cache/ghsa200-worker-clones')
lines = []
# prior worker result.json files
found = []
for d in sorted(root.glob('herdr-260814-w2-*')):
    for name in ('result.json','cases.jsonl','report.md'):
        f = d/name
        if f.exists() and f.stat().st_size:
            found.append(str(f))
lines.append('PRIOR_OUTPUTS '+str(len(found)))
lines.extend(found[:40])
# clone mapping for slice repos
repos = [
 'thephpleague/commonmark','dep0we/atomic-agents-stack','electron/electron',
 'mermaid-js/mermaid','open-webui/open-webui','vllm-project/vllm',
 'FlowiseAI/Flowise','nodejs/undici','seaweedfs/seaweedfs'
]
lines.append('CLONE_HITS')
for repo in repos:
    slug = repo.replace('/','__')
    hits=[]
    if clone_root.exists():
        for camp in clone_root.iterdir():
            p = camp/slug
            if p.exists():
                hits.append(str(p))
    lines.append(repo+' '+str(len(hits))+' '+(hits[0] if hits else 'NONE'))
# advisory files
adv_root = Path('/home/hanqing/.cache/cve-analyzer/advisory-database')
ghsas = ['GHSA-JFM3-95JQ-Q3RF','GHSA-RM43-82J9-R4MJ','GHSA-4F78-QHMW-8J8M','GHSA-C4C3-PG64-4M4V','GHSA-MJ63-M3RC-8PPR','GHSA-8X5V-CPV7-8JJP','GHSA-87X5-VMC3-756J','GHSA-WG86-R78F-74MP','GHSA-MJ5R-JF49-M3W7','GHSA-9F4C-93C8-JC8G','GHSA-5XVG-PMGG-3MXR','GHSA-CHM3-VQCF-52RX','GHSA-XC48-889X-5QMW','GHSA-FR6G-7CQ8-FG82','GHSA-JR45-8VMC-QM54','GHSA-W62W-66V9-VVGV','GHSA-RQ84-P6RR-VF89','GHSA-F2R8-JV7C-XQMP']
lines.append('ADVISORY_HITS')
for g in ghsas:
    g=g.lower()
    year=None
    # GHSA files live under advisories/github-reviewed/YYYY/MM/<id>.json
    hits=[]
    if adv_root.exists():
        for p in adv_root.glob('advisories/github-reviewed/*/*/'+g+'.json'):
            hits.append(str(p))
            break
    lines.append(g+' '+str(len(hits))+' '+(hits[0] if hits else 'NONE'))
out = owned/'_discover.txt'
out.write_text('
'.join(lines)+'
')
print('wrote', out, 'bytes', out.stat().st_size)
