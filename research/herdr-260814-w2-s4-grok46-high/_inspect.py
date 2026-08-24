import json, os
from pathlib import Path
root = Path('/home/hanqing/agents/ai-slop/autoresearch')
out = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s4-grok46-high/_inspect_out.txt')
lines = []
for name in ['herdr-260814-w2-s3-grok46-high','herdr-260814-w2-s4-grok46-high','herdr-260814-w2-s5-grok46-high','herdr-260814-w2-sample12-grok46-high']:
    d = root/name
    lines.append('DIR '+name+' exists='+str(d.exists()))
    if d.exists():
        lines.append('  files='+', '.join(sorted(x.name for x in d.iterdir() if x.is_file())[:30]))
        for fn in ['result.json','cases.jsonl','report.md']:
            f=d/fn
            lines.append('  '+fn+' exists='+str(f.exists())+' size='+str(f.stat().st_size if f.exists() else 0))
        rj=d/'result.json'
        if rj.exists():
            data=json.loads(rj.read_text())
            lines.append('  result keys='+', '.join(list(data)[:40]))
            if 'rows' in data: lines.append('  n_rows='+str(len(data['rows'])))
            if 'verdicts' in data: lines.append('  verdicts keys='+', '.join(list(data['verdicts'])[:20]) if isinstance(data['verdicts'], dict) else str(type(data['verdicts'])))
            lines.append('  result head='+json.dumps(data)[:1500])
        cj=d/'cases.jsonl'
        if cj.exists() and cj.stat().st_size:
            first=cj.read_text().splitlines()[0]
            lines.append('  case0='+first[:1500])
out.write_text('
'.join(lines))
print('WROTE', out, 'bytes', out.stat().st_size)
