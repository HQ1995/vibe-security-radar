#!/usr/bin/env python3
import os, subprocess, json
from pathlib import Path
ROOTS=[
'/home/hanqing/.cache/ghsa200-worker-clones',
'/home/hanqing/.cache/cve-analyzer/repos',
]
ORDS={
35:['473c32270d72252ee6753afc35c3ea4360d169e0','bc972505e381b12ad999e5066d3fe5770c5e1bd4','b1de75a7c67ce6aee977bd788b41e61837dbe0b9','733c20fc9d4af7c109c711315e63bbd21623e62f'],
51:['f05553413db29ebcf5d8c75c8a6154a9e9987690','daf13dbb0616115bf0aa946f46c3ba2afb93d283','a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf','78ec0a1edfcd113840e0f0a5a510031d3bcc16ee'],
53:['b7b362ae427ccf4b33b8e8cd147f16410f3ce800','7d1ddbfdb8296058ab787f7c57b8943c0214d14d','23838a995955'],
56:['c139c021f68a09d22c2af88641b61c00f67f2af4','57b7634391959dbbdb39b387ac4dc68157cd58a1','5e5a80b5'],
84:['57b7634391959dbbdb39b387ac4dc68157cd58a1','fdf67a6fba0deae30912905a79fb5a9e83751a79'],
116:['e1fe58639756cf7b232458eddd6978e4ed0031f5','98569e4edbfc316877c9e0d27ea89fab3c49e3bd','e1d4b4682efc898ba5aa3751b2da2072f89c7e24'],
129:['251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34','2727f3f701677d467dfb5e053c57237cbc752c3c','277e9cef0ad16d7eaaab253573d0695951a65dbd','358cc3968c8f06f1be0967e41df191088db0b662'],
153:['bc182d55dde5686a36ca2eb88fe6c2adabb9fad9','025f711506850aadb69cde1b57e5e5d57628c87f'],
154:['aa42da361821ddfbb85b126564e71587347d2786','a52b92461cf39d983f51ce8724fe7e6b944073e4'],
}
need=set()
for v in ORDS.values():
    need.update(v)
repos=[]
for root in ROOTS:
    if not os.path.isdir(root): continue
    for dirpath, dirnames, filenames in os.walk(root):
        if '.git' in dirnames or os.path.basename(dirpath)=='.git' or 'HEAD' in filenames and os.path.isdir(os.path.join(dirpath,'objects')):
            gitdir=dirpath if os.path.basename(dirpath)=='.git' or (os.path.isdir(os.path.join(dirpath,'objects')) and 'HEAD' in filenames) else dirpath
            # only treat as git if .git exists or this is a git dir
            if os.path.isdir(os.path.join(dirpath,'.git')):
                repos.append(dirpath)
                dirnames[:] = []
            elif os.path.basename(dirpath)=='.git':
                repos.append(os.path.dirname(dirpath))
                dirnames[:] = []
print('REPOCOUNT', len(repos))
# restrict to likely names
keys=('coolify','openclaw','wacrm','taylored','argo','misp','omnifaces')
repos=[r for r in repos if any(k in r.lower() for k in keys)]
print('FILTERED', len(repos))
for r in repos:
    print('R', r)
out={}
for ord_, shas in ORDS.items():
    out[str(ord_)]=[]
    for sha in shas:
        hits=[]
        for r in repos:
            p=subprocess.run(['git','-C',r,'cat-file','-t',sha],capture_output=True,text=True)
            if p.returncode==0:
                hits.append(r+' '+p.stdout.strip())
        out[str(ord_)].append({'sha':sha,'hits':hits[:5],'nhits':len(hits)})
Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-final-unknown9-grok46-high/sha_hits.json').write_text(json.dumps(out,indent=2))
print('WROTE')
