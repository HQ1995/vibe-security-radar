#!/usr/bin/env python3
"""Publish the tiered 168-union research ledger into web/src/generated/research-data.json.

New generator v2: reads foundation.jsonl (+ ir-chains.jsonl for chain context),
merges with the existing 84-case generated file (which keeps its rich evidence),
fills the remaining rows mechanically from the local advisory-database and the
git pool. Missing fields are left null/"" - never fabricated.
"""
import json, os, re, subprocess, sys
from pathlib import Path
from research_lib import git, find_clones, clone_with_commit, commit_text

ROOT = Path('/home/hanqing/agents/ai-slop')
FOUNDATION = ROOT/'research/orchestrator-260814-ghsa200-canvas/foundation.jsonl'
CHAINS = ROOT/'research/orchestrator-260814-irchains-sol/ir-chains.jsonl'
OUT = ROOT/'web/src/generated/research-data.json'
BASE_BACKUP = ROOT/'web/src/generated/research-data.base84.json'
DATE_FALLBACK = ROOT/'research/orchestrator-260814-ghsa200-canvas/sweep/ghsa-first-party-dates.json'
ENRICH = ROOT/'research/orchestrator-260814-ghsa200-canvas/sweep/enrichment-fixes.json'
CODE_EVIDENCE = ROOT/'research/orchestrator-260814-ghsa200-canvas/sweep/code-evidence.json'
AI_CENSUS = ROOT/'research/orchestrator-260814-ghsa200-canvas/sweep/ai-commit-census.json'
ADB = '/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database'
POOL = '/home/hanqing/.cache/ghsa200-sweep-fetch'
CVE_REPOS = '/home/hanqing/.cache/cve-analyzer/repos'
WORKER_CLONES = '/home/hanqing/.cache/ghsa200-worker-clones'
FAMILY_PATTERNS = [
    ('claude_flow', re.compile(r'claude[- ]?flow', re.I)),
    ('copilot', re.compile(r'copilot', re.I)),
    ('cursor', re.compile(r'cursor', re.I)),
    ('openai_gpt_codex', re.compile(r'codex|gpt-|openai', re.I)),
    ('claude', re.compile(r'claude|anthropic', re.I)),
]
def detect_family(text):
    for fam, pat in FAMILY_PATTERNS:
        if pat.search(text):
            return fam
    return None

_ADB_INDEX = None
def adb_index():
    global _ADB_INDEX
    if _ADB_INDEX is not None:
        return _ADB_INDEX
    files=subprocess.run(['git','--no-optional-locks','-C',ADB,'ls-tree','-r','--name-only','origin/main',
                          'advisories/github-reviewed/','advisories/unreviewed/'],
                         capture_output=True,text=True,timeout=120).stdout.splitlines()
    idx={}
    for f in files:
        if f.endswith('.json'):
            idx.setdefault(f.split('/')[-2].lower(), f)
    _ADB_INDEX=idx
    return idx

def advisory_meta(case_id):
    gid=case_id.lower()
    f=adb_index().get(gid)
    if not f:
        return {}
    b=subprocess.run(['git','--no-optional-locks','-C',ADB,'show','origin/main:'+f],capture_output=True,text=True,timeout=30)
    if b.returncode==0:
        try:
            a=json.loads(b.stdout)
            eco=(a.get('affected') or [{}])[0].get('package',{}).get('ecosystem','')
            db=a.get('database_specific') or {}
            sev=(db.get('severity') or '').upper() or None
            if sev=='MODERATE': sev='MEDIUM'
            return {'published':(a.get('published') or '')[:10],'summary':a.get('summary') or '',
                    'severity':sev,'aliases':a.get('aliases') or [],'ecosystem':eco,
                    'description':a.get('description') or a.get('details') or None,
                    'cwes':db.get('cwe_ids') or [],
                    'references':[r.get('url') for r in (a.get('references') or []) if r.get('url')]}
        except Exception:
            return {}
    return {}

def load_date_fallbacks():
    try:
        return json.loads(DATE_FALLBACK.read_text())
    except (FileNotFoundError, ValueError):
        return {}

def load_enrichments():
    try:
        return json.loads(ENRICH.read_text())
    except (FileNotFoundError, ValueError):
        return {}

def load_code_evidence():
    try:
        return json.loads(CODE_EVIDENCE.read_text())
    except (FileNotFoundError, ValueError):
        return {}

def load_ai_census():
    try:
        a = json.loads(AI_CENSUS.read_text())
        # embed aggregate only; per-repo rows stay in the sweep artifact
        return {k: a[k] for k in ('window','repos_scanned','repos_missing',
                                  'total_commits','marked_ai_commits','families')}
    except (FileNotFoundError, ValueError, KeyError):
        return None

def commit_meta(repo,sha):
    if not repo or not sha: return None
    for path in find_clones(repo):
        m=commit_text(path,sha)
        if m is not None:
            return m
    return None

CVELIST='/home/hanqing/.cache/cve-analyzer/cvelistV5'
ECO_LANG={'PyPI':'Python','npm':'JavaScript','Go':'Go','Maven':'Java','RubyGems':'Ruby',
          'Packagist':'PHP','crates.io':'Rust','NuGet':'C#','Hex':'Elixir','Pub':'Dart',
          'SwiftURL':'Swift','GitHub Actions':'GitHub Actions'}

def cve_date(cve_id):
    """First-party published date for a CVE from the frozen cvelistV5 tree."""
    m=re.match(r'^CVE-(\d{4})-(\d+)$', (cve_id or '').strip(), re.I)
    if not m: return None
    year,num=m.group(1),int(m.group(2))
    path=os.path.join(CVELIST,'cves',year,f'{num//1000}xxx',f'CVE-{year}-{num}.json')
    if not os.path.isfile(path): return None
    try:
        return json.load(open(path)).get('cveMetadata',{}).get('datePublished') or None
    except Exception:
        return None

def cve_meta(cve_id):
    """Severity/CWE/description/references for a CVE from pinned cvelistV5."""
    m=re.match(r'^CVE-(\d{4})-(\d+)$', (cve_id or '').strip(), re.I)
    if not m: return {}
    year,num=m.group(1),int(m.group(2))
    path=os.path.join(CVELIST,'cves',year,f'{num//1000}xxx',f'CVE-{year}-{num}.json')
    if not os.path.isfile(path): return {}
    try:
        a=json.load(open(path)); cna=(a.get('containers') or {}).get('cna') or {}
    except Exception:
        return {}
    sev=''
    for mt in (cna.get('metrics') or []):
        for key in ('cvssV4_0','cvssV3_1','cvssV3_0','cvssV2_0'):
            v=(mt.get(key) or {})
            if v.get('baseSeverity'):
                sev=v['baseSeverity']; break
        if sev: break
    if sev=='MODERATE': sev='MEDIUM'
    cwes=[]
    for pt in (cna.get('problemTypes') or []):
        for d in (pt.get('descriptions') or []):
            val=(d.get('description') or '').upper()
            if val.startswith('CWE-'): cwes.append(val)
    desc=((cna.get('descriptions') or [{}])[0] or {}).get('value') or None
    refs=[r.get('url') for r in (cna.get('references') or []) if r.get('url')]
    return {'severity':sev or None,'cwes':cwes,'description':desc,'references':refs}

def advisory_full(case_id):
    gid=case_id.lower()
    f=adb_index().get(gid)
    if not f: return None
    b=subprocess.run(['git','--no-optional-locks','-C',ADB,'show','origin/main:'+f],
                     capture_output=True,text=True,timeout=30)
    if b.returncode!=0: return None
    try: return json.loads(b.stdout)
    except Exception: return None

def repo_from_advisory(a):
    if not a: return None
    for ref in (a.get('references') or []):
        if ref.get('type')=='PACKAGE':
            m=re.match(r'https?://github\.com/([^/]+/[^/]+)/?$', ref.get('url',''))
            if m: return m.group(1)
    for ref in (a.get('references') or []):
        m=re.match(r'https?://github\.com/([^/]+/[^/]+)', ref.get('url',''))
        if m and m.group(1).split('/')[0].lower()!='advisories': return m.group(1)
    return None

def ecosystem_of(a):
    if not a: return ''
    return ((a.get('affected') or [{}])[0].get('package') or {}).get('ecosystem','')

CAUSE_PATTERNS = [
    ('ssrf_network', re.compile(r'ssrf|server-side request|outbound (url|dial)|private (ip|address)', re.I)),
    ('injection', re.compile(r'xss|cross-site|injection|command|exec|sqli|ssti|rce|deserializ', re.I)),
    ('path_link', re.compile(r'travers|symlink|path (confin|bypass|escape)|link following', re.I)),
    ('auth_access', re.compile(r'auth|access control|permission|privilege|idor|tenant|session', re.I)),
    ('resource_abuse', re.compile(r'dos|denial|resource|unbounded|memory|overflow|exhaust', re.I)),
    ('validation_fail_open', re.compile(r'validat|fail[- ]open|saniti|bypass|denylist|allowlist', re.I)),
]
def cause_of(text):
    t = (text or '').lower()
    for k, pat in CAUSE_PATTERNS:
        if pat.search(t):
            return k
    return 'other_ambiguous'

def enrich(cases):
    """Fill null published_at / empty repository / empty language from pinned
    cvelistV5 (CVE aliases) and the advisory-database. Never fabricates; any
    gap left behind is recorded as unresolved by the caller."""
    for c in cases:
        a=None
        if not c.get('published_at'):
            for alias in (c.get('aliases') or []):
                if alias.upper().startswith('CVE-'):
                    date=cve_date(alias)
                    if date:
                        c['published_at']=date
                        break
            if not c.get('published_at'):
                a=a or advisory_full(c['case_id'])
                if a and a.get('published'):
                    c['published_at']=a['published'][:10]
        need_repo=not c.get('repository')
        need_lang=not (c.get('repository_metadata') or {}).get('language')
        if need_repo or need_lang:
            a=a or advisory_full(c['case_id'])
            if a:
                if need_repo:
                    repo=repo_from_advisory(a)
                    if repo:
                        c['repository']=repo
                        c['repository_metadata']['full_name']=repo
                if need_lang:
                    lang=ECO_LANG.get(ecosystem_of(a),'')
                    if lang:
                        c['repository_metadata']['language']=lang
    for c in cases:
        lm=c.get('repository_metadata') or {}
        lang=lm.get('language')
        if lang in ECO_LANG:
            lm['language']=ECO_LANG[lang]

# load 168 foundation
found=[json.loads(l) for l in open(FOUNDATION) if l.strip()]
# load existing 84 (rich)
# base = the original 84 rich cases (kept as a separate file, not the
# previously generated 168 output, so re-runs do not freeze stale rows)
existing={}
if not BASE_BACKUP.exists() and OUT.exists():
    BASE_BACKUP.write_text(OUT.read_text())
if BASE_BACKUP.exists():
    d=json.loads(BASE_BACKUP.read_text())
    for c in d.get('cases',[]):
        c.setdefault('tier','all_pass')
        c['research_status']='HOLD'
        existing[c['case_id'].upper()]=c
else:
    d={'snapshot':{},'cases':[],'cause_categories':{},'ai_provenance_families':{}}

chains={}
for l in open(CHAINS):
    r=json.loads(l)
    chains[r.get('case_id','').upper()]=r

REPO_RE = re.compile(r'github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)', re.I)
def email_family(email, name):
    t = (str(email)+' '+str(name)).lower()
    if 'anthropic' in t or 'claude' in t: return 'claude'
    if 'copilot' in t: return 'copilot'
    if 'cursor' in t: return 'cursor'
    if 'openai' in t or 'codex' in t or 'gpt' in t: return 'openai_gpt_codex'
    return None

cases=list(existing.values())
have={c['case_id'].upper() for c in cases}
for r in found:
    cid=r['case_id'].upper()
    if cid in have: continue
    meta=advisory_meta(r['case_id'])
    a_full=advisory_full(r['case_id'])
    repo=r.get('repository')
    ev_text=' '.join(list(r.get('decisive_evidence') or [])+list(r.get('counterevidence') or []))
    repo = repo or (REPO_RE.search(ev_text).group(1) if REPO_RE.search(ev_text) else None)
    slug = re.search(r'([A-Za-z0-9_.-]+)__([A-Za-z0-9_.-]+)__GHSA-[a-z0-9-]+', ev_text, re.I)
    repo = repo or (f'{slug.group(1)}/{slug.group(2)}' if slug else None)
    repo = repo or (repo_from_advisory(a_full) if a_full else None)
    cand=(r.get('candidate_set') or [None])[0]
    fix=(r.get('minimum_fix_set') or [None])[0]
    cm=commit_meta(repo,cand) or {}
    fm=commit_meta(repo,fix) or {}
    msg=' '.join([cm.get('subject',''),cm.get('body',''),cm.get('author_name',''),cm.get('author_email','')])
    fam = detect_family(msg) or email_family(cm.get('author_email'), cm.get('author_name'))
    ai_generic = not fam and bool(re.search(r'\[ai\]|ai[- ]assist|ai[- ]generat', msg, re.I))
    if fam is None:
        # fallback: the row's own recorded evidence (leader replay marker or
        # fp211 decisive/counterevidence text usually names the tool)
        ev = ' '.join([str(r.get('leader_replay',{}).get('ai_marker') or '')]
                      + list(r.get('decisive_evidence') or [])
                      + list(r.get('counterevidence') or []))
        fam = detect_family(ev)
    gates=r.get('gates') or {}
    ch=chains.get(cid) or {}
    ov=ch.get('original_vulnerability') or {}
    if fam is None:
        bic=ch.get('original_introducing_commit') or {}
        fam = email_family(bic.get('author_email'), bic.get('author_name'))
    mech = meta.get('summary') or (ch.get('attempted_remediation') or {}).get('changed') or (r.get('decisive_evidence') or [None])[0]
    case={
      'case_id':r['case_id'],
      'aliases':meta.get('aliases') or [],
      'repository':repo,
      'repository_metadata':{'full_name':repo or '','language':meta.get('ecosystem') or '','archived':False},
      'contribution_class':r.get('contribution_class') or 'UNKNOWN',
      'candidate_set':r.get('candidate_set') or [],
      'carrier_set':r.get('carrier_set') or [],
      'minimum_fix_set':r.get('minimum_fix_set') or [],
      'gates':{'identity':gates.get('identity_gate','UNKNOWN'),'ai_hunk':gates.get('ai_hunk_gate','UNKNOWN'),
               'topology':gates.get('topology_gate','UNKNOWN'),'but_for':gates.get('but_for_gate','UNKNOWN'),
               'fix_reversal':gates.get('fix_reversal_gate','UNKNOWN'),'release':gates.get('release_gate','UNKNOWN'),
               'uniqueness':gates.get('uniqueness_gate','UNKNOWN')},
      'vulnerable_release':None,
      'fixed_release':None,
      'published_at':meta.get('published') or load_date_fallbacks().get(r['case_id']),
      'severity':meta.get('severity'),
      'cwes':meta.get('cwes') or [],
      'description':meta.get('description'),
      'references':meta.get('references') or [],
      'mechanism_key':r.get('mechanism_key') or None,
      'mechanism':mech,
      'scope_statement':(r.get('decisive_evidence') or [None])[0] if r.get('tier')=='scoped_contribution' else None,
      'cause_category':cause_of(mech),
      'ai_provenance':{'family':fam,'coverage':'complete' if fam else ('generic' if ai_generic else 'unresolved'),
                       'candidate_count':len(r.get('candidate_set') or []),
                       'named_candidate_count':len(r.get('candidate_set') or []),
                       'note':(ov.get('original_mechanism') or '')[:200] or None},
      'fix_authorship':{'classification':'ai_assisted' if detect_family(fm.get('body','')) else ('no_ai_marker' if fm else 'mixed'),
                        'families':[x for x in [detect_family(fm.get('body',''))] if x],
                        'fixes':[{'sha':fix,'classification':'ai_assisted' if detect_family(fm.get('body','')) else 'no_ai_marker',
                                  'author':{'name':fm.get('author_name',''),'email':fm.get('author_email','')}}] if fix else []},
      'code_evidence':None,
      'tier':r.get('tier'),
      'research_status':'HOLD',
    }
    cases.append(case)

enrich(cases)

# First-party GHSA severity/CWE/description/references for every case, so the
# site no longer needs the legacy 36-case catalog. Memoized; local advisory DB.
_sev_cache={}
def _meta_cached(cid):
    if cid not in _sev_cache:
        _sev_cache[cid]=advisory_meta(cid)
    return _sev_cache[cid]
for c in cases:
    m=_meta_cached(c.get('case_id','') or '')
    cves={}
    for alias in (c.get('aliases') or []):
        if alias.upper().startswith('CVE-') and alias.upper() not in cves:
            cves[alias.upper()]=cve_meta(alias)
    if not c.get('severity'):
        c['severity']=m.get('severity') or next((v['severity'] for v in cves.values() if v.get('severity')), None)
    if not c.get('cwes'):
        merged=[]
        for v in [m] + list(cves.values()):
            for cwe in (v.get('cwes') or []):
                if cwe not in merged: merged.append(cwe)
        c['cwes']=merged
    if not c.get('description'):
        c['description']=m.get('description') or next((v.get('description') for v in cves.values() if v.get('description')), None)
    if not c.get('references'):
        merged=[]
        for v in [m] + list(cves.values()):
            for u in (v.get('references') or []):
                if u not in merged: merged.append(u)
        c['references']=merged

all_pass=sum(1 for c in cases if c.get('tier')=='all_pass')
scoped=sum(1 for c in cases if c.get('tier')=='scoped_contribution')
fb = {k.lower(): v for k, v in load_date_fallbacks().items()}
enr = {k.lower(): v for k, v in load_enrichments().items()}
ce = {k.lower(): v for k, v in load_code_evidence().items()}
for c in cases:
    if (c.get('contribution_class') or '').startswith('AI_INCOMPLETE_REMEDIATION') and not c.get('ir_chain'):
        ch2 = chains.get(c.get('case_id','').upper())
        if ch2:
            ov2 = ch2.get('original_vulnerability') or {}
            bic = ch2.get('original_introducing_commit') or {}
            c['ir_chain'] = {
                'original_advisory_ids': ch2.get('original_advisory_ids') or ov2.get('original_advisory_ids') or [],
                'original_mechanism': ov2.get('original_mechanism') or ch2.get('original_mechanism'),
                'original_sink': ov2.get('original_sink'),
                'original_author_kind': ch2.get('original_author_kind'),
                'original_author_name': bic.get('author_name') or None,
                'original_sha': bic.get('sha') if isinstance(bic, dict) else None,
                'attempted_remediation': ch2.get('attempted_remediation') or ov2.get('attempted_remediation') or None,
                'residual_bypass': ov2.get('residual_bypass'),
                'final_closure': ch2.get('final_closure') or ov2.get('final_closure') or None,
            }
    if not c.get('published_at') and (c.get('case_id') or '').lower() in fb:
        c['published_at'] = fb[(c.get('case_id') or '').lower()]
    e = enr.get((c.get('case_id') or '').lower())
    if e:
        for k in ('repository','mechanism','scope_statement','cause_category',
                  'description','severity','cwes','aliases','references','published_at'):
            if not c.get(k) and e.get(k):
                c[k] = e[k]
        if not (c.get('repository_metadata') or {}).get('language') and e.get('language'):
            c.setdefault('repository_metadata', {})['language'] = e['language']
        ap = c.setdefault('ai_provenance', {})
        if not ap.get('family') and e.get('family'):
            ap['family'] = e['family']
            ap['coverage'] = 'complete'
    if not c.get('code_evidence') and ce.get((c.get('case_id') or '').lower()):
        c['code_evidence'] = ce[(c.get('case_id') or '').lower()]
# Infer missing language from local code-hunk file extensions (deterministic,
# no GitHub API). Leave empty when there is no code evidence to derive from.
EXT_LANG={'php':'PHP','ts':'TypeScript','tsx':'TypeScript','js':'JavaScript','jsx':'JavaScript','mjs':'JavaScript',
          'py':'Python','go':'Go','rs':'Rust','rb':'Ruby','cs':'C#','swift':'Swift','java':'Java','kt':'Kotlin',
          'kts':'Kotlin','ex':'Elixir','exs':'Elixir','vue':'Vue','dart':'Dart','scala':'Scala','sh':'Shell',
          'pl':'Perl','c':'C/C++','h':'C/C++','cpp':'C/C++','cc':'C/C++','hpp':'C/C++'}
def lang_from_hunks(c):
    counts={}
    for key in ('comparison_hunks','fix_hunks','candidate_hunks'):
        for h in (c.get('code_evidence') or {}).get(key) or []:
            lang=EXT_LANG.get(os.path.splitext((h or {}).get('file') or '')[1].lstrip('.').lower())
            if lang:
                counts[lang]=counts.get(lang,0)+1
    return max(counts, key=counts.get) if counts else ''

def lang_from_repo(repo):
    # Root marker-file heuristic over local clones; deterministic, no API.
    if not repo:
        return ''
    for path in find_clones(repo):
        root = Path(path)
        if not root.is_dir():
            continue
        if (root/'composer.json').exists(): return 'PHP'
        if (root/'go.mod').exists(): return 'Go'
        if (root/'Cargo.toml').exists(): return 'Rust'
        if (root/'Gemfile').exists(): return 'Ruby'
        if (root/'Package.swift').exists(): return 'Swift'
        if (root/'pom.xml').exists(): return 'Java'
        if (root/'package.json').exists():
            return 'TypeScript' if (root/'tsconfig.json').exists() else 'JavaScript'
    return ''

for c in cases:
    lm=c.get('repository_metadata') or {}
    if not lm.get('language'):
        lm['language']=lang_from_hunks(c) or lang_from_repo(c.get('repository'))
        c['repository_metadata']=lm
snap={'status':'HOLD','case_set':'UNION_168_TIERED','case_count':len(cases),
      'exact_publication_dates':sum(1 for c in cases if c.get('published_at')),
      'unknown_publication_dates':sum(1 for c in cases if not c.get('published_at')),
      'date_policy':'EXACT_GHSA_ID_FROM_PINNED_FIRST_PARTY_EVIDENCE',
      'source_cutoff':'2026-08-15T00:00:00Z'}
d['snapshot']=snap
d['cases']=cases
census=load_ai_census()
if census:
    d['ai_commit_census']=census
OUT.write_text(json.dumps(d,indent=1)+'\n')
print('cases:',len(cases),'all_pass:',all_pass,'scoped:',scoped,'->',OUT)
