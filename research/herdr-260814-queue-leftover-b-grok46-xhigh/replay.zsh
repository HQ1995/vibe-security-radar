#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat GIT_ASKPASS=
# Unset credential-bearing variables without printing names or values.
typeset -a _drop
_drop=()
for _n in ${(k)parameters}; do
  case $_n in
    *TOKEN*|*KEY*|*SECRET*|*PASSWORD*|*AUTH*) _drop+=($_n) ;;
  esac
done
for _n in ${_drop}; do
  unset $_n 2>/dev/null || true
done
unset _drop _n
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, subprocess, os, re

ROOT=Path('/home/hanqing/agents/ai-slop')
OWN=ROOT/'autoresearch/herdr-260814-queue-leftover-b-grok46-xhigh'
SRC=ROOT/'autoresearch/herdr-260814-nextqueue-v2-grok46-low'
res=json.loads((OWN/'result.json').read_text())
pins=res['current_input_hashes']

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT/'autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')==pins['CONTRACT.md']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl')==pins['canonical94_ledger.jsonl']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json')==pins['canonical94_summary.json']
assert h(SRC/'assignment.jsonl')==pins['source_assignment.jsonl']
assert h(SRC/'cases.jsonl')==pins['source_cases.jsonl']
assert h(SRC/'result.json')==pins['source_result.json']
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
for p in OWN.iterdir():
    if p.is_file():
        assert all(b<128 for b in p.read_bytes()), p.name

src=json.loads((SRC/'result.json').read_text())
want=['GHSA-9Q9Q-324X-93R2','GHSA-FRH3-6PV6-RC8J','GHSA-PF94-94M9-536P','GHSA-Q6V9-R226-V65F','GHSA-RF5Q-VWXW-GMRF','GHSA-V56Q-MH7H-F735']
assert src['leftover_ids'][-6:]==want
assert src['leftover_ids'][:5]==['GHSA-R54C-2XMF-2CF3','GHSA-V5MV-P594-2X33','GHSA-V95X-XHQ5-4929','GHSA-WVMP-6R4V-J6CV','GHSA-375F-4R2H-F99J']
assert set(want).isdisjoint(src['queued_ids'])
assert set(want).isdisjoint(src['leftover_ids'][:5])
a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/'cases.jsonl').read_text().splitlines() if l.strip()]
assert [x['case_id'] for x in a]==[x['case_id'] for x in c]==want
assert len(set(want))==6
assert all(x['verdict']=='REJECT' for x in c)
assert all(x['proposed_pass'] is False and x['countable_pass'] is False for x in c)
assert all(x['gates']['ai_hunk_gate']=='FAIL' for x in c)
assert all(x['gates']['identity_gate']=='PASS' for x in c)
assert all(x['gates']['uniqueness_gate']=='PASS' for x in c)
assert not any(all(v=='PASS' for v in x['gates'].values()) for x in c)
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['conservation']['equation']=='6=6+0' and res['conservation']['holds']
assert res['canonical94_strict_count']==94
canon=set(str(x).upper() for x in json.loads((ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json').read_text())['strict_released_case_ids'])
assert len(canon)==94
assert not set(want)&canon
text=(OWN/'report.md').read_text()
assert 'PASS=0' in text and '6=6+0' in text
assert 'Worker PASS is proposal-only' in text
assert 'leftover_ids suffix exactly' in text
assert res['did_not_use_github_api_or_credentials'] is True
assert res['anonymous_public_access_only'] is True
assert res['no_network_in_replay'] is True

ADV=Path('/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database')
_cred=re.compile(r'(TOKEN|KEY|SECRET|PASSWORD|AUTH)', re.I)
env={k:v for k,v in os.environ.items() if _cred.search(k) is None}
env['PATH']='/usr/local/bin:/usr/bin:/bin'
env['GIT_OPTIONAL_LOCKS']='0'
env['GIT_TERMINAL_PROMPT']='0'
env['GIT_NO_LAZY_FETCH']='1'
env['GIT_PAGER']='cat'
env['GIT_ASKPASS']=''
_git=['git','-c','protocol.https.allow=never','-c','protocol.http.allow=never','-c','protocol.git.allow=never','-c','protocol.ssh.allow=never']

def git_out(repo,*args):
    p=subprocess.run([*_git,'-C',str(repo),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,check=False)
    err=p.stderr.decode()
    keep=[]
    for line in err.splitlines():
        if 'unable to normalize alternate object path' in line: continue
        if 'lazy fetching disabled' in line: continue
        if line.strip():
            keep.append(line)
    if p.returncode!=0 or keep:
        raise SystemExit('git fail '+str(args)+' '+'\n'.join(keep))
    return p.stdout.decode().strip()

assert git_out(ADV,'rev-parse','HEAD')==res['advisory_database']['head']
assert git_out(ADV,'rev-parse','HEAD:advisories/github-reviewed')==res['advisory_database']['github_reviewed_tree']
paths={
 'GHSA-9Q9Q-324X-93R2':'advisories/github-reviewed/2026/05/GHSA-9q9q-324x-93r2/GHSA-9q9q-324x-93r2.json',
 'GHSA-FRH3-6PV6-RC8J':'advisories/github-reviewed/2026/05/GHSA-frh3-6pv6-rc8j/GHSA-frh3-6pv6-rc8j.json',
 'GHSA-PF94-94M9-536P':'advisories/github-reviewed/2026/05/GHSA-pf94-94m9-536p/GHSA-pf94-94m9-536p.json',
 'GHSA-Q6V9-R226-V65F':'advisories/github-reviewed/2026/05/GHSA-q6v9-r226-v65f/GHSA-q6v9-r226-v65f.json',
 'GHSA-RF5Q-VWXW-GMRF':'advisories/github-reviewed/2026/05/GHSA-rf5q-vwxw-gmrf/GHSA-rf5q-vwxw-gmrf.json',
 'GHSA-V56Q-MH7H-F735':'advisories/github-reviewed/2026/07/GHSA-v56q-mh7h-f735/GHSA-v56q-mh7h-f735.json',
}
for cid,rel in paths.items():
    got=h(ADV/rel)
    assert got==res['first_party_advisory_sha256'][cid], (cid,got)

cl=res['read_only_clones']
po=res['pinned_objects']
B=cl['bandit']
I=cl['immutable_js']

assert git_out(B,'rev-parse',po['ae3520_fix'])==po['ae3520_fix']
assert git_out(B,'rev-parse',po['ae3520_fix']+'^:lib/bandit/http1/socket.ex')==po['socket_parent']
assert git_out(B,'rev-parse',po['ae3520_fix']+':lib/bandit/http1/socket.ex')==po['socket_fixed']
parent_sock=git_out(B,'show',po['ae3520_fix']+'^:lib/bandit/http1/socket.ex')
assert 'We should be reading (and ignoring) trailers here' in parent_sock
assert 'do_read_chunked_data!(socket, buffer, body, read_size, read_timeout)' in parent_sock
fixed_sock=git_out(B,'show',po['ae3520_fix']+':lib/bandit/http1/socket.ex')
assert 'Keyword.get(opts, :length, 8_000_000)' in fixed_sock
assert '{:more, body, buffer}' in fixed_sock
assert git_out(B,'show','-s','--format=%an',po['ae3520_fix'])=='Mat Trudel'
a330_files=git_out(B,'diff-tree','-r','--name-only','--no-commit-id',po['bandit_claude_ci'])
assert a330_files=='.github/workflows/elixir.yml'
body=git_out(B,'show','-s','--format=%B',po['bandit_claude_ci'])
assert 'Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>' in body
assert git_out(B,'show','-s','--format=%an',po['bandit_e73e379_named_intro'])=='Mat Trudel'
e73_files=set(git_out(B,'diff-tree','-r','--name-only','--no-commit-id',po['bandit_e73e379_named_intro']).splitlines())
assert e73_files=={'lib/bandit/http1/handler.ex','lib/bandit/http1/socket.ex','test/bandit/http1/request_test.exs'}

assert git_out(B,'rev-parse',po['frh3_fix']+'^:lib/bandit/websocket/permessage_deflate.ex')==po['deflate_parent']
assert git_out(B,'rev-parse',po['frh3_fix']+':lib/bandit/websocket/permessage_deflate.ex')==po['deflate_fixed']
parent_def=git_out(B,'show',po['frh3_fix']+'^:lib/bandit/websocket/permessage_deflate.ex')
assert ':zlib.inflate(' in parent_def
assert 'safeInflate' not in parent_def
fixed_def=git_out(B,'show',po['frh3_fix']+':lib/bandit/websocket/permessage_deflate.ex')
assert 'safeInflate' in fixed_def
assert git_out(B,'rev-list','--parents','-n','1',po['frh3_fix']).count(' ')==1

assert git_out(B,'rev-parse',po['pf94_fix']+'^:lib/bandit/websocket/connection.ex')==po['conn_parent']
assert git_out(B,'rev-parse',po['pf94_fix']+':lib/bandit/websocket/connection.ex')==po['conn_fixed']
assert git_out(B,'rev-parse',po['pf94_fix']+'^')==po['frh3_fix']
parent_conn=git_out(B,'show',po['pf94_fix']+'^:lib/bandit/websocket/connection.ex')
assert 'oversize_message?' not in parent_conn
assert 'fragment_frame.data' in parent_conn
fixed_conn=git_out(B,'show',po['pf94_fix']+':lib/bandit/websocket/connection.ex')
assert 'oversize_message?' in fixed_conn

assert git_out(B,'rev-parse',po['q6v9_fix']+'^:lib/bandit/http2/frame.ex')==po['frame_parent']
assert git_out(B,'rev-parse',po['q6v9_fix']+':lib/bandit/http2/frame.ex')==po['frame_fixed']
parent_fr=git_out(B,'show',po['q6v9_fix']+'^:lib/bandit/http2/frame.ex')
assert '_payload::binary-size(length), rest::binary>>' in parent_fr
fixed_fr=git_out(B,'show',po['q6v9_fix']+':lib/bandit/http2/frame.ex')
assert 'when length > max_frame_size do' in fixed_fr

assert git_out(I,'rev-parse',po['imm_claude_ops'])==po['imm_claude_ops']
ops_files=set(git_out(I,'diff-tree','-r','--name-only','--no-commit-id',po['imm_claude_ops']).splitlines())
assert ops_files=={'__tests__/IndexedSeq.ts','src/Operations.js'}
assert 'src/List.js' not in ops_files
ops_body=git_out(I,'show','-s','--format=%B',po['imm_claude_ops'])
assert 'Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>' in ops_body
assert git_out(I,'rev-list','--parents','-n','1',po['a1a1ee_merge'])==po['a1a1ee_merge']+' '+po['a1a1ee_p1']+' '+po['a1a1ee_p2']
assert git_out(I,'show','-s','--format=%an',po['a1a1ee_p2'])=='Julien Deniau'
p2_files=set(git_out(I,'diff-tree','-r','--name-only','--no-commit-id',po['a1a1ee_p2']).splitlines())
assert p2_files=={'__tests__/List.ts','src/List.js'}
assert git_out(I,'rev-parse',po['f0bc99_fix']+'^:src/List.js')==po['list_parent_4x']
assert git_out(I,'rev-parse',po['f0bc99_fix']+':src/List.js')==po['list_fixed_4x']
assert git_out(I,'rev-parse',po['a1a1ee_p2']+':src/List.js')==po['list_fixed_5x']
parent_list=git_out(I,'show',po['f0bc99_fix']+'^:src/List.js')
assert 'while (newTailOffset >= 1 << (newLevel + SHIFT))' in parent_list
assert git_out(I,'rev-parse','v5.1.5^{commit}')==po['v515_peel']
assert git_out(I,'rev-parse','v4.3.8^{commit}')==po['v438_peel']
r=subprocess.run([*_git,'-C',str(I),'merge-base','--is-ancestor',po['imm_claude_ops'],'v5.1.5'],env=env)
assert r.returncode==1
r=subprocess.run([*_git,'-C',str(I),'merge-base','--is-ancestor',po['f0bc99_fix'],'v4.3.8'],env=env)
assert r.returncode==1
r=subprocess.run([*_git,'-C',str(I),'merge-base','--is-ancestor',po['imm_claude_ops'],po['f0bc99_fix']],env=env)
assert r.returncode==1
r=subprocess.run([*_git,'-C',str(I),'merge-base','--is-ancestor',po['imm_claude_ops'],po['a1a1ee_merge']],env=env)
assert r.returncode==0
print('REPLAY_OK assigned=6 reviewed=6 unreviewed=0 PASS=0 canonical94=94 equation=6=6+0')
PY
