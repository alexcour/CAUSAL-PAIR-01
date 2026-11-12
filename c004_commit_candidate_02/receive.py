"""Read retained commit-hook evidence. No producer imports or engine execution."""
import argparse,copy,hashlib,json
from pathlib import Path
def need(x,s):
    if not x:raise ValueError(s)
def one(r):
    c=r['config'];case=c['schedule'];d=c['deadline_ns'];margin=c['margin_ns'];pid=r['pid'];killed=case=='kill_after_valid_hook'
    need(c['gate'] in ('HOOK_SAMPLE','HOOK_MARGIN') and case in ('valid','expired_before_hook','pause_after_valid_hook','kill_after_valid_hook'),'KNOWN_CASE')
    need(margin==(500_000_000 if c['gate']=='HOOK_MARGIN' else 0),'FIXED_MARGIN')
    need(r['wait']['pid']==pid and r['wait']['waited'] is True,'WAITED_WORKER')
    effect=case in ('valid','pause_after_valid_hook');expected=[[1,1]] if effect else []
    need(r['sql']==dict(effects=expected,consumptions=expected),'EXACT_ATOMIC_RETAINED_SQL')
    if killed:
        need(r['wait']['exit']!=0 and r['wait']['termination'] in ('SIGKILL','TerminateProcess') and 'worker' not in r and 'release' not in r,'KILL_WITHOUT_REPLY_OR_RELEASE')
    else:
        w=r['worker'];need(w['pid']==pid and r['wait']['exit']==0 and len(w['events'])==1 and r['wait']['termination'] is None,'ONE_ACTUAL_HOOK')
        e=w['events'][0];need(e['margin_ns']==margin and e['admit'] is effect and w['commit_rc']==(0 if effect else 19),'HOOK_DECISION_AND_RESULT')
        need((e['tick_ns']+margin<d) is effect,'DECLARED_GATE_TIMING')
        need(w['entered_ns']<=e['tick_ns']<=w['returned_ns']<=r['observed_ns'],'HOOK_INSIDE_COMMIT_CALL')
        need(len(w['rollback_callbacks'])==int(not effect),'ROLLBACK_CALLBACK')
        if not effect:need(d<=e['tick_ns']<=w['rollback_callbacks'][0]<=w['returned_ns'],'EXPIRED_HOOK_ROLLBACK_ORDER')
    if case!='valid':
        p=r['pause'];need(p['pid']==pid and p['marker_ns']<d,'SUPERVISED_PAUSE')
        need(p['point']==('BEFORE_COMMIT_CALL' if case=='expired_before_hook' else 'INSIDE_COMMIT_HOOK_AFTER_VALID_SAMPLE'),'PINNED_PROGRAM_POINT')
        if not killed:need(r['release']['pid']==pid and d<=r['release']['tick_ns']<=r['worker']['returned_ns'],'RELEASE_AFTER_DEADLINE')
        if case=='pause_after_valid_hook':
            need(r['worker']['events'][0]['tick_ns']<=p['marker_ns']<=r['release']['tick_ns'],'VALID_HOOK_PRECEDES_LATE_RELEASE')
            if margin:need(r['release']['tick_ns']-r['worker']['events'][0]['tick_ns']>margin,'NOMINAL_MARGIN_BOUND_BREACHED')
        if case=='expired_before_hook':need(r['release']['tick_ns']<=r['worker']['entered_ns'],'RELEASE_BEFORE_COMMIT_CALL')
    return dict(gate=c['gate'],schedule=case,optimized=c['optimized'],late_commit=case=='pause_after_valid_hook')
def run(a):
    m=json.loads((a.out/'MANIFEST.json').read_text(encoding='utf-8'));need(m['source_sha256']==hashlib.sha256((Path(__file__).parent/'hook.py').read_bytes()).hexdigest(),'PINNED_HOOK_SOURCE');rows=[];mutants=0
    for e in m['cells']:
        p=Path(e['file']);need(not p.is_absolute() and '..' not in p.parts and '\\' not in e['file'],'CONFINED_REPORT')
        r=json.loads((a.out/p).read_text(encoding='utf-8'));need(all(r['config'][k]==e[k] for k in ('gate','schedule','optimized')),'MANIFEST_BINDING');rows.append(one(r))
        changes=[lambda b:b['wait'].update(waited=False),lambda b:b['sql']['effects'].append([9,9]),lambda b:b['config'].update(margin_ns=-1)]
        if rows[-1]['late_commit']:changes.append(lambda b:b['release'].update(tick_ns=b['config']['deadline_ns']-1))
        if 'worker' in r:changes.append(lambda b:b['worker'].update(commit_rc=99))
        for change in changes:
            b=copy.deepcopy(r);change(b);need(b!=r,'CHANGED_MUTANT')
            try:one(b)
            except Exception:mutants+=1
            else:raise ValueError('ALTERED_WITNESS_ACCEPTED')
    need(len(rows)==len({(x['gate'],x['schedule'],x['optimized']) for x in rows})==16 and sum(x['late_commit'] for x in rows)==4 and mutants==64,'EXACT_HOOK_COVERAGE')
    report=dict(status='REAL_SQLITE_COMMIT_HOOK_COUNTEREXAMPLES_RECEIVED',cells=16,late_commit_counterexamples=4,expiry_rollbacks=4,killed_worker_rollbacks=4,ordinary_valid_commits=4,mutations_rejected=mutants,C004_closed=False,native_FCI_execution=False,results=rows)
    a.result.write_bytes((json.dumps(report,sort_keys=True,indent=2)+'\n').encode());print(json.dumps({k:v for k,v in report.items() if k!='results'}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--result',type=Path,required=True);run(p.parse_args())
