"""Independent fixture classifier. Does not import bench or native engines."""
import argparse,copy,hashlib,json
from pathlib import Path
GATES={'APPLICATION_SAMPLE','COMMIT_PREPARE_AUTHORIZER'}
CASES={'valid','expires_before_prepare','pause_after_last_sample','kill_after_last_sample','revoked_before_transaction','revocation_requested_under_lock'}
def need(x,why):
    if not x:raise ValueError(why)
def one(r):
    c=r['config'];gate=c['gate'];case=c['schedule'];sql=r['sql'];w=r.get('worker');d=c['deadline_ns']
    need(gate in GATES and case in CASES and r['worker_wait']['pid']==r['worker_pid'] and r['worker_wait']['waited'] is True,'FIXTURE_CELL_BINDING')
    committed=case in ('valid','pause_after_last_sample','revocation_requested_under_lock') or case=='expires_before_prepare' and gate=='APPLICATION_SAMPLE'
    need(len(sql['effects'])==len(sql['consumptions'])==int(committed),'ATOMIC_EFFECT_CONSUMPTION')
    if committed:
        need(sql['effects']==[[1,1]] and 0<sql['consumptions'][0][1]<d,'EFFECT_AND_VALID_INITIAL_SAMPLE')
    if case=='kill_after_last_sample':
        need(r['worker_wait']['exit']!=0 and r['worker_wait']['termination'] in ('SIGKILL','TerminateProcess') and 'worker' not in r,'WAITED_TERMINATION_NO_ACK')
        need(sql['ordering']==[] and sql['authority']==[[1,0]],'KILL_ROLLS_BACK_ALL_STAGED_ROWS')
    else:
        need(r['worker_wait']['exit']==0 and w['pid']==r['worker_pid'],'CLEAN_WORKER_REPLY')
        expected='COMMITTED' if committed else 'REFUSED_REVOKED' if case=='revoked_before_transaction' else 'REFUSED_EXPIRED_AT_PREPARE'
        need(w['status']==expected,'EXACT_DISCRIMINATING_OUTCOME')
        initial=w['events'][0];need(initial['kind']=='APPLICATION_SAMPLE','FIRST_APPLICATION_SAMPLE')
        if case!='revoked_before_transaction':need(initial['tick_ns']<d,'INITIAL_SAMPLE_VALID')
        if gate=='COMMIT_PREPARE_AUTHORIZER' and case!='revoked_before_transaction':
            need(len(w['events'])==2 and w['events'][1]['kind']=='COMMIT_PREPARE_SAMPLE','AUTHORZER_RECHECK_ACTUALLY_RAN')
            need((w['events'][1]['tick_ns']>=d)==(case=='expires_before_prepare'),'PREPARE_RECHECK_TIMING')
        else:need(len(w['events'])==1,'NO_UNDECLARED_RECHECK')
    late=committed and case in ('pause_after_last_sample','expires_before_prepare')
    if 'pause' in r:
        need(r['pause']['pid']==r['worker_pid'] and r['pause']['sampled_before_deadline'] is True and r['pause']['marker_ns']<d,'PAUSED_AFTER_A_VALID_SAMPLE')
        expected_stage='BEFORE_SQL_COMMIT_PREPARE' if case=='expires_before_prepare' else 'INSIDE_COMMIT_PREPARE_AFTER_SAMPLE' if gate=='COMMIT_PREPARE_AUTHORIZER' else 'AFTER_APPLICATION_SAMPLE_BEFORE_COMMIT_CALL'
        need(r['pause']['stage']==expected_stage,'EXACT_PAUSE_PLACEMENT')
    if late:
        need(r['release']['released_ns']>=d and w['commit_returned_ns']>=r['release']['released_ns'],'CAUSAL_LATE_COMMIT_LOWER_BOUND')
        need(r['observed_ns']>=w['commit_returned_ns'],'DURABLE_POSTCOMMIT_READBACK')
    if case=='revocation_requested_under_lock':
        need(r['revocation_request']['pid']==r['controller_wait']['pid']==r['controller']['pid'] and r['controller_wait']['exit']==0 and r['controller_wait']['waited'] is True,'DISTINCT_CONTROLLER_WAITED')
        # Clock samples may tie. Causality also follows from the source-pinned
        # supervisor reading the request marker before writing the release.
        need(r['revocation_request']['requested_ns']<=r['revocation_request_observed_ns']<=r['release']['released_ns']<=w['commit_returned_ns'],'REVOCATION_HANDSHAKE_NONDECREASING_CLOCK')
        need(sql['ordering']==[[1,'E'],[2,'R']] and sql['authority']==[[2,1]],'DURABLE_EFFECT_BEFORE_REVOCATION_COMMIT')
    elif case=='revoked_before_transaction':need(sql['ordering']==[[1,'R']] and sql['authority']==[[2,1]],'COMPLETED_REVOCATION_BLOCKS_EFFECT')
    else:need(sql['ordering']==([[1,'E']] if committed else []) and sql['authority']==[[1,0]],'ONLY_DECLARED_ORDERING_DELTA')
    return dict(gate=gate,schedule=case,optimized=c['optimized'],late_commit_counterexample=late,committed=committed)
def run(a):
    m=json.loads((a.out/'MANIFEST.json').read_text());need(len(m['cells'])==24,'EXACT_24')
    need(m['source_sha256']==hashlib.sha256((Path(__file__).parent/'bench.py').read_bytes()).hexdigest(),'FIXTURE_SOURCE_HASH')
    results=[];mutants=0
    for e in m['cells']:
        p=Path(e['file']);need(not p.is_absolute() and '..' not in p.parts,'CONFINED_REPORT')
        r=json.loads((a.out/p).read_text());need((r['config']['gate'],r['config']['schedule'],r['config']['optimized'])==(e['gate'],e['schedule'],e['optimized']),'MANIFEST_CELL_IDENTITY');results.append(one(r))
        changes=[lambda x:x['worker_wait'].update(waited=False),lambda x:x['sql']['effects'].append([99,99])]
        if results[-1]['late_commit_counterexample']:changes.append(lambda x:x['release'].update(released_ns=x['config']['deadline_ns']-1))
        if e['schedule']=='revocation_requested_under_lock':changes.append(lambda x:x['sql'].update(ordering=[[1,'R'],[2,'E']]))
        for change in changes:
            bad=copy.deepcopy(r);change(bad);need(bad!=r,'MUTATION_CHANGED')
            try:one(bad)
            except Exception:mutants+=1
            else:raise ValueError('BAD_FIXTURE_EVIDENCE_ACCEPTED')
    need(len({(x['gate'],x['schedule'],x['optimized']) for x in results})==24 and sum(x['late_commit_counterexample'] for x in results)==6 and mutants==58,'DISCRIMINATOR_COUNTS')
    result=dict(harness_status='PASS',physical_COMMIT_deadline_contract='COUNTEREXAMPLES_RECEIVED',C004_closed=False,M1='HOLD',SR02='BLOCKED',cells=24,
        late_commit_counterexamples=6,revocation_order_cells=8,rollback_kill_cells=4,expired_before_prepare_recheck_denials=2,evidence_mutations_rejected=mutants,results=results,
        scope='Synthetic SQLite gate comparison; no FCI engine, IPC-role security, hardware timing or production qualification. Trusted OS, clock and fixture instrumentation.')
    a.result.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:v for k,v in result.items() if k!='results'}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--result',type=Path,required=True);run(p.parse_args())
