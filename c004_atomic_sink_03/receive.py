"""Separate contract oracle and finite-graph reception; no producer import."""
import argparse,copy,hashlib,json
from pathlib import Path
OPS=('tick','revoke','clock_fault','prepare_A','prepare_B','prepare_CONFLICT','prepare_FORGED','commit','commit_lost','query_A','query_B','query_CONFLICT','query_FORGED','crash','restart')
PATHS={
 'expiry_between_prepare_and_commit':['prepare_A','tick','tick','commit'],
 'revoke_between_prepare_and_commit':['prepare_A','revoke','commit'],
 'clock_fault_between_prepare_and_commit':['prepare_A','clock_fault','commit'],
 'pending_crash':['prepare_A','crash','restart','query_A'],
 'lost_reply_retry_after_expiry_revoke_restart':['prepare_A','commit_lost','crash','tick','tick','restart','revoke','prepare_A'],
 'cache_scope':['prepare_A','commit','query_CONFLICT','query_FORGED'],
 'new_epoch_valid_commit':['revoke','prepare_B','tick','tick','commit'],
 'exclusive_boundary':['tick','tick','prepare_A'],
 'cached_history_under_clock_fault':['prepare_A','commit','clock_fault','crash','restart','prepare_A'],
 'restart_does_not_heal_clock':['clock_fault','crash','restart','prepare_A']}
def need(x,s):
    if not x:raise ValueError(s)
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
def state_ok(s):
    need(set(s)=={'now','epoch','alive','clock_ok','pending','effects','consumptions','results'},'STATE_FIELDS')
    need(type(s['now']) is int and 0<=s['now']<=3 and type(s['epoch']) is int and s['epoch'] in (0,1),'TIME_EPOCH_DOMAIN')
    need(type(s['alive']) is type(s['clock_ok']) is bool and s['pending'] in (None,'A','B') and (s['alive'] or s['pending'] is None),'VOLATILE_DOMAIN')
    need(all(len(s[k])==2 for k in ('effects','consumptions','results')),'STORE_DOMAIN')
    for i,rid in enumerate(('A','B')):
        e,c,r=(s[k][i] for k in ('effects','consumptions','results'))
        need((e is None)==(c is None)==(r is None),'ATOMIC_EFFECT_CONSUMPTION_RESULT')
        if e is None:continue
        need(e['rid']==rid and e['op']=='op_'+rid and e['binding']=='request_'+rid and e['grant_epoch']==i and e['deadline']==2+i,'PERMIT_BINDINGS')
        need(type(e['commit_tick']) is int and 0<=e['commit_tick']<=s['now'] and e['authority_epoch'] in (0,1) and type(e['clock_ok']) is bool,'COMMIT_RECORD_DOMAIN')
        expected=dict(result_id=rid+':'+str(e['commit_tick'])+':'+str(e['authority_epoch']),op='op_'+rid,commit_tick=e['commit_tick'])
        need(r==expected and c==dict(rid=rid,binding='request_'+rid,result_id=expected['result_id']),'RETAINED_RESULT_CONSUMPTION_BINDING')
def oracle(old,action,mode):
    # Contract oracle written separately. The split mode deliberately drops only
    # final current-clock/epoch/deadline validation, exposing required invariants.
    expected=copy.deepcopy(old);status=None;result=None
    if action=='tick':expected['now']=old['now']+int(old['now']<3);status='TICK'
    elif action=='clock_fault':expected['clock_ok']=False;status='CLOCK_FAULT'
    elif action=='restart':expected['alive']=True;status='READY'
    elif not old['alive']:status='OFFLINE'
    elif action=='crash':expected.update(alive=False,pending=None);status='STOPPED'
    elif action=='revoke':expected['epoch']=1;status='REVOKED'
    elif action[:6] in ('query_','prepar'):
        name=action.partition('_')[2];i=int(name=='B')
        if name=='FORGED':status='BAD_AUTH'
        elif name=='CONFLICT':status='BINDING_CONFLICT'
        elif old['results'][i] is not None:status='FOUND';result=old['results'][i]
        elif action.startswith('query_'):status='NOT_FOUND'
        elif old['pending'] is not None:status='BUSY'
        elif old['clock_ok'] is False:status='CLOCK_UNTRUSTED'
        elif old['epoch']!=i:status='REVOKED'
        elif 2+i<=old['now']:status='EXPIRED'
        else:expected['pending']=name;status='PREPARED'
    elif old['pending'] is None:status='EMPTY'
    else:
        name=old['pending'];i=int(name=='B');expected['pending']=None
        if mode=='ATOMIC_SPEC' and not old['clock_ok']:status='CLOCK_UNTRUSTED'
        elif mode=='ATOMIC_SPEC' and old['epoch']!=i:status='REVOKED'
        elif mode=='ATOMIC_SPEC' and old['now']>=2+i:status='EXPIRED'
        else:
            expected['effects'][i]=dict(rid=name,op='op_'+name,binding='request_'+name,grant_epoch=i,deadline=2+i,commit_tick=old['now'],authority_epoch=old['epoch'],clock_ok=old['clock_ok'])
            result=dict(result_id=name+':'+str(old['now'])+':'+str(old['epoch']),op='op_'+name,commit_tick=old['now'])
            expected['results'][i]=result;expected['consumptions'][i]=dict(rid=name,binding='request_'+name,result_id=result['result_id'])
            status='COMMITTED' if action=='commit' else 'UNKNOWN'
            if status=='UNKNOWN':result=None
    response=dict(status=status)
    if result is not None:response['result']=result
    return expected,response
def graph_ok(g):
    mode=g['mode'];need(mode in ('ATOMIC_SPEC','SPLIT_SAMPLE') and g['schema']=='C004-ABSTRACT-SINK/1','MODEL_IDENTITY');nodes=g['states'];edges=g['edges']
    initial=dict(now=0,epoch=0,alive=True,clock_ok=True,pending=None,effects=[None,None],consumptions=[None,None],results=[None,None])
    need(nodes and nodes[0]==initial and len({canon(s) for s in nodes})==len(nodes),'UNIQUE_STATES_AND_INITIAL')
    for s in nodes:state_ok(s)
    need(len(edges)==len(nodes)*len(OPS),'COMPLETE_ACTION_COUNT');seen=set();reachable={0};adj={};counts=dict(new_effect_edges=0,late_effect_edges=0,stale_epoch_edges=0,untrusted_clock_edges=0,cached_reply_edges=0,unknown_reply_edges=0)
    for e in edges:
        f,t,a=e['source'],e['target'],e['action'];need(type(f) is type(t) is int and 0<=f<len(nodes) and 0<=t<len(nodes) and a in OPS,'EDGE_DOMAIN');need((f,a) not in seen,'UNIQUE_EDGE');seen.add((f,a));adj.setdefault(f,[]).append(t)
        old,new=nodes[f],nodes[t];expected,r=oracle(old,a,mode);need(new==expected and e['reply']==r,'COMPLETE_CONTRACT_TRANSITION')
        for i in (0,1):
            if old['effects'][i] is not None:need(new['effects'][i]==old['effects'][i] and new['consumptions'][i]==old['consumptions'][i] and new['results'][i]==old['results'][i],'IMMUTABLE_AT_MOST_ONCE_HISTORY')
            elif new['effects'][i] is not None:
                v=new['effects'][i];counts['new_effect_edges']+=1;counts['late_effect_edges']+=int(v['commit_tick']>=v['deadline']);counts['stale_epoch_edges']+=int(v['authority_epoch']!=v['grant_epoch']);counts['untrusted_clock_edges']+=int(not v['clock_ok'])
        counts['cached_reply_edges']+=int(r['status']=='FOUND');counts['unknown_reply_edges']+=int(r['status']=='UNKNOWN')
    todo=[0]
    while todo:
        for t in adj[todo.pop()]:
            if t not in reachable:reachable.add(t);todo.append(t)
    need(len(reachable)==len(nodes) and len(seen)==len(nodes)*len(OPS),'ALL_REACHABLE_FINITE_STATES_CLOSED')
    need(counts['new_effect_edges']>0 and counts['cached_reply_edges']>0 and counts['unknown_reply_edges']>0,'NONVACUOUS_EFFECT_RETRY_LOST_REPLY')
    for k in ('late_effect_edges','stale_epoch_edges','untrusted_clock_edges'):need(counts[k]==0 if mode=='ATOMIC_SPEC' else counts[k]>0,'EXPECTED_SAFETY_OR_COUNTEREXAMPLE:'+k)
    return dict(mode=mode,states=len(nodes),edges=len(edges),**counts)
def probes_ok(g,probes):
    need(set(probes)==set(PATHS),'TEN_PROBES_PRESENT');lookup={(e['source'],e['action']):e for e in g['edges']};atomic=g['mode']=='ATOMIC_SPEC'
    expected={
      'expiry_between_prepare_and_commit':'EXPIRED' if atomic else 'COMMITTED',
      'revoke_between_prepare_and_commit':'REVOKED' if atomic else 'COMMITTED',
      'clock_fault_between_prepare_and_commit':'CLOCK_UNTRUSTED' if atomic else 'COMMITTED',
      'pending_crash':'NOT_FOUND','lost_reply_retry_after_expiry_revoke_restart':'FOUND','cache_scope':'BAD_AUTH',
      'new_epoch_valid_commit':'COMMITTED','exclusive_boundary':'EXPIRED','cached_history_under_clock_fault':'FOUND','restart_does_not_heal_clock':'CLOCK_UNTRUSTED'}
    for name,path in PATHS.items():
        trace=probes[name];need(len(trace)==len(path),'EXACT_PROBE_LENGTH');node=0
        for action,e in zip(path,trace):need(e==lookup[node,action],'PROBE_IS_REACHABLE_GRAPH_PATH');node=e['target']
        need(trace[-1]['reply']['status']==expected[name],'EXACT_PROBE_OUTCOME')
        if name=='lost_reply_retry_after_expiry_revoke_restart':
            before=g['states'][trace[1]['target']];after=g['states'][node];need(trace[1]['reply']==dict(status='UNKNOWN') and after['effects']==before['effects'] and trace[-1]['reply']['result']==before['results'][0],'EXPIRED_RETRY_IS_OLD_RESULT_WITHOUT_NEW_EFFECT')
        if name=='pending_crash':need(g['states'][node]['effects']==[None,None],'PREPARE_HAS_NO_DURABLE_EFFECT')
    return 10
def rejected(call):
    try:call()
    except Exception:return 1
    raise ValueError('ALTERED_MODEL_EVIDENCE_ACCEPTED')
def run(a):
    rows=[];mutants=0;manifest=json.loads((a.out/'CAPTURE_MANIFEST.json').read_bytes())
    expected={m+'-'+k+'.json' for m in ('ATOMIC_SPEC','SPLIT_SAMPLE') for k in ('graph','probes')};need(set(manifest)==expected,'EXACT_CAPTURE_SET')
    for n,h in manifest.items():need(hashlib.sha256((a.out/n).read_bytes()).hexdigest()==h,'CAPTURE_HASH')
    for mode in ('ATOMIC_SPEC','SPLIT_SAMPLE'):
        g=json.loads((a.out/(mode+'-graph.json')).read_bytes());p=json.loads((a.out/(mode+'-probes.json')).read_bytes());need(g['mode']==mode,'FILE_MODE_BINDING')
        row=graph_ok(g);row['probes']=probes_ok(g,p);rows.append(row)
        # Six graph mutants per variant; each must alter evidence and be rejected.
        for k in range(6):
            b=copy.deepcopy(g)
            if k==0:b['edges'].pop()
            elif k==1:b['states'][0]['now']=1
            elif k==2:next(e for e in b['edges'] if e['reply']['status']=='COMMITTED')['reply']['status']='REFUSED'
            elif k==3:next(e for e in b['edges'] if e['reply']['status']=='FOUND')['reply']['result']['result_id']='forged'
            elif k==4:
                s=next(s for s in b['states'] if s['effects'][0] is not None);s['consumptions'][0]=None
            else:b['mode']='UNKNOWN_PRIMITIVE'
            need(b!=g,'GRAPH_MUTANT_CHANGED');mutants+=rejected(lambda:graph_ok(b))
        for name in PATHS:
            b=copy.deepcopy(p);b[name][-1]['reply']['status']='FORGED_REPLY';need(b!=p,'PROBE_MUTANT_CHANGED');mutants+=rejected(lambda:probes_ok(g,b))
    need(mutants==32,'EXACT_MUTATION_COUNT')
    r=dict(status='ABSTRACT_ATOMIC_SINK_CONTRACT_RECEIVED',models=rows,evidence_mutations_rejected=mutants,C004_closed=False,physical_primitive_implemented=False,native_FCI_execution=False,production_qualified=False)
    a.result.write_bytes((json.dumps(r,sort_keys=True,indent=2)+'\n').encode());print(json.dumps(r))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--result',type=Path,required=True);run(p.parse_args())
