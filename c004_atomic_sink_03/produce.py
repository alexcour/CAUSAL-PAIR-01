"""Finite abstract sink, not a real atomic deadline primitive or physical experiment."""
import argparse,collections,copy,hashlib,json
from pathlib import Path
MODES=('ATOMIC_SPEC','SPLIT_SAMPLE')
ACTIONS=('tick','revoke','clock_fault','prepare_A','prepare_B','prepare_CONFLICT','prepare_FORGED','commit','commit_lost','query_A','query_B','query_CONFLICT','query_FORGED','crash','restart')
REQUESTS={'A':dict(rid='A',op='op_A',epoch=0,deadline=2,binding='request_A',auth=True,bound=True),
          'B':dict(rid='B',op='op_B',epoch=1,deadline=3,binding='request_B',auth=True,bound=True),
          'CONFLICT':dict(rid='A',op='op_alias',epoch=0,deadline=2,binding='other_request',auth=True,bound=False),
          'FORGED':dict(rid='A',op='op_A',epoch=0,deadline=2,binding='request_A',auth=False,bound=True)}
PROBES={
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
def initial():return dict(now=0,epoch=0,alive=True,clock_ok=True,pending=None,effects=[None,None],consumptions=[None,None],results=[None,None])
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
def reply(status,**kw):return dict(status=status,**kw)
def step(before,action,mode):
    s=copy.deepcopy(before)
    if action=='tick':s['now']=min(3,s['now']+1);return s,reply('TICK')
    if action=='clock_fault':s['clock_ok']=False;return s,reply('CLOCK_FAULT')
    if action=='restart':s['alive']=True;return s,reply('READY')
    if not s['alive']:return s,reply('OFFLINE')
    if action=='crash':s['alive']=False;s['pending']=None;return s,reply('STOPPED')
    if action=='revoke':s['epoch']=1;return s,reply('REVOKED')
    if action.startswith(('prepare_','query_')):
        kind,name=action.split('_',1);p=REQUESTS[name];i=0 if p['rid']=='A' else 1
        if not p['auth']:return s,reply('BAD_AUTH')
        if not p['bound']:return s,reply('BINDING_CONFLICT')
        if s['results'][i] is not None:return s,reply('FOUND',result=copy.deepcopy(s['results'][i]))
        if kind=='query':return s,reply('NOT_FOUND')
        if s['pending'] is not None:return s,reply('BUSY')
        if not s['clock_ok']:return s,reply('CLOCK_UNTRUSTED')
        if s['epoch']!=p['epoch']:return s,reply('REVOKED')
        if s['now']>=p['deadline']:return s,reply('EXPIRED')
        s['pending']=name;return s,reply('PREPARED')
    if s['pending'] is None:return s,reply('EMPTY')
    p=REQUESTS[s['pending']];i=0 if p['rid']=='A' else 1;s['pending']=None
    if mode=='ATOMIC_SPEC':
        if not s['clock_ok']:return s,reply('CLOCK_UNTRUSTED')
        if s['epoch']!=p['epoch']:return s,reply('REVOKED')
        if s['now']>=p['deadline']:return s,reply('EXPIRED')
    effect=dict(rid=p['rid'],op=p['op'],binding=p['binding'],grant_epoch=p['epoch'],deadline=p['deadline'],commit_tick=s['now'],authority_epoch=s['epoch'],clock_ok=s['clock_ok'])
    # The simultaneous abstract transition is a SPECIFICATION ASSUMPTION.
    # It does not implement timed persistence on a real platform.
    result=dict(result_id=p['rid']+':'+str(s['now'])+':'+str(s['epoch']),op=p['op'],commit_tick=s['now'])
    s['effects'][i]=effect;s['consumptions'][i]=dict(rid=p['rid'],binding=p['binding'],result_id=result['result_id']);s['results'][i]=result
    return s,reply('UNKNOWN') if action=='commit_lost' else reply('COMMITTED',result=copy.deepcopy(result))
def explore(mode):
    states=[initial()];ids={canonical(states[0]):0};edges=[];q=collections.deque([0])
    while q:
        i=q.popleft()
        for action in ACTIONS:
            after,r=step(states[i],action,mode);key=canonical(after)
            if key not in ids:ids[key]=len(states);states.append(after);q.append(ids[key])
            edges.append(dict(source=i,action=action,target=ids[key],reply=r))
    graph=dict(schema='C004-ABSTRACT-SINK/1',mode=mode,states=states,edges=edges)
    lookup={(e['source'],e['action']):e for e in edges};probes={}
    for name,path in PROBES.items():
        node=0;trace=[]
        for action in path:
            edge=lookup[node,action];trace.append(copy.deepcopy(edge));node=edge['target']
        probes[name]=trace
    return graph,probes
def run(out):
    if out.exists():raise ValueError('FRESH_OUTPUT_REQUIRED')
    out.mkdir(parents=True);manifest={}
    for mode in MODES:
        g,p=explore(mode)
        for name,value in ((mode+'-graph.json',g),(mode+'-probes.json',p)):
            raw=(canonical(value)+'\n').encode();(out/name).write_bytes(raw);manifest[name]=hashlib.sha256(raw).hexdigest()
        print(json.dumps(dict(mode=mode,states=len(g['states']),edges=len(g['edges']),probes=len(p))))
    (out/'CAPTURE_MANIFEST.json').write_bytes((canonical(manifest)+'\n').encode())
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);run(p.parse_args().out)
