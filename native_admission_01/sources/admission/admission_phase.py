"""Fresh root grant after closure owner wait; appended admission-only phase."""
import copy,hashlib,json,os,selectors,subprocess,uuid
from pathlib import Path
import quiescence as q
from admission import GRANT,policy,C_UID

def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+'\n');p.chmod(0o444)

def phase(a,runtime,work,sd,evidence,row,flags,client,answer,snapshot,context_path,supervisor_key):
    q.need(os.getuid()==0 and row['retirement_wait']['waited'] is True,'ROOT_AFTER_CLOSURE_WAIT')
    before=snapshot(runtime,row['profile']);ctx=row['v2_context'];pending=row['cut']=='before_commit'
    retired=row['retirement_close']['response']['result']['result'].get('certificate')
    body=dict(schema='FCI-NATIVE-C-ADMISSION-GRANT/1',grant_id=uuid.uuid4().hex,scope=ctx['scope'],
        retirement_digest=q.digest(retired) if retired else None,state_digest=q.digest(before['stores']),
        authority_inventory=q.inventory(runtime,row['profile']),successor_uid=C_UID,generation=3,
        admission_policy_sha256=policy(),retirement_owner_wait=row['retirement_wait'],no_live_clones_assumed=True,
        execution_authorized=False,recovery_authorized=False)
    grant=q.signed(supervisor_key,GRANT,body);path=context_path.with_name('admission-grant.json');put(path,grant)
    row.update(admission_before=before,admission_grant=grant,admission_grant_boundary=dict(uid=path.stat().st_uid,
        mode=path.stat().st_mode&0o777,parent_uid=path.parent.stat().st_uid,parent_mode=path.parent.stat().st_mode&0o777))
    processes=[]
    def start(n):
        err=(evidence/('admission-owner-'+str(n)+'.stderr')).open('w')
        sock=sd/('a'+str(n));p=subprocess.Popen(flags+[str(a.stage/'admission/owner.py'),'--stage',str(a.stage),
            '--runtime',str(runtime),'--work',str(work),'--socket',str(sock),'--gate-context',str(context_path),
            '--grant',str(path),'--profile',row['profile']],user=62021,group=62021,extra_groups=(),umask=0o077,
            stdout=subprocess.PIPE,stderr=err,text=True);err.close();processes.append(p)
        with selectors.DefaultSelector() as s:
            s.register(p.stdout,selectors.EVENT_READ);q.need(bool(s.select(15)),'ADMISSION_OWNER_READY')
        line=p.stdout.readline();q.need(bool(line),'ADMISSION_OWNER_NOT_READY');ready=json.loads(line)
        q.need(ready['pid']==p.pid,'ADMISSION_OWNER_PID');return p,sock,ready
    def stop(p):
        p.terminate();p.communicate(timeout=10);return dict(pid=p.pid,exit=p.returncode,waited=True)
    try:
        owner,sock,row['admission_owner_ready']=start(0)
        ask=lambda uid,op='admit_C':answer(client(sock,uid,dict(op=op,args={})))
        row['admission_denials']=[ask(uid) for uid in (62023,62024,62026,62025)]
        if pending:
            held=path.with_name('admission-grant.held');os.replace(path,held)
            try:row['admission_missing_grant']=ask(62022);q.need(not path.exists(),'NO_GRANT_AUTOCREATE')
            finally:os.replace(held,path)
            target=runtime/('spend.db' if row['profile']=='FCI' else 'reference.db');held=target.with_name(target.name+'.admission-held')
            q.need(target.resolve().is_relative_to(runtime.resolve()),'CONFINED_AUTHORITY_FAULT');old=hashlib.sha256(target.read_bytes()).hexdigest();os.replace(target,held)
            try:row['admission_missing_authority']=ask(62022);q.need(not target.exists(),'NO_AUTHORITY_AUTOCREATE')
            finally:os.replace(held,target)
            q.need(hashlib.sha256(target.read_bytes()).hexdigest()==old,'AUTHORITY_RESTORED_BYTES')
            bad=copy.deepcopy(body);bad['scope']['content_hash']='0'*64;put(path,q.signed(supervisor_key,GRANT,bad))
            try:row['admission_cross_scope']=ask(62022)
            finally:put(path,grant)
            bad=copy.deepcopy(body);bad['state_digest']='0'*64;put(path,q.signed(supervisor_key,GRANT,bad))
            try:row['admission_stale_view']=ask(62022)
            finally:put(path,grant)
            row['admission_after_refusals']=snapshot(runtime,row['profile'])
            row['admission_abort']=ask(62022,'abort_admission_trial')
            # Two real client processes overlap at the single-owner serialized endpoint.
            p1=client(sock,62022,dict(op='admit_C',args={}));p2=client(sock,62022,dict(op='admit_C',args={}))
            row['admission_pair']=[answer(p1),answer(p2)]
            row['admission_repeat']=ask(62022)
            row['admission_issue_probe']=ask(62022,'probe_issue_C')
        else:row['admission_historical_refusal']=ask(62022)
        row['admission_after']=snapshot(runtime,row['profile']);row['admission_wait']=stop(owner)
        if pending:
            owner,sock,row['admission_restart_ready']=start(1)
            row['admission_restart_read']=answer(client(sock,62022,dict(op='admit_C',args={})))
            row['admission_restart_issue_probe']=answer(client(sock,62022,dict(op='probe_issue_C',args={})))
            row['admission_restart_wait']=stop(owner)
        row['admission_final']=snapshot(runtime,row['profile'])
        row['admission_final_inventory']=q.inventory(runtime,row['profile'])
        q.need(row['admission_final']['stores']==row['admission_after']['stores'],'NO_RESTART_RETRIEVAL_WRITES')
    finally:
        for p in processes:
            if p.poll() is None:p.terminate();p.communicate(timeout=10)
