"""Fresh C admission/activation, normal startup/rearm, then real native effect cases."""
import copy,hashlib,json,os,selectors,signal,subprocess,time,uuid
from pathlib import Path
import quiescence as q
from activation import GRANT as ACTIVATION_GRANT,policy as activation_policy
from execution import GRANT,policy

def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+'\n');p.chmod(0o444)
def phase(a,runtime,work,sd,evidence,row,flags,client,answer,snapshot,context_path,supervisor_key):
    before=snapshot(runtime,row['profile']);main=q.authority_names(row['profile'])[0]
    ads=q.rows(before['stores'],main,'native_admissions');adm=json.loads(ads[0]['envelope']) if ads else None
    now=int(time.monotonic());control=q.rows(before['stores'],main,'sk_control')[0]
    body=dict(schema='FCI-C-ACTIVATION-GRANT/1',grant_id=uuid.uuid4().hex,scope=row['v2_context']['scope'],admission_digest=q.digest(adm) if adm else None,
        state_digest=q.digest(before['stores']),inventory=q.inventory(runtime,row['profile']),control=[control[k] for k in ('policy','epoch','revoked')],activation_policy=activation_policy(),
        owner_wait=row['admission_restart_wait' if adm else 'admission_wait'],boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),not_before=now,not_after=now+120)
    path=context_path.with_name('activation-grant.json');grant=q.signed(supervisor_key,ACTIVATION_GRANT,body);put(path,grant)
    x=dict(before=before,activation_grant=grant);row['execution']=x
    processes=[]
    def start(command,name):
        err=(evidence/(name+'.stderr')).open('w')
        p=subprocess.Popen(flags+command,user=62021,group=62021,extra_groups=(),umask=0o077,stdout=subprocess.PIPE,stderr=err,text=True)
        err.close();processes.append(p)
        with selectors.DefaultSelector() as s:s.register(p.stdout,selectors.EVENT_READ);q.need(bool(s.select(20)),'NATIVE_C_OWNER_READY_TIMEOUT')
        line=p.stdout.readline();q.need(bool(line),'NATIVE_C_OWNER_NOT_READY:'+name);ready=json.loads(line);q.need(ready['pid']==p.pid,'NATIVE_C_PID');return p,ready
    def stop(p):p.terminate();p.communicate(timeout=10);return dict(pid=p.pid,exit=p.returncode,waited=True)
    try:
        sock=sd/'x0';owner,x['activation_ready']=start([str(a.stage/'activation/owner.py'),'--stage',str(a.stage),'--runtime',str(runtime),'--work',str(work),
            '--socket',str(sock),'--gate-context',str(context_path),'--admission-grant',str(context_path.with_name('admission-grant.json')),'--grant',str(path),'--profile',row['profile']],'C-activation-owner')
        ask=lambda uid,op,args=None:answer(client(sock,uid,dict(op=op,args={} if args is None else args)))
        x['activate']=ask(62022,'activate_C')
        x['activated']=snapshot(runtime,row['profile']);x['activation_wait']=stop(owner)
        if not adm:
            q.need(x['activate']['response']['ok'] is False and x['activate']['response']['error']=='ADMITTED_C_REQUIRED','HISTORICAL_NO_C')
            x['final']=snapshot(runtime,row['profile']);return
        activation=x['activate']['response']['result']['result']['certificate'];allocation=activation['body']['allocation']
        scope=dict(key=allocation['key'],h=allocation['h']);startpath=context_path.with_name('C-start.json');livepath=context_path.with_name('C-live.json');marker=work/'C-kill-marker.json'
        def transition(purpose,wait,owner_pid=None,epoch=None):
            snap=snapshot(runtime,row['profile']);tick=int(time.monotonic())
            b=dict(schema='FCI-C-NATIVE-TRANSITION-GRANT/1',purpose=purpose,execution_policy=policy(),scope=scope,activation=activation,
                state_digest=q.digest(snap['stores']),inventory=q.inventory(runtime,row['profile']),boot_id=body['boot_id'],not_before=tick,not_after=tick+120,
                owner_wait=wait,owner_pid=owner_pid,native_epoch=epoch)
            env=q.signed(supervisor_key,GRANT,b);put(startpath if purpose=='STARTUP' else livepath,env)
            return dict(grant=env,snapshot=snap,boundary=dict(uid=(startpath if purpose=='STARTUP' else livepath).stat().st_uid,mode=0o444,parent_uid=context_path.parent.stat().st_uid,parent_mode=context_path.parent.stat().st_mode&0o777))
        def native_start(n,case):
            return start([str(a.stage/'execution/owner.py'),'--stage',str(a.stage),'--runtime',str(runtime),'--work',str(work),'--socket',str(sd/('n'+str(n))),
                '--start-grant',str(startpath),'--live-grant',str(livepath),'--marker',str(marker),'--profile',row['profile'],'--case',case,'--root-pin',row['supervisor_public']],'C-native-owner-'+str(n))
        x['start_grant']=transition('STARTUP',x['activation_wait'])
        owner,x['native_ready']=native_start(0,row['execution_case']);sock=sd/'n0'
        x['after_startup']=snapshot(runtime,row['profile'])
        x['rearm_grant']=transition('REARM',x['activation_wait'],owner.pid,x['native_ready']['native_epoch'])
        x['rearm_wrong_role']=ask(62026,'rearm_C');x['rearm']=ask(62022,'rearm_C')
        q.need(x['rearm']['response']['ok'] and x['rearm']['response']['result']['result']['status']=='READY','NORMAL_NATIVE_C_REARM_READY')
        x['after_rearm']=snapshot(runtime,row['profile'])
        epoch=q.rows(x['after_rearm']['stores'],main,'d2_meta')[0]['epoch'] if row['profile']=='FCI' else q.rows(x['after_rearm']['stores'],'reference.db','control')[0]['epoch']
        x['execute_grant']=transition('EXECUTE',x['activation_wait'],owner.pid,epoch)
        x['issue_wrong_role']=ask(62026,'issue_C',dict(challenge='c'*32,ttl=25))
        x['issue']=ask(62022,'issue_C',dict(challenge='c'*32,ttl=2 if row['execution_case']=='expired_after_precheck' else 25))
        q.need(x['issue']['response']['ok'],'FRESH_NATIVE_C_PERMIT');issued=x['issue']['response']['result']['result']
        x['execute_wrong_roles']=[ask(uid,'execute_C',issued) for uid in (62022,62023,62024,62025)]
        bad=copy.deepcopy(issued);bad['permit']['body']['allocation']['uid']=62024;x['bad_signature']=ask(62026,'execute_C',bad)
        bad=copy.deepcopy(issued);bad['request']['native']['operation']['value']+=1;x['bad_request']=ask(62026,'execute_C',bad)
        x['before_effect']=snapshot(runtime,row['profile'])
        pending=client(sock,62026,dict(op='execute_C',args=issued))
        if row['execution_case'] in ('before_commit','after_commit'):
            pidfd=os.pidfd_open(owner.pid,0)
            try:
                deadline=time.monotonic()+25
                while not marker.exists():q.need(owner.poll() is None and time.monotonic()<deadline,'C_COMMIT_MARKER_TIMEOUT');time.sleep(.01)
                x['kill_marker']=json.loads(marker.read_text());q.need(x['kill_marker']==dict(pid=owner.pid,uid=62021,point=row['execution_case']),'C_KILL_BOUNDARY')
                signal.pidfd_send_signal(pidfd,signal.SIGKILL,None,0);owner.wait(timeout=10);q.need(owner.returncode==-9,'C_REAL_SIGKILL')
                x['native_wait']=dict(pid=owner.pid,exit=owner.returncode,waited=True,pidfd_bound=True)
            finally:os.close(pidfd)
            # Existing answer(eof=True) hardcodes B UID; preserve the actual C wire UID here.
            out,err=pending.communicate(timeout=10);q.need(pending.returncode!=0 and not out.strip() and 'NATIVE_EOF_NO_ACK' in err,'C_EOF_NO_ACK')
            x['lost_reply']=dict(client_uid=62026,client_pid=pending.pid,exit=pending.returncode,error='NATIVE_EOF_NO_ACK')
            # Recover rollback journals using SQLite only before read-only snapshots.
            import sqlite3
            for name in q.authority_names(row['profile']):
                with sqlite3.connect((runtime/name).resolve().as_uri()+'?mode=rw',uri=True,isolation_level=None) as db:db.execute('SELECT name FROM sqlite_master LIMIT 1').fetchall()
            x['after_effect']=snapshot(runtime,row['profile'])
            x['resume_start_grant']=transition('STARTUP',x['native_wait'])
            owner,x['resume_ready']=native_start(1,'resume');sock=sd/'n1'
            x['resume_before']=snapshot(runtime,row['profile']);x['resume_old_permit']=ask(62026,'execute_C',issued)
            x['history']=ask(62026,'history_C');x['history_repeat']=ask(62026,'history_C')
            x['resume_after']=snapshot(runtime,row['profile']);x['resume_wait']=stop(owner)
        else:
            x['execute']=answer(pending);x['after_effect']=snapshot(runtime,row['profile'])
            x['history']=ask(62026,'history_C');x['history_repeat']=ask(62026,'history_C')
            if row['execution_case']=='success':x['repeat_execute']=ask(62026,'execute_C',issued)
            x['native_wait']=stop(owner)
        x['final']=snapshot(runtime,row['profile']);x['final_inventory']=q.inventory(runtime,row['profile'])
    finally:
        for p in processes:
            if p.poll() is None:p.terminate();p.communicate(timeout=10)
