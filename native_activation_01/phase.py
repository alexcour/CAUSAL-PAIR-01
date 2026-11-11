"""Append activation/permit qualification after the preserved admission phase."""
import copy,hashlib,json,os,selectors,subprocess,time,uuid
from pathlib import Path
import quiescence as q
from activation import GRANT,policy
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+'\n');p.chmod(0o444)
def phase(a,runtime,work,sd,evidence,row,flags,client,answer,snapshot,context_path,supervisor_key):
    pending=row['cut']=='before_commit';before=snapshot(runtime,row['profile']);main=q.authority_names(row['profile'])[0]
    admissions=q.rows(before['stores'],main,'native_admissions');adm=json.loads(admissions[0]['envelope']) if admissions else None
    control=q.rows(before['stores'],main,'sk_control')[0];now=int(time.monotonic())
    body=dict(schema='FCI-C-ACTIVATION-GRANT/1',grant_id=uuid.uuid4().hex,scope=row['v2_context']['scope'],admission_digest=q.digest(adm) if adm else None,
        state_digest=q.digest(before['stores']),inventory=q.inventory(runtime,row['profile']),control=[control[k] for k in ('policy','epoch','revoked')],
        activation_policy=policy(),owner_wait=row['admission_restart_wait'] if pending else row['admission_wait'],
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),not_before=now,not_after=now+120)
    grant=q.signed(supervisor_key,GRANT,body);path=context_path.with_name('activation-grant.json');put(path,grant)
    row.update(activation_before=before,activation_grant=grant,activation_grant_boundary=dict(uid=path.stat().st_uid,mode=path.stat().st_mode&0o777,parent_uid=path.parent.stat().st_uid,parent_mode=path.parent.stat().st_mode&0o777))
    processes=[]
    def start(n):
        err=(evidence/('activation-owner-'+str(n)+'.stderr')).open('w');sock=sd/('v'+str(n))
        p=subprocess.Popen(flags+[str(a.stage/'activation/owner.py'),'--stage',str(a.stage),'--runtime',str(runtime),'--work',str(work),
            '--socket',str(sock),'--gate-context',str(context_path),'--admission-grant',str(context_path.with_name('admission-grant.json')),
            '--grant',str(path),'--profile',row['profile']],user=62021,group=62021,extra_groups=(),umask=0o077,stdout=subprocess.PIPE,stderr=err,text=True)
        err.close();processes.append(p)
        with selectors.DefaultSelector() as s:s.register(p.stdout,selectors.EVENT_READ);q.need(bool(s.select(15)),'ACTIVATION_OWNER_READY')
        line=p.stdout.readline();q.need(bool(line),'ACTIVATION_OWNER_NOT_READY');ready=json.loads(line);q.need(ready['pid']==p.pid,'ACTIVATION_OWNER_PID');return p,sock,ready
    def stop(p):p.terminate();p.communicate(timeout=10);return dict(pid=p.pid,exit=p.returncode,waited=True)
    try:
        owner,sock,row['activation_owner_ready']=start(0)
        def ask(uid,op='activate_C',args=None):return answer(client(sock,uid,dict(op=op,args={} if args is None else args)))
        row['activation_role_denials']=[ask(uid) for uid in (62023,62024,62026,62025)]
        if not pending:row['activation_historical_refusal']=ask(62022)
        else:
            row['activation_missing_grant']=None;held=path.with_name('activation-grant.held');os.replace(path,held)
            try:row['activation_missing_grant']=ask(62022)
            finally:os.replace(held,path)
            target=runtime/('spend.db' if row['profile']=='FCI' else 'reference.db');held=target.with_name(target.name+'.activation-held')
            q.need(target.resolve().is_relative_to(runtime.resolve()),'CONFINED_ACTIVATION_FAULT');sha=hashlib.sha256(target.read_bytes()).hexdigest();os.replace(target,held)
            try:row['activation_missing_authority']=ask(62022);q.need(not target.exists(),'NO_ACTIVATION_AUTOCREATE')
            finally:os.replace(held,target)
            q.need(hashlib.sha256(target.read_bytes()).hexdigest()==sha,'AUTHORITY_BYTES_RESTORED')
            for name in ('scope','stale_view','expired_grant','policy'):
                b=copy.deepcopy(body)
                if name=='scope':b['scope']['content_hash']='0'*64
                elif name=='stale_view':b['state_digest']='0'*64
                elif name=='expired_grant':b['not_before']=now-10;b['not_after']=now-1
                else:b['activation_policy']='0'*64
                put(path,q.signed(supervisor_key,GRANT,b))
                try:row['activation_bad_'+name]=ask(62022)
                finally:put(path,grant)
            row['activation_after_refusals']=snapshot(runtime,row['profile']);row['activation_abort']=ask(62022,'abort_activation')
            row['activation_close']=ask(62022);row['activation_repeat']=ask(62022)
            row['activation_after_open']=snapshot(runtime,row['profile'])
            row['activation_early_issue_roles']=[ask(uid,'issue_C',dict(challenge='a'*32,ttl=25)) for uid in (62024,62026)]
            row['activation_issue']=ask(62022,'issue_C',dict(challenge='a'*32,ttl=25));row['activation_issue_repeat']=ask(62022,'issue_C',dict(challenge='a'*32,ttl=25))
            result=row['activation_issue']['response'];q.need(result['ok'] is True,'REAL_NATIVE_PERMIT_ISSUED');issued=result['result']['result']
            valid=dict(permit=issued['permit'],request=issued['request'])
            row['activation_valid_check']=ask(62026,'authorize_C',valid)
            row['activation_check_role_denials']=[ask(uid,'authorize_C',valid) for uid in (62022,62024)]
            row['activation_wrong_ttl']=ask(62022,'issue_C',dict(challenge='a'*32,ttl=24))
            bad=copy.deepcopy(valid);bad['permit']['body']['allocation']['uid']=62024;row['activation_tampered_permit']=ask(62026,'authorize_C',bad)
            bad=copy.deepcopy(valid);bad['request']['native']['operation']['value']+=1;row['activation_tampered_request']=ask(62026,'authorize_C',bad)
            row['activation_bare_permit']=ask(62026,'authorize_C',dict(permit=issued['request']['permit'],request=issued['request']))
            row['activation_after_checks']=snapshot(runtime,row['profile'])
            row['activation_short_issue']=ask(62022,'issue_C',dict(challenge='b'*32,ttl=2));short=row['activation_short_issue']['response']['result']['result']
            row['activation_short_valid']=ask(62026,'authorize_C',dict(permit=short['permit'],request=short['request']))
            while int(time.monotonic())<short['permit']['body']['not_after']:time.sleep(.02)
            row['activation_expiry_clock']=dict(boot_id=body['boot_id'],observed=int(time.monotonic()),deadline=short['permit']['body']['not_after'])
            row['activation_short_expired']=ask(62026,'authorize_C',dict(permit=short['permit'],request=short['request']))
            row['activation_short_reissue']=ask(62022,'issue_C',dict(challenge='b'*32,ttl=2))
            row['activation_pre_restart']=snapshot(runtime,row['profile']);row['activation_wait']=stop(owner)
            owner,sock,row['activation_restart_ready']=start(1)
            row['activation_restart_cert']=ask(62022);row['activation_restart_issue']=ask(62022,'issue_C',dict(challenge='a'*32,ttl=25))
            row['activation_restart_valid']=ask(62026,'authorize_C',valid);row['activation_before_revoke']=snapshot(runtime,row['profile'])
            row['activation_revoke']=ask(62022,'revoke_C');row['activation_revoke_repeat']=ask(62022,'revoke_C')
            row['activation_revoked_check']=ask(62026,'authorize_C',valid)
            row['activation_revoked_issue']=ask(62022,'issue_C',dict(challenge='c'*32,ttl=25));row['activation_revoked_reactivate']=ask(62022)
        row['activation_after']=snapshot(runtime,row['profile']);row['activation_final_inventory']=q.inventory(runtime,row['profile'])
        row['activation_restart_wait' if pending else 'activation_wait']=stop(owner)
    finally:
        for p in processes:
            if p.poll() is None:p.terminate();p.communicate(timeout=10)
