"""Eight fresh real SIGKILLs, root storage recovery, forty read-only queries."""
import argparse,hashlib,json,os,selectors,sqlite3,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import quiescence as q
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'retirement'))
from phase import phase as retirement_phase
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'admission'))
from admission_phase import phase as admission_phase
import select,signal,uuid
def need(ok,why):
    if not ok:raise ValueError(why)
def get(p):return json.loads(p.read_text())
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(a):
    need(sys.platform=='linux' and os.getuid()==0 and a.launch_eight,'EXPLICIT_LINUX_ROOT_LAUNCH')
    pins=get(a.manifest);need(sha(a.manifest)==a.manifest_sha256,'EXTERNAL_SOURCE_HASH')
    for n,h in pins['files'].items():need(sha(a.stage/n)==h,'STAGED_SOURCE:'+n)
    sys.path[:0]=[str(a.stage/'task'),str(a.stage/'support/fci-same-k-handoff-20261030'),str(a.stage/'reference'),str(a.stage/'recovery')]
    import run_native_bridge as native
    from snapshots import root_snapshot
    from handoff import public
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
    supervisor_key=Key.generate()
    attestation_root=a.stage/'attestations';attestation_root.mkdir(mode=0o755)
    native.checked_sources(a.stage/'native');a.out.mkdir(parents=True,exist_ok=False)
    lab=a.stage/'r';lab.mkdir(mode=0o755);reports=[]
    for opt in (False,True):
     for profile in ('FCI','STANDARD'):
      for cut in ('before_commit','after_commit'):
        folder=lab/str(len(reports));folder.mkdir(mode=0o755);evidence=a.out/(profile+'-'+cut+('-O' if opt else '-normal'));evidence.mkdir()
        pidfd=None
        processes=[];clients=[];row=dict(profile=profile,cut=cut,optimized=opt,status='INCONCLUSIVE',waits=[])
        flags=[sys.executable]+(['-O'] if opt else [])+['-I','-B']
        try:
            runtime=native.provision(a.stage/'native',folder,profile);work=folder/'w';work.mkdir(mode=0o700);os.chown(work,62021,62021)
            sd=folder/'s';sd.mkdir(mode=0o755);os.chown(sd,62021,62021)
            core=runtime/('consumer.db' if profile=='FCI' else 'resource.db');inode=core.stat().st_ino
            private=get(runtime/'bridge-private.json');row['trust_anchors']={n:public(Key.from_private_bytes(bytes.fromhex(private[n]))) for n in ('issuer','sink')}
            immutable={p.name:sha(p) for p in runtime.iterdir() if p.suffix in ('.json','.key')}
            prep=subprocess.Popen(flags+[str(a.stage/'recovery/run_recovery.py'),'--child','--phase','fault','--case','live_holder_preparation','--profile',profile,
                '--runtime',str(runtime),'--work',str(work),'--native-root',str(a.stage/'native'),'--support-root',str(a.stage/'support'),'--reference-root',str(a.stage/'reference')],
                user=62021,group=62021,extra_groups=(),umask=0o077,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:out,err=prep.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                prep.kill();prep.communicate();raise ValueError('PREPARATION_TIMEOUT')
            row['preparation_wait']=dict(pid=prep.pid,exit=prep.returncode,waited=True)
            need(prep.returncode==0,'PREPARATION:'+err[-1500:]);row['preparation']=get(work/'fault.json')
            put(work/'supervisor.json',dict(old_process_waited=True,old_exit=0,old_pid=prep.pid,single_owner_no_clones=True,authority_inode=inode));os.chown(work/'supervisor.json',62021,62021);(work/'supervisor.json').chmod(0o600)
            def owner(command,name):
                errfile=(evidence/(name+'.stderr')).open('w')
                p=subprocess.Popen(flags+command,user=62021,group=62021,extra_groups=(),umask=0o077,stdout=subprocess.PIPE,stderr=errfile,text=True);errfile.close();processes.append((name,p))
                with selectors.DefaultSelector() as s:
                    s.register(p.stdout,selectors.EVENT_READ);need(bool(s.select(20)),'OWNER_READY_TIMEOUT:'+name)
                line=p.stdout.readline();need(bool(line),'OWNER_NOT_READY:'+name);ready=json.loads(line);need(ready['pid']==p.pid,'READY_PID');return p,ready
            def client(sock,uid,request,eof=False):
                p=subprocess.Popen(flags+[str(a.stage/'task/wire.py'),'--socket',str(sock)],user=uid,group=uid,extra_groups=(),umask=0o077,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                p.stdin.write(json.dumps(request));p.stdin.close();p.stdin=None;clients.append(p);return p
            def answer(p,eof=False):
                out,err=p.communicate(timeout=30)
                if eof:
                    need(p.returncode!=0 and not out.strip() and 'NATIVE_EOF_NO_ACK' in err,'EXACT_EOF_NO_ACK')
                    return dict(client_pid=p.pid,client_uid=62024,exit=p.returncode,error='NATIVE_EOF_NO_ACK')
                need(p.returncode==0,'RPC:'+err[-1200:]);v=json.loads(out);need(v['client_pid']==p.pid,'CLIENT_PID');return v
            writer,ready=owner([str(a.stage/'task/actors.py'),'--mode','writer','--profile',profile,'--case','COMMIT_FIRST','--cut',cut,
                '--native-root',str(a.stage/'native'),'--support-root',str(a.stage/'support'),'--reference-root',str(a.stage/'reference'),'--recovery-root',str(a.stage/'recovery'),
                '--runtime',str(runtime),'--work',str(work),'--socket',str(sd/'w')],'writer');row['writer_ready']=ready
            pidfd=os.pidfd_open(writer.pid,0)
            stat_raw=Path('/proc/'+str(writer.pid)+'/stat').read_text()
            birth=dict(pid=writer.pid,uid=62021,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),start_ticks=int(stat_raw[stat_raw.rfind(')')+2:].split()[19]))
            proc_status=Path('/proc/'+str(writer.pid)+'/status').read_text()
            kernel_uids=[int(x) for x in next(line for line in proc_status.splitlines() if line.startswith('Uid:')).split()[1:]]
            need(kernel_uids==[62021]*4,'BIRTH_UID')
            row['pidfd_kernel_uids']=kernel_uids
            row['pidfd_birth']=birth
            old=client(sd/'w',62024,dict(op='execute_B',args={}))
            deadline=time.monotonic()+25
            while not (work/'kill-marker.json').exists():
                need(writer.poll() is None and time.monotonic()<deadline,'KILL_MARKER_TIMEOUT');time.sleep(.01)
            marker=get(work/'kill-marker.json');need(marker['pid']==writer.pid and marker['uid']==62021 and marker['point']==cut,'KILL_MARKER_IDENTITY');row['marker']=marker
            signal.pidfd_send_signal(pidfd,signal.SIGKILL,None,0)
            writer.wait(timeout=10);need(writer.returncode==-9,'REAL_SIGKILL_WAITED')
            poller=select.poll();poller.register(pidfd,select.POLLIN);need(bool(poller.poll(0)),'BOUND_PIDFD_TERMINATED')
            os.close(pidfd);pidfd=None
            row['pidfd_wait']=dict(method='Popen.wait/waitpid',returncode=writer.returncode,signal=9,pidfd_bound=True,pidfd_ready=True)
            row['writer_rpc']=answer(old,True)
            row['files_before_storage_recovery']={p.name:sha(p) for p in runtime.iterdir() if p.is_file() and '.db' in p.name}
            # SQLite hot-journal recovery ONLY. No engine, new execute, rearm or certificate.
            recovered=[]
            for dbpath in runtime.glob('*.db'):
                with sqlite3.connect(dbpath.resolve().as_uri()+'?mode=rw',uri=True,isolation_level=None) as db:
                    db.execute('SELECT count(*) FROM sqlite_master').fetchone();need(db.total_changes==0,'NO_SQL_APPLICATION_WRITES')
                recovered.append(dbpath.name)
            row['storage_recovery']=dict(kind='SQLITE_OPEN_RW_SELECT_FOR_HOT_JOURNAL_RECOVERY',stores=sorted(recovered),native_engine_constructed=False,new_business_execute=False)
            row['root_before']=root_snapshot(runtime,profile);row['db_hashes_before']={p.name:sha(p) for p in runtime.glob('*.db')}
            ctxdir=attestation_root/folder.name;ctxdir.mkdir(mode=0o755)
            context=q.make_context(ready,public(supervisor_key),birth,uuid.uuid4().hex,os.getpid())
            proof=q.signed(supervisor_key,q.DOMAIN,q.make_proof(context,row['pidfd_wait'],row['root_before']['stores'],q.inventory(runtime,profile)))
            context_path=ctxdir/'context.json';proof_path=ctxdir/'proof.json'
            put(context_path,context);put(proof_path,proof);context_path.chmod(0o444);proof_path.chmod(0o444)
            row.update(v2_context=context,v2_attestation=proof,supervisor_public=public(supervisor_key))
            row['root_context_boundary']=dict(directory_uid=ctxdir.stat().st_uid,directory_mode=ctxdir.stat().st_mode&0o777,context_uid=context_path.stat().st_uid,context_mode=context_path.stat().st_mode&0o777,proof_uid=proof_path.stat().st_uid,proof_mode=proof_path.stat().st_mode&0o777)
            row['authority_inventory']=q.inventory(runtime,profile)
            supervisor=dict(old_process_waited=True,old_exit=-9,old_pid=writer.pid,single_owner_no_clones=True,authority_inode=inode)
            put(work/'supervisor-B.json',supervisor);os.chown(work/'supervisor-B.json',62021,62021);(work/'supervisor-B.json').chmod(0o600);row['supervisor_B']=supervisor
            observer,rr=owner([str(a.stage/'crash/observe.py'),'--stage',str(a.stage),'--runtime',str(runtime),'--work',str(work),'--socket',str(sd/'r'),'--profile',profile,'--gate-context',str(context_path)],'reader');row['reader_ready']=rr
            ask=lambda q:answer(client(sd/'r',62023,dict(op='inspect',args=dict(query_id=q*32))))
            row['retained_reads']=[ask('a'),ask('b')]
            row['wrong_role']=answer(client(sd/'r',62024,dict(op='inspect',args=dict(query_id='f'*32))))
            # Reversible unavailability of a real authority file, not an input boolean.
            target=runtime/('spend.db' if profile=='FCI' else 'reference.db');held=target.with_name(target.name+'.held')
            need(target.resolve().is_relative_to(folder.resolve()) and held.resolve().is_relative_to(folder.resolve()),'CONFINED_FAULT_PATHS')
            original_hash=sha(target);os.replace(target,held)
            try:
                row['missing_authority_read']=ask('c');need(not target.exists() and sha(held)==original_hash,'NO_AUTHORITY_AUTOCREATE_OR_WRITE')
            finally:os.replace(held,target)
            row['authority_unavailability']=dict(file=target.name,absent_during_probe=True,no_autocreate=True,hash_before=original_hash,hash_after=sha(target),restored=True)
            target=work/'supervisor-B.json';held=work/'supervisor-B.json.held';os.replace(target,held)
            proof_held=ctxdir/'proof.json.held';need(proof_path.resolve().is_relative_to(attestation_root.resolve()),'CONFINED_ROOT_PROOF_FAULT')
            os.replace(proof_path,proof_held)
            try:
                row['missing_supervisor_read']=ask('d');need(not target.exists() and not proof_path.exists(),'NO_SUPERVISOR_AUTOCREATE')
            finally:
                os.replace(held,target);os.replace(proof_held,proof_path)
            row['v2_proof_unavailability']=dict(absent_during_probe=True,no_autocreate=True,restored_unchanged=get(proof_path)==proof)
            row['supervisor_unavailability']=dict(absent_during_probe=True,no_autocreate=True,restored=True,unchanged=get(target)==supervisor)
            row['restored_read']=ask('e');row['root_after']=root_snapshot(runtime,profile);row['db_hashes_after']={p.name:sha(p) for p in runtime.glob('*.db')}
            need(core.stat().st_ino==inode and immutable=={n:sha(runtime/n) for n in immutable},'RETAINED_INODE_AND_KEYS')
            need(get(context_path)==context and get(proof_path)==proof and q.inventory(runtime,profile)==row['authority_inventory'],'ROOT_CONTEXT_AND_AUTHORITY_UNCHANGED')
            row['private_pins_retained']=True
            retirement_phase(a,runtime,work,sd,evidence,row,flags,observer,client,answer,root_snapshot,context_path)
            need(immutable=={n:sha(runtime/n) for n in immutable},'RETIREMENT_PRIVATE_KEYS_UNCHANGED')
            admission_phase(a,runtime,work,sd,evidence,row,flags,client,answer,root_snapshot,context_path,supervisor_key)
            need(immutable=={n:sha(runtime/n) for n in immutable},'ADMISSION_PRIVATE_KEYS_UNCHANGED')
            row['status']='CAPTURED'
        except BaseException:
            import traceback
            row['failure']=traceback.format_exc();raise
        finally:
            if pidfd is not None:os.close(pidfd)
            for p in clients:
                if p.poll() is None:p.kill();p.communicate(timeout=10)
            for name,p in processes:
                if p.poll() is None:p.terminate()
                p.communicate(timeout=10);row['waits'].append(dict(mode=name,pid=p.pid,exit=p.returncode,waited=True))
            put(evidence/'REPORT.json',row);reports.append(dict(file=evidence.name+'/REPORT.json',profile=profile,cut=cut,optimized=opt))
            put(a.out/'MANIFEST.json',dict(source_manifest_sha256=a.manifest_sha256,sources=pins,cells=reports))
        print(profile,cut,opt,'CAPTURED',flush=True)
    need(len(reports)==8,'EXACT_EIGHT')
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('stage','manifest','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);p.add_argument('--launch-eight',action='store_true');run(p.parse_args())
