"""Frozen archive replay plus explicitly synthetic, re-signed supervisor mutants."""
import argparse,copy,hashlib,json,pathlib,subprocess,sys,tempfile,zipfile
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import quiescence as q
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
ARCHIVE_SHA='80721dc1916e4f08532999804c7e6425814691c5bcd8609e3883a9a05bd8a07b'
def run(a):
    raw=a.legacy_zip.read_bytes();q.need(hashlib.sha256(raw).hexdigest()==ARCHIVE_SHA,'FROZEN_ARCHIVE_HASH')
    rejected=[];legacy=[];synthetic=[]
    with tempfile.TemporaryDirectory() as temp:
        root=pathlib.Path(temp)
        with zipfile.ZipFile(a.legacy_zip) as z:
            q.need(z.testzip() is None and all(not pathlib.PurePosixPath(n).is_absolute() and '..' not in pathlib.PurePosixPath(n).parts for n in z.namelist()),'ARCHIVE_CRC_AND_PATHS');z.extractall(root)
        sources=json.loads((root/'source-manifest.json').read_text())
        for n,h in sources['files'].items():q.need(hashlib.sha256((root/'sources'/n).read_bytes()).hexdigest()==h,'LEGACY_SOURCE:'+n)
        q.need((root/'EXECUTED_COMMIT.txt').read_text().strip()=='7f721381f4e70505fbe5591f012bc134ffae3613','LEGACY_EXECUTED_COMMIT')
        manifest=root/'cells/MANIFEST.json';mh=hashlib.sha256(manifest.read_bytes()).hexdigest()
        for opt in (False,True):
            output=root/('baseline-O.json' if opt else 'baseline-normal.json')
            proc=subprocess.run([sys.executable]+(['-O'] if opt else [])+['-I','-B',str(root/'sources/crash/receive.py'),'--manifest',str(manifest),'--manifest-sha256',mh,'--source-manifest',str(root/'source-manifest.json'),'--out',str(output)],capture_output=True,text=True)
            q.need(proc.returncode==0 and output.read_bytes()==(root/'reader-normal.json').read_bytes(),'FROZEN_READER_REPLAY:'+proc.stderr[-500:])
        for f in sorted((root/'cells').glob('*/REPORT.json')):
            row=json.loads(f.read_text());prepared=row['writer_ready'];stores=row['root_before']['stores'];profile=row['profile'];committed=row['cut']=='after_commit'
            old_context=dict(scope=q.scope(prepared),issuer_public=row['trust_anchors']['issuer'],sink_public=row['trust_anchors']['sink'])
            old=q.decide(old_context,None,prepared,stores,{})
            q.need(old['quiescence']=='UNATTESTED' and old['code']=='LEGACY_SUPERVISION_UNBOUND' and old['decision']=='HOLD','NO_RETROACTIVE_TERMINATION_PROOF')
            q.need(old['outcome']==('RESULT_VERIFIED' if committed else 'NATIVE_B_UNRESOLVED'),'LEGACY_OUTCOME_REPLAY');legacy.append(old)
            # These test-only keys/births do NOT attest the historical process.
            key=Key.generate();pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
            birth=dict(pid=12345,uid=62021,boot_id=prepared['request_B']['native']['authorization']['body']['boot_id'],start_ticks=123456)
            ctx=q.make_context(prepared,pub,birth,'a'*32,23456)
            files={n:dict(dev=1,inode=100+i,uid=62021,mode=0o600,sha256=row['db_hashes_before'][n]) for i,n in enumerate(q.authority_names(profile))}
            wait=dict(method='Popen.wait/waitpid',returncode=-9,signal=9,pidfd_bound=True,pidfd_ready=True)
            body=q.make_proof(ctx,wait,stores,files);proof=q.signed(key,q.DOMAIN,body)
            good=q.decide(ctx,proof,prepared,stores,files)
            q.need(good['quiescence']=='ATTESTED_TERMINATED_OWNER' and good['authority']=='RETAINED_VIEW_VERIFIED'
                and good['decision']==('HISTORICAL_RESULT_ONLY' if committed else 'HOLD'),'SYNTHETIC_VALID_ATTESTATION')
            q.need(good['code']==('RESULT_RETRIEVED_NO_REEXECUTION' if committed else 'NATIVE_B_UNRESOLVED'),'SYNTHETIC_OUTCOME');synthetic.append(good)
            def check(name,context=None,b=None,fs=None,ss=None,sign=True,pf=None,code=None):
                cc=copy.deepcopy(ctx if context is None else context);bb=copy.deepcopy(body if b is None else b)
                pp=q.signed(key,q.DOMAIN,bb) if sign else pf
                result=q.decide(cc,pp,prepared,stores if ss is None else ss,files if fs is None else fs)
                q.need(result['decision']=='HOLD' and result['execution_authorized'] is result['recovery_authorized'] is False,'MUTANT_ADMITTED:'+name)
                if code:q.need(result['code']==code,'WRONG_MUTANT_REASON:'+name)
                rejected.append(f.parent.name+':'+name)
            check('missing_proof',sign=False,pf=None,code='SUPERVISOR_PROOF_UNAVAILABLE')
            bad=copy.deepcopy(proof);bad['signature']='00'*64;check('invalid_signature',sign=False,pf=bad,code='TERMINATION_ATTESTATION_INVALID')
            badctx=copy.deepcopy(ctx);badctx['supervisor_public']='00'*32;check('wrong_root_pin',context=badctx,code='TERMINATION_ATTESTATION_INVALID')
            for field,value in [('returncode',86),('returncode',-9.0),('signal',15),('pidfd_bound',False),('pidfd_ready',False),('method','untrusted_pid_field')]:
                bad=copy.deepcopy(body);bad['wait'][field]=value;check('resigned_wait_'+field+'_'+str(value),b=bad,code='TERMINATION_ATTESTATION_INVALID')
            for field,value in [('pid',54321),('uid',62023),('start_ticks',654321),('boot_id','00000000-0000-0000-0000-000000000000')]:
                bad=copy.deepcopy(body);bad['birth'][field]=value;check('resigned_different_birth_'+field,b=bad,code='TERMINATION_ATTESTATION_INVALID')
            badctx=copy.deepcopy(ctx);badctx['proof_id']='b'*32;check('proof_replay_different_context',context=badctx,code='TERMINATION_ATTESTATION_INVALID')
            for field,value in [('uid',True),('start_ticks',123456.0)]:
                cc=copy.deepcopy(ctx);bb=copy.deepcopy(body);cc['birth'][field]=bb['birth'][field]=value;check('resigned_birth_type_'+field,context=cc,b=bb,code='TERMINATION_ATTESTATION_INVALID')
            for field,value in [('supervisor_uid',False),('supervisor_pid','23456'),('policy_sha256','00'*32),('no_live_clones_assumed',False)]:
                cc=copy.deepcopy(ctx);bb=copy.deepcopy(body);cc[field]=bb[field]=value;check('resigned_scope_'+field,context=cc,b=bb,code='TERMINATION_ATTESTATION_INVALID')
            bb=copy.deepcopy(body);bb['authority_inventory'].pop(next(iter(files)));check('resigned_incomplete_authority',b=bb,code='TERMINATION_ATTESTATION_INVALID')
            fs=copy.deepcopy(files);fs.pop(next(iter(fs)));check('missing_current_authority',fs=fs,code='AUTHORITY_FILE_UNAVAILABLE')
            for field,value in [('inode',99999),('sha256','00'*32)]:
                fs=copy.deepcopy(files);fs[next(iter(fs))][field]=value;check('current_authority_'+field,fs=fs,code='AUTHORITY_VIEW_CHANGED')
            ss=copy.deepcopy(stores);ss[q.authority_names(profile)[0]]['sk_business']['rows']=[]
            check('changed_sql_view',ss=ss,code='AUTHORITY_VIEW_CHANGED')
            bb=copy.deepcopy(body);bb['state_digest']=q.digest(ss);check('resigned_inconsistent_sql_view',ss=ss,b=bb,code='NATIVE_VIEW_INCONSISTENT')
            cc=copy.deepcopy(ctx);bb=copy.deepcopy(body);cc['scope']['native_operation_id']=bb['scope']['native_operation_id']='0'*64
            check('resigned_wrong_attempt',context=cc,b=bb,code='TERMINATION_ATTESTATION_INVALID')
    result=dict(status='QUIESCENCE_V2_PORTABLE_RECEIVED',legacy_captures_replayed=8,legacy_quiescence_admitted=0,
        synthetic_attestation_fixtures=8,synthetic_historical_results=4,synthetic_unresolved_B=4,resigned_and_other_mutants_rejected=len(rejected),
        native_executions=0,legacy_archive_sha256=ARCHIVE_SHA,policy_sha256=q.policy_hash(),mutants=rejected,
        independent_audit=False,recovery_authorized=False,M1='HOLD',SR02='BLOCKED')
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='mutants'}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--legacy-zip',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);run(p.parse_args())
