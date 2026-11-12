"""C004 discriminating SQLite fixture. Not a native FCI implementation.

Two finite sampled gates, six controlled schedules, normal/-O. A passing harness
receives counterexamples; it does not qualify a physical COMMIT deadline.
"""
import argparse,json,os,platform,sqlite3,subprocess,sys,time
from pathlib import Path
GATES=('APPLICATION_SAMPLE','COMMIT_PREPARE_AUTHORIZER')
CASES=('valid','expires_before_prepare','pause_after_last_sample','kill_after_last_sample','revoked_before_transaction','revocation_requested_under_lock')
def need(value,why):
    if not value:raise ValueError(why)
def put(path,value):
    with Path(path).open('w',encoding='utf-8') as f:json.dump(value,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def get(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def connection(path):
    db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=rw',uri=True,isolation_level=None,cached_statements=0,timeout=15)
    db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA busy_timeout=15000');return db
def wait_file(path,process=None):
    stop=time.monotonic()+20
    while not path.exists():
        need(time.monotonic()<stop and (process is None or process.poll() is None),'FIXTURE_MARKER_TIMEOUT:'+path.name);time.sleep(.005)
def pause(folder,stage,deadline):
    put(folder/'pause.json',dict(pid=os.getpid(),stage=stage,sampled_before_deadline=time.monotonic_ns()<deadline,marker_ns=time.monotonic_ns()))
    wait_file(folder/'release.json');return get(folder/'release.json')
def actor(a):
    folder=a.cell;cfg=get(folder/'config.json');db=connection(folder/'case.db');events=[]
    try:
        if a.role=='controller':
            put(folder/'revoke-request.json',dict(pid=os.getpid(),requested_ns=time.monotonic_ns()))
            db.execute('BEGIN IMMEDIATE');db.execute('UPDATE authority SET epoch=2,revoked=1');db.execute("INSERT INTO ordering(kind) VALUES('R')")
            db.execute('COMMIT');put(folder/'controller.json',dict(pid=os.getpid(),status='REVOCATION_COMMITTED',returned_ns=time.monotonic_ns()));return
        db.execute('BEGIN IMMEDIATE');epoch,revoked=db.execute('SELECT epoch,revoked FROM authority').fetchone()
        now=time.monotonic_ns();events.append(dict(kind='APPLICATION_SAMPLE',tick_ns=now))
        if revoked or epoch!=1:
            db.execute('ROLLBACK');put(folder/'worker.json',dict(pid=os.getpid(),status='REFUSED_REVOKED',events=events));return
        need(now<cfg['deadline_ns'],'FIXTURE_EXPIRED_BEFORE_INITIAL_SAMPLE')
        db.execute('INSERT INTO effects VALUES(1,1)');db.execute('INSERT INTO consumptions VALUES(1,?)',(now,));db.execute("INSERT INTO ordering(kind) VALUES('E')")
        if cfg['schedule']=='expires_before_prepare':pause(folder,'BEFORE_SQL_COMMIT_PREPARE',cfg['deadline_ns'])
        def authorize(action,arg1,arg2,database,trigger):
            if action==sqlite3.SQLITE_TRANSACTION and arg1=='COMMIT':
                tick=time.monotonic_ns();events.append(dict(kind='COMMIT_PREPARE_SAMPLE',tick_ns=tick))
                if tick>=cfg['deadline_ns']:return sqlite3.SQLITE_DENY
                if cfg['schedule'] in ('pause_after_last_sample','kill_after_last_sample','revocation_requested_under_lock'):
                    pause(folder,'INSIDE_COMMIT_PREPARE_AFTER_SAMPLE',cfg['deadline_ns'])
            return sqlite3.SQLITE_OK
        if cfg['gate']=='COMMIT_PREPARE_AUTHORIZER':db.set_authorizer(authorize)
        elif cfg['schedule'] in ('pause_after_last_sample','kill_after_last_sample','revocation_requested_under_lock'):
            pause(folder,'AFTER_APPLICATION_SAMPLE_BEFORE_COMMIT_CALL',cfg['deadline_ns'])
        entered=time.monotonic_ns()
        try:db.execute('COMMIT')
        except sqlite3.DatabaseError as error:
            need(cfg['gate']=='COMMIT_PREPARE_AUTHORIZER' and events[-1]['kind']=='COMMIT_PREPARE_SAMPLE' and events[-1]['tick_ns']>=cfg['deadline_ns'],'UNEXPECTED_SQL_ERROR:'+str(error))
            db.set_authorizer(None);db.execute('ROLLBACK')
            put(folder/'worker.json',dict(pid=os.getpid(),status='REFUSED_EXPIRED_AT_PREPARE',events=events,commit_call_entered_ns=entered));return
        returned=time.monotonic_ns();db.set_authorizer(None)
        put(folder/'worker.json',dict(pid=os.getpid(),status='COMMITTED',events=events,commit_call_entered_ns=entered,commit_returned_ns=returned))
    finally:db.close()
def observe(path):
    # RW opening here is solely SQLite recovery after a waited-for killed worker.
    db=connection(path)
    try:
        need(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'SQL_INTEGRITY')
        return dict(authority=[list(x) for x in db.execute('SELECT epoch,revoked FROM authority')],effects=[list(x) for x in db.execute('SELECT * FROM effects')],
            consumptions=[list(x) for x in db.execute('SELECT * FROM consumptions')],ordering=[list(x) for x in db.execute('SELECT seq,kind FROM ordering ORDER BY seq')])
    finally:db.close()
def collect(a):
    out=a.out.resolve();need(not out.exists(),'FRESH_OUTPUT_REQUIRED');out.mkdir(parents=True);records=[]
    for optimized in (False,True):
      for gate in GATES:
       for case in CASES:
        folder=out/(gate+'-'+case+('-O' if optimized else '-normal'));folder.mkdir()
        db=sqlite3.connect(folder/'case.db',isolation_level=None)
        try:
            db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
            db.executescript('CREATE TABLE authority(epoch INTEGER,revoked INTEGER);INSERT INTO authority VALUES(1,0);CREATE TABLE effects(id PRIMARY KEY,value);CREATE TABLE consumptions(id PRIMARY KEY,sampled_ns);CREATE TABLE ordering(seq INTEGER PRIMARY KEY,kind);')
            if case=='revoked_before_transaction':db.executescript("UPDATE authority SET epoch=2,revoked=1;INSERT INTO ordering(kind) VALUES('R');")
        finally:db.close()
        cfg=dict(gate=gate,schedule=case,optimized=optimized,deadline_ns=time.monotonic_ns()+(10 if case=='revocation_requested_under_lock' else 2)*1_000_000_000)
        put(folder/'config.json',cfg);flags=[sys.executable]+(['-O'] if optimized else [])+['-I','-B',str(Path(__file__).resolve()),'--cell',str(folder)]
        worker=subprocess.Popen(flags+['--role','worker'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);controller=None
        row=dict(config=cfg,worker_pid=worker.pid,platform=platform.system(),python=platform.python_version(),sqlite=sqlite3.sqlite_version)
        try:
            if case in ('expires_before_prepare','pause_after_last_sample','kill_after_last_sample','revocation_requested_under_lock'):
                wait_file(folder/'pause.json',worker);row['pause']=get(folder/'pause.json');need(row['pause']['pid']==worker.pid,'WORKER_MARKER_PID')
                if case=='revocation_requested_under_lock':
                    controller=subprocess.Popen(flags+['--role','controller'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    wait_file(folder/'revoke-request.json',controller);row['revocation_request']=get(folder/'revoke-request.json');row['revocation_request_observed_ns']=time.monotonic_ns()
                    # The request is not a completed revocation; final ordering is read durably.
                else:
                    while time.monotonic_ns()<=cfg['deadline_ns']+20_000_000:need(worker.poll() is None,'WORKER_DIED_WHILE_PAUSED');time.sleep(.005)
                if case=='kill_after_last_sample':
                    worker.kill();worker.communicate(timeout=10)
                    row['worker_wait']=dict(pid=worker.pid,exit=worker.returncode,waited=True,termination='SIGKILL' if os.name!='nt' else 'TerminateProcess')
                else:
                    row['release']=dict(released_ns=time.monotonic_ns(),worker_pid=worker.pid);put(folder/'release.json',row['release'])
            if case!='kill_after_last_sample':
                stdout,stderr=worker.communicate(timeout=20);need(worker.returncode==0,'WORKER_FAILED:'+stderr[-800:])
                row['worker_wait']=dict(pid=worker.pid,exit=worker.returncode,waited=True);row['worker']=get(folder/'worker.json')
            if controller:
                stdout,stderr=controller.communicate(timeout=20);need(controller.returncode==0,'CONTROLLER_FAILED:'+stderr[-800:])
                row['controller_wait']=dict(pid=controller.pid,exit=controller.returncode,waited=True);row['controller']=get(folder/'controller.json')
            row['sql']=observe(folder/'case.db');row['observed_ns']=time.monotonic_ns();put(folder/'REPORT.json',row)
            records.append(dict(file=folder.name+'/REPORT.json',gate=gate,schedule=case,optimized=optimized))
        finally:
            for child in (worker,controller):
                if child and child.poll() is None:child.kill();child.communicate(timeout=10)
    clock=time.get_clock_info('monotonic')
    put(out/'MANIFEST.json',dict(schema='C004-SAMPLED-GATE-FIXTURE/1',cells=records,source_sha256=__import__('hashlib').sha256(Path(__file__).read_bytes()).hexdigest(),clock=dict(implementation=clock.implementation,resolution_seconds=clock.resolution,monotonic=clock.monotonic)))
    print(json.dumps(dict(status='CAPTURED',cells=len(records),platform=platform.system(),sqlite=sqlite3.sqlite_version)))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('c004-results'));p.add_argument('--cell',type=Path);p.add_argument('--role',choices=('worker','controller'))
    a=p.parse_args();actor(a) if a.cell else collect(a)
