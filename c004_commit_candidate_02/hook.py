"""Real SQLite C commit-hook experiment via documented C APIs, synthetic DBs only."""
import argparse,ctypes,ctypes.util,hashlib,json,os,platform,sqlite3,subprocess,sys,time
from pathlib import Path
GATES=('HOOK_SAMPLE','HOOK_MARGIN')
CASES=('valid','expired_before_hook','pause_after_valid_hook','kill_after_valid_hook')
def need(x,s):
    if not x:raise ValueError(s)
def put(p,x):
    with p.open('w',encoding='utf-8',newline='\n') as f:json.dump(x,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def get(p):return json.loads(p.read_text(encoding='utf-8'))
def wait(p,child=None):
    end=time.monotonic()+20
    while not p.exists():
        need(time.monotonic()<end and (child is None or child.poll() is None),'WAIT:'+p.name);time.sleep(.005)
def library():
    if os.name=='nt':
        import _sqlite3
        name=str(Path(_sqlite3.__file__).parent/'sqlite3.dll');need(Path(name).is_file(),'SQLITE_DLL_REQUIRED')
    else:name=ctypes.util.find_library('sqlite3');need(bool(name),'SQLITE_SHARED_LIBRARY_REQUIRED')
    lib=ctypes.CDLL(name)
    lib.sqlite3_open.argtypes=[ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p)];lib.sqlite3_open.restype=ctypes.c_int
    lib.sqlite3_close.argtypes=[ctypes.c_void_p];lib.sqlite3_close.restype=ctypes.c_int
    lib.sqlite3_exec.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p];lib.sqlite3_exec.restype=ctypes.c_int
    lib.sqlite3_libversion.restype=ctypes.c_char_p;lib.sqlite3_sourceid.restype=ctypes.c_char_p
    return lib,name
def actor(folder):
    cfg=get(folder/'config.json');lib,name=library();db=ctypes.c_void_p();need(lib.sqlite3_open(os.fsencode(folder/'case.db'),ctypes.byref(db))==0,'SQLITE_OPEN')
    callback_type=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_void_p)
    lib.sqlite3_commit_hook.argtypes=[ctypes.c_void_p,callback_type,ctypes.c_void_p];lib.sqlite3_commit_hook.restype=ctypes.c_void_p
    events=[];rollbacks=[];callback_errors=[]
    def sql(s):
        rc=lib.sqlite3_exec(db,s.encode(),None,None,None);need(rc==0,'SQLITE_EXEC:'+s+':'+str(rc))
    def pause(point):
        put(folder/'pause.json',dict(pid=os.getpid(),point=point,marker_ns=time.monotonic_ns()));wait(folder/'release.json')
    @callback_type
    def hook(_):
        try:
            tick=time.monotonic_ns();margin=cfg['margin_ns'];admit=tick+margin<cfg['deadline_ns']
            events.append(dict(tick_ns=tick,margin_ns=margin,admit=admit))
            if admit and cfg['schedule'] in ('pause_after_valid_hook','kill_after_valid_hook'):pause('INSIDE_COMMIT_HOOK_AFTER_VALID_SAMPLE')
            return 0 if admit else 1
        except BaseException as e:
            callback_errors.append(type(e).__name__);return 1
    rollback_type=ctypes.CFUNCTYPE(None,ctypes.c_void_p)
    @rollback_type
    def rollback(_):rollbacks.append(time.monotonic_ns())
    lib.sqlite3_rollback_hook.argtypes=[ctypes.c_void_p,rollback_type,ctypes.c_void_p];lib.sqlite3_rollback_hook.restype=ctypes.c_void_p
    try:
        sql('PRAGMA synchronous=FULL');sql('BEGIN IMMEDIATE');sql('INSERT INTO effects VALUES(1,1)');sql('INSERT INTO consumptions VALUES(1,1)')
        lib.sqlite3_commit_hook(db,hook,None);lib.sqlite3_rollback_hook(db,rollback,None)
        if cfg['schedule']=='expired_before_hook':pause('BEFORE_COMMIT_CALL')
        entered=time.monotonic_ns();rc=lib.sqlite3_exec(db,b'COMMIT',None,None,None);returned=time.monotonic_ns()
        need(not callback_errors and len(events)==1,'CALLBACK_EXECUTED_ONCE_WITHOUT_ERROR')
        need(rc==(0 if events[0]['admit'] else 19),'EXACT_COMMIT_RESULT')
        put(folder/'worker.json',dict(pid=os.getpid(),sqlite_c=lib.sqlite3_libversion().decode(),sqlite_sourceid=lib.sqlite3_sourceid().decode(),library=name,
            events=events,rollback_callbacks=rollbacks,commit_rc=rc,entered_ns=entered,returned_ns=returned))
    finally:need(lib.sqlite3_close(db)==0,'SQLITE_CLOSE')
def observe(path):
    # Opening this fresh connection also performs SQLite recovery after waited kill.
    with sqlite3.connect(path) as db:
        need(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'SQL_INTEGRITY')
        return {n:[list(x) for x in db.execute('SELECT * FROM '+n)] for n in ('effects','consumptions')}
def collect(out):
    need(not out.exists(),'FRESH_OUTPUT_REQUIRED');out.mkdir(parents=True);cells=[]
    for opt in (False,True):
      for gate in GATES:
       for case in CASES:
        folder=out/(gate+'-'+case+('-O' if opt else '-normal'));folder.mkdir()
        with sqlite3.connect(folder/'case.db') as db:
            need(db.execute('PRAGMA journal_mode=DELETE').fetchone()==('delete',),'DELETE_JOURNAL');db.execute('PRAGMA synchronous=FULL')
            db.executescript('CREATE TABLE effects(id PRIMARY KEY,value);CREATE TABLE consumptions(id PRIMARY KEY,value);')
        cfg=dict(gate=gate,schedule=case,optimized=opt,deadline_ns=time.monotonic_ns()+2_000_000_000,margin_ns=500_000_000 if gate=='HOOK_MARGIN' else 0)
        put(folder/'config.json',cfg);flags=[sys.executable]+(['-O'] if opt else [])+['-I','-B',str(Path(__file__).resolve()),'--worker',str(folder)]
        child=subprocess.Popen(flags,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);r=dict(config=cfg,pid=child.pid,platform=platform.system(),python=platform.python_version(),python_sqlite=sqlite3.sqlite_version)
        try:
            if case!='valid':
                wait(folder/'pause.json',child);r['pause']=get(folder/'pause.json')
                while time.monotonic_ns()<=cfg['deadline_ns']+20_000_000:need(child.poll() is None,'CHILD_DIED_PAUSED');time.sleep(.005)
                if case=='kill_after_valid_hook':child.kill()
                else:r['release']=dict(tick_ns=time.monotonic_ns(),pid=child.pid);put(folder/'release.json',r['release'])
            stdout,stderr=child.communicate(timeout=20);r['wait']=dict(waited=True,pid=child.pid,exit=child.returncode,termination=('TerminateProcess' if os.name=='nt' else 'SIGKILL') if case=='kill_after_valid_hook' else None)
            if case!='kill_after_valid_hook':need(child.returncode==0,'WORKER_FAILURE:'+stderr[-1200:]);r['worker']=get(folder/'worker.json')
            r['sql']=observe(folder/'case.db');r['observed_ns']=time.monotonic_ns();put(folder/'REPORT.json',r);cells.append(dict(file=folder.name+'/REPORT.json',gate=gate,schedule=case,optimized=opt))
        finally:
            if child.poll() is None:child.kill();child.communicate(timeout=10)
    clock=time.get_clock_info('monotonic');put(out/'MANIFEST.json',dict(schema='C004-COMMIT-HOOK/1',cells=cells,source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),clock=dict(implementation=clock.implementation,resolution=clock.resolution)))
    print(json.dumps(dict(captured=len(cells),platform=platform.system())))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--worker',type=Path);p.add_argument('--out',type=Path);a=p.parse_args();actor(a.worker) if a.worker else collect(a.out)
