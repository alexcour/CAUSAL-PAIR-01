"""Append the new closure phase AFTER the preserved, already received read phase."""
import hashlib,json,os,selectors,subprocess
from pathlib import Path
def need(x,why):
    if not x:raise ValueError(why)
def phase(a,runtime,work,sd,evidence,row,flags,observer,client,answer,snapshot,context_path):
    observer.terminate();observer.wait(timeout=10);row['reader_stopped_before_retirement']=True
    err=(evidence/'retirement-owner.stderr').open('w')
    cmd=flags+[str(a.stage/'retirement/closer.py'),'--stage',str(a.stage),'--runtime',str(runtime),'--work',str(work),'--socket',str(sd/'c'),'--gate-context',str(context_path),'--profile',row['profile']]
    owner=subprocess.Popen(cmd,user=62021,group=62021,extra_groups=(),umask=0o077,stdout=subprocess.PIPE,stderr=err,text=True);err.close()
    try:
        with selectors.DefaultSelector() as select:
            select.register(owner.stdout,selectors.EVENT_READ);need(bool(select.select(15)),'CLOSURE_OWNER_READY')
        line=owner.stdout.readline();need(bool(line),'CLOSURE_OWNER_NOT_READY');row['retirement_owner_ready']=json.loads(line)
        need(row['retirement_owner_ready']['pid']==owner.pid,'CLOSURE_OWNER_PID')
        ask=lambda uid,op:answer(client(sd/'c',uid,dict(op=op,args={})))
        row['retirement_before']=snapshot(runtime,row['profile'])
        row['retirement_denials']=[ask(uid,'close_B') for uid in (62023,62024,62025)]
        if row['cut']=='before_commit':row['retirement_abort']=ask(62022,'abort_retirement_trial')
        row['retirement_close']=ask(62022,'close_B');row['retirement_repeat']=ask(62022,'close_B')
        row['retirement_after']=snapshot(runtime,row['profile']);row['retirement_probes']=ask(62024,'probe_B')
        row['retirement_after_probes']=snapshot(runtime,row['profile'])
        row['retirement_hashes_after']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime.glob('*.db')}
        need(row['retirement_after']['stores']==row['retirement_after_probes']['stores'],'NO_PROBE_STATE_CHANGE')
    finally:
        if owner.poll() is None:owner.terminate()
        owner.communicate(timeout=10);row['retirement_wait']=dict(pid=owner.pid,exit=owner.returncode,waited=True)
