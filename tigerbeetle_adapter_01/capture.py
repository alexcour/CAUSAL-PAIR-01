"""Real pinned server, synthetic ledger; cluster event expiry, not FCI O6."""
import argparse, dataclasses, hashlib, json, os, shutil, socket, subprocess, sys, time
from pathlib import Path

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def run(runtime, out):
    require(not out.exists(), 'fresh output directory required')
    out.mkdir(parents=True)
    require(shutil.disk_usage(out).free > 1_750_000_000, 'development ledger needs 1.75GB free (1.14GB file plus headroom)')
    sys.path.insert(0, str(runtime / 'vendor'))
    import tigerbeetle as tb
    meta = json.loads((runtime / 'RUNTIME.json').read_text())
    binary = Path(meta['binary'])
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == meta['binary_sha256'], 'binary identity')
    for name, digest in meta['client_files'].items():
        require(hashlib.sha256((runtime / 'vendor' / name).read_bytes()).hexdigest() == digest, 'client identity: ' + name)
    db = out / 'synthetic.tigerbeetle'
    flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
    fmt = subprocess.run([str(binary), 'format', '--cluster=81113', '--replica=0', '--replica-count=1', '--development', str(db)], capture_output=True, timeout=30, **flags)
    (out / 'format.log').write_bytes(fmt.stdout + fmt.stderr)
    require(fmt.returncode == 0, 'format failed; see format.log')
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
    process = client = log = None
    events = []
    def start():
        nonlocal process, client, log
        log = (out / ('server-%s.log' % len(events))).open('wb')
        process = subprocess.Popen([str(binary), 'start', '--addresses=127.0.0.1:%d' % port, '--cache-grid=64MiB', '--development', str(db)], stdout=log, stderr=subprocess.STDOUT, **flags)
        for _ in range(200):
            require(process.poll() is None, 'server exited; inspect log')
            try:
                with socket.create_connection(('127.0.0.1', port), .1): break
            except OSError: time.sleep(.05)
        else: raise RuntimeError('server readiness timeout')
        client = tb.ClientSync(cluster_id=81113, replica_addresses='127.0.0.1:%d' % port)
    def stop():
        nonlocal client, process, log
        if client is not None: client.close(); client = None
        if process is not None:
            process.terminate()
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
            process = None
        if log is not None: log.close(); log = None
    def send(label, transfer):
        result = client.create_transfers([transfer])
        require(len(result) == 1, 'one result per event')
        row = {'case': label, 'request': dataclasses.asdict(transfer), 'status': result[0].status.name, 'timestamp': result[0].timestamp}
        events.append(row)
        (out / 'events.partial.json').write_text(json.dumps(events, indent=2))
        return row
    def pending(i, timeout):
        return tb.Transfer(id=i, debit_account_id=1, credit_account_id=2, amount=10, ledger=1, code=1, flags=tb.TransferFlags.PENDING, timeout=timeout)
    def resolve(i, p, void=False):
        return tb.Transfer(id=i, pending_id=p, amount=0 if void else 10, ledger=1, flags=tb.TransferFlags.VOID_PENDING_TRANSFER if void else tb.TransferFlags.POST_PENDING_TRANSFER)
    def after_expiry(p):
        deadline = p['timestamp'] + p['request']['timeout'] * 1_000_000_000
        for _ in range(200):
            probe = send('cluster_clock_probe', tb.Transfer())
            if probe['timestamp'] >= deadline: return
            time.sleep(.05)
        raise RuntimeError('cluster expiry not observed')
    try:
        start()
        accounts = client.create_accounts([tb.Account(id=i, ledger=1, code=1) for i in (1, 2)])
        require(len(accounts) == 2 and all(x.status.name == 'CREATED' for x in accounts), 'accounts')
        p = send('pending_live', pending(10, 30))
        post = resolve(11, 10)
        send('post_live', post)
        # The application discards a SUCCESS reply. No actual network fault injected.
        send('application_ack_discard_retry', post)
        conflict = dataclasses.replace(post, amount=9)
        send('id_amount_conflict', conflict)
        send('second_post', resolve(12, 10))
        send('pending_void', pending(20, 30))
        send('void_live', resolve(21, 20, True))
        send('post_voided', resolve(22, 20))
        expired = send('pending_expiring', pending(30, 1))
        after_expiry(expired)
        send('post_expired', resolve(31, 30))
        send('void_expired', resolve(32, 30, True))
        before = [dataclasses.asdict(x) for x in client.lookup_transfers([11])]
        stop(); start()
        after = [dataclasses.asdict(x) for x in client.lookup_transfers([11])]
        balances = [dataclasses.asdict(x) for x in client.lookup_accounts([1, 2])]
        report = {'schema': 1, 'capability': 'CLUSTER_EVENT_EXPIRY', 'commit_deadline': False,
                  'platform': meta['platform'], 'runtime': meta, 'events': events,
                  'before_restart': before, 'after_restart': after, 'accounts': balances,
                  'restart': 'owned server process termination and restart, same data file; not power loss',
                  'ack_fault': 'application discarded successful reply; no transport fault injection'}
        (out / 'capture.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'output': str(out / 'capture.json'), 'events': len(events)}))
    finally:
        stop()
        # Keep JSON and raw logs, release only this owned disposable data file.
        if db.exists(): db.unlink()

if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--runtime', type=Path, required=True); p.add_argument('--out', type=Path, required=True)
    a = p.parse_args(); run(a.runtime.resolve(), a.out.resolve())
