"""New trusted certificate-only delegate, not a second native engine constructor.

The frozen certificate method and native SQL guard helpers are inherited exactly.
Keys and cached deployment/policy are supplied by the trusted owner/provisioner.
No engine, rearm, execute, redeem or successor allocation is exposed by this API.
"""
from pathlib import Path
import sqlite3

from certified_bridge import CertifiedBridge
from handoff import public


class CertificateView(CertifiedBridge):
    def __init__(self, runtime, profile, deployment, policy, sink_key, auth, trace=lambda _: None):
        self.runtime = Path(runtime)
        self.profile = profile
        self.path = str(self.runtime / ('consumer.db' if profile == 'FCI' else 'resource.db'))
        self.table = 'demo_configuration' if profile == 'FCI' else 'configuration'
        self.effects = 'demo_effects' if profile == 'FCI' else 'effects'
        self.controller = 62022
        self.requesters = {62023, 62024}
        self.certificate_deployment = deployment
        self.policy = policy
        self.sink_key = sink_key
        self.auth = auth
        self.certificate_trace = trace
        self.certificate_fault = lambda point: trace('HOOK_' + point.upper())
        with self.open_control() as db:
            self.require(db.execute('SELECT schema,policy FROM sk_control WHERE id=1').fetchone()
                         == ('SAME-K-NATIVE-BRIDGE/1', policy), 'CERTIFIER_POLICY_BINDING')
            self.require(db.execute("SELECT count(*) FROM sqlite_master WHERE name IN ('sk_certificates','sk_certificate_events')").fetchone()[0] == 2,
                         'CERTIFIER_TABLES')
        self.require(not hasattr(self, 'engine'), 'NO_SECOND_ENGINE')
