
import { DeterministicTime } from '../../L0/Kernel.js';
import { IdentityManager, AuthorityEngine } from '../../L1/Identity.js';
import { MetricRegistry, MetricType, StateModel } from '../../L2/State.js';
import { ProtocolEngine } from '../../L4/Protocol.js';
import type { Protocol } from '../../L4/Protocol.js';
import { AuditLog } from '../../L5/Audit.js';
import { generateKeyPair } from '../../L0/Crypto.js';
import { GovernanceKernel } from '../../Kernel.js';
import { ActionFactory } from '../../L2/ActionFactory.js';

describe('L4 Protocol System', () => {
    let audit: AuditLog;
    let time: DeterministicTime;
    let registry: MetricRegistry;
    let identity: IdentityManager;
    let authority: AuthorityEngine;
    let state: StateModel;
    let engine: ProtocolEngine;
    let kernel: GovernanceKernel;

    const adminKeys = generateKeyPair();
    const admin: any = {
        id: 'admin',
        publicKey: adminKeys.publicKey,
        type: 'ACTOR',
        identityProof: 'ROOT_PROOF',
        status: 'ACTIVE',
        isRoot: true,
        createdAt: '0:0'
    };

    beforeEach(() => {
        audit = new AuditLog();
        time = new DeterministicTime();
        registry = new MetricRegistry();
        identity = new IdentityManager();
        identity.register(admin);
        authority = new AuthorityEngine(identity);
        state = new StateModel(audit, registry, identity);

        registry.register({ id: 'temp', description: 'Temperature', type: MetricType.GAUGE });
        registry.register({ id: 'fan', description: 'Fan Speed', type: MetricType.GAUGE });

        engine = new ProtocolEngine(state);
        kernel = new GovernanceKernel(identity, authority, state, engine, audit, registry);
    });

    test('should trigger protocol when condition met', () => {
        const coolingProtocol: Protocol = {
            id: 'p-cool',
            name: 'Cooling Logic',
            version: '1.0',
            lifecycle: 'ACTIVE',
            preconditions: [{
                type: 'METRIC_THRESHOLD',
                metricId: 'temp',
                operator: '>',
                value: 30
            }],
            execution: [{
                type: 'MUTATE_METRIC',
                metricId: 'fan',
                mutation: 10
            }]
        } as any;

        engine.propose(coolingProtocol);
        engine.ratify('p-cool', 'SIG');
        engine.activate('p-cool');

        // Case 1: Temp = 20 (No Trigger)
        kernel.execute(ActionFactory.create('temp', 20, admin.id, adminKeys.privateKey, '0:1'));
        kernel.execute(ActionFactory.create('fan', 0, admin.id, adminKeys.privateKey, '0:2'));
        expect(state.get('fan')).toBe(0);

        // Case 2: Temp = 35 (Trigger)
        kernel.execute(ActionFactory.create('temp', 35, admin.id, adminKeys.privateKey, '0:3'));
        expect(state.get('fan')).toBe(10);
    });

    test('should execute multiple rules', () => {
        const coolingProtocol: Protocol = {
            id: 'p-cool',
            name: 'Cooling',
            version: '1.0',
            lifecycle: 'ACTIVE',
            preconditions: [{ type: 'METRIC_THRESHOLD', metricId: 'temp', operator: '>', value: 30 }],
            execution: [
                { type: 'MUTATE_METRIC', metricId: 'fan', mutation: 50 },
                { type: 'MUTATE_METRIC', metricId: 'temp', mutation: -5 }
            ]
        } as any;

        engine.propose(coolingProtocol);
        engine.ratify('p-cool', 'SIG');
        engine.activate('p-cool');

        kernel.execute(ActionFactory.create('fan', 10, admin.id, adminKeys.privateKey, '0:4'));
        kernel.execute(ActionFactory.create('temp', 40, admin.id, adminKeys.privateKey, '0:5'));

        expect(state.get('fan')).toBe(60);
        expect(state.get('temp')).toBe(35);
    });
});
