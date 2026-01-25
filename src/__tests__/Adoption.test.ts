import { LogicalTimestamp } from '../L0/Kernel.js';
import { generateKeyPair, signData, hash } from '../L0/Crypto.js';
import type { KeyPair } from '../L0/Crypto.js';
import { IdentityManager, AuthorityEngine } from '../L1/Identity.js';
import { StateModel, MetricRegistry, MetricType } from '../L2/State.js';
import { ProtocolEngine } from '../L4/Protocol.js';
import type { ProtocolBundle, Protocol } from '../L4/Protocol.js';
import { AuditLog } from '../L5/Audit.js';
import { ActionFactory } from '../L2/ActionFactory.js';
import { GovernanceKernel } from '../Kernel.js';
import { DeterministicTime } from '../L0/Kernel.js';

describe('Iron Canonical Protocol Bundles', () => {
    let identity: IdentityManager;
    let authority: AuthorityEngine;
    let state: StateModel;
    let protocol: ProtocolEngine;
    let auditLog: AuditLog;
    let registry: MetricRegistry;
    let kernel: GovernanceKernel;

    let adminKeys: KeyPair;

    beforeEach(() => {
        adminKeys = generateKeyPair();

        identity = new IdentityManager();
        identity.register({
            id: 'self',
            publicKey: adminKeys.publicKey,
            type: 'ACTOR',
            identityProof: 'SYSTEM_GENESIS',
            status: 'ACTIVE',
            createdAt: '0:0',
            isRoot: true
        });

        authority = new AuthorityEngine(identity);
        auditLog = new AuditLog();
        registry = new MetricRegistry();
        state = new StateModel(auditLog, registry, identity);

        registry.register({ id: 'stress', description: '', type: MetricType.GAUGE });
        registry.register({ id: 'recovery', description: '', type: MetricType.GAUGE });

        protocol = new ProtocolEngine(state);
        kernel = new GovernanceKernel(identity, authority, state, protocol, auditLog, registry);
        kernel.boot();
    });


    function sortObject(obj: any): any {
        if (obj === null || typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.map(item => sortObject(item));
        const sorted: any = {};
        Object.keys(obj).sort().forEach(key => {
            sorted[key] = sortObject(obj[key]);
        });
        return sorted;
    }

    function createSignedBundle(bundle: Omit<ProtocolBundle, 'bundleId' | 'signature'>, keys: KeyPair): ProtocolBundle {
        const cleanBundle = JSON.parse(JSON.stringify(bundle));
        const sortedBundle = sortObject(cleanBundle);
        const stringToHash = JSON.stringify(sortedBundle);
        const bundleId = hash(stringToHash);
        const signature = signData(bundleId, keys.privateKey);

        return {
            ...bundle,
            bundleId,
            signature: `ed25519:${signature}`
        } as ProtocolBundle;
    }

    test('Rule 1 & 2: Load Valid Signed Bundle', () => {
        const p1: Protocol = {
            id: 'DailyRecovery',
            name: 'DailyRecovery',
            version: '1.0.0',
            category: 'Habit',
            lifecycle: 'PROPOSED',
            triggerConditions: [],
            authorizedCapacities: [],
            stateTransitions: [],
            completionConditions: [],
            preconditions: [{ type: 'METRIC_THRESHOLD', metricId: 'stress', operator: '>', value: 80 }],
            execution: [{ type: 'MUTATE_METRIC', metricId: 'recovery', mutation: 10 }]
        };

        const bundleSource = {
            protocols: [p1],
            owner: {
                entityId: 'self',
                publicKey: `ed25519:${adminKeys.publicKey}`
            }
        };

        const bundle = createSignedBundle(bundleSource as any, adminKeys);

        // Load
        expect(() => protocol.loadBundle(bundle, 'self')).not.toThrow();

        // Verify Outcome via Kernel
        const action = ActionFactory.create('stress', 90, 'self', adminKeys.privateKey, '1000:0');
        kernel.execute(action);

        expect(state.get('recovery')).toBe(10);
    });

    test('Rule 1 Rejection: Tampered Bundle ID', () => {
        const p1: Protocol = {
            id: 'P1', name: 'P1', version: '1', category: 'Habit',
            lifecycle: 'PROPOSED', triggerConditions: [], authorizedCapacities: [],
            stateTransitions: [], completionConditions: [], preconditions: [], execution: []
        };
        const bundleSource = {
            protocols: [p1],
            owner: { entityId: 'self', publicKey: adminKeys.publicKey }
        };
        const bundle = createSignedBundle(bundleSource as any, adminKeys);

        bundle.bundleId = 'fake-id';
        expect(() => protocol.loadBundle(bundle, '*')).toThrow(/Bundle ID Mismatch/);
    });

    test('Rule 2 Rejection: Tampered Signature', () => {
        const p1: Protocol = {
            id: 'P1', name: 'P1', version: '1', category: 'Habit',
            lifecycle: 'PROPOSED', triggerConditions: [], authorizedCapacities: [],
            stateTransitions: [], completionConditions: [], preconditions: [], execution: []
        };
        const bundleSource = {
            protocols: [p1],
            owner: { entityId: 'self', publicKey: adminKeys.publicKey }
        };
        const bundle = createSignedBundle(bundleSource as any, adminKeys);

        bundle.signature = 'ed25519:bad-sig';
        expect(() => protocol.loadBundle(bundle, '*')).toThrow(/Invalid Bundle Signature/);
    });

    test('Rule 7 Rejection: Bundle Conflict', () => {
        const pExisting: Protocol = {
            id: 'existing', name: 'Existing', version: '1', category: 'Habit',
            lifecycle: 'PROPOSED', triggerConditions: [], authorizedCapacities: [],
            stateTransitions: [], completionConditions: [],
            preconditions: [], execution: [{ type: 'MUTATE_METRIC', metricId: 'recovery', mutation: 1 }]
        };
        protocol.propose(pExisting);
        protocol.ratify('existing', 'GOV');
        protocol.activate('existing');


        const p2: Protocol = {
            id: 'conflict', name: 'Conflict', version: '1', category: 'Habit',
            lifecycle: 'PROPOSED', triggerConditions: [], authorizedCapacities: [],
            stateTransitions: [], completionConditions: [],
            preconditions: [], execution: [{ type: 'MUTATE_METRIC', metricId: 'recovery', mutation: 5 }]
        };

        const bundleSource = {
            protocols: [p2],
            owner: { entityId: 'self', publicKey: adminKeys.publicKey }
        };

        const bundle = createSignedBundle(bundleSource as any, adminKeys);

        expect(() => protocol.loadBundle(bundle, '*')).toThrow(/Bundle Conflict/);
    });
});

