
import { DeterministicTime } from '../L0/Kernel';
import { generateKeyPair, KeyPair, signData, hash } from '../L0/Crypto';
import { IdentityManager, Principal } from '../L1/Identity';
import { StateModel, MetricRegistry, MetricType } from '../L2/State';
import { ProtocolEngine, ProtocolBundle, Protocol } from '../L4/Protocol';
import { AuditLog } from '../L5/Audit';
import { IntentFactory } from '../L2/IntentFactory';

describe('Iron. Canonical Protocol Bundles', () => {
    let identity: IdentityManager;
    let state: StateModel;
    let protocol: ProtocolEngine;
    let auditLog: AuditLog;
    let registry: MetricRegistry;

    let adminKeys: KeyPair;

    beforeEach(() => {
        adminKeys = generateKeyPair();

        identity = new IdentityManager();
        identity.register({ id: 'self', publicKey: adminKeys.publicKey, type: 'INDIVIDUAL', validFrom: 0, validUntil: 999999, rules: ['*'] });
        identity.register({ id: 'admin', publicKey: adminKeys.publicKey, type: 'INDIVIDUAL', validFrom: 0, validUntil: 999999, rules: ['*'] });
        auditLog = new AuditLog();
        registry = new MetricRegistry();
        state = new StateModel(auditLog, registry, identity);

        registry.register({ id: 'stress', description: '', type: MetricType.GAUGE });
        registry.register({ id: 'recovery', description: '', type: MetricType.GAUGE });

        protocol = new ProtocolEngine(state);
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
        };
    }

    test('Rule 1 & 2: Load Valid Signed Bundle', () => {
        const p1: Protocol = {
            name: 'DailyRecovery',
            category: 'Habit',
            preconditions: [{ type: 'METRIC_THRESHOLD', metricId: 'stress', operator: '>', value: 80 }],
            execution: [{ type: 'MUTATE_METRIC', metricId: 'recovery', mutation: 10 }]
        };

        const bundleSource = {
            libraryName: 'iron.individual.core',
            version: '1.0.0',
            owner: {
                publicKey: `ed25519:${adminKeys.publicKey}`,
                scope: 'self'
            },
            protocols: [p1],
            createdAt: new Date().toISOString()
        };

        const bundle = createSignedBundle(bundleSource, adminKeys);

        // Load
        expect(() => protocol.loadBundle(bundle, 'self')).not.toThrow();

        // Verify Outcome
        state.apply(IntentFactory.create('stress', 90, 'self', adminKeys.privateKey, 1000));
        protocol.evaluateAndExecute('self', adminKeys.privateKey, 2000);
        expect(state.get('recovery')).toBe(10);
    });

    test('Rule 1 Rejection: Tampered Bundle ID', () => {
        const p1: Protocol = { name: 'P1', category: 'Habit', preconditions: [], execution: [] };
        const bundle = createSignedBundle({
            libraryName: 'test', version: '1', owner: { publicKey: adminKeys.publicKey, scope: '*' },
            protocols: [p1], createdAt: ''
        }, adminKeys);

        bundle.bundleId = 'fake-id';
        expect(() => protocol.loadBundle(bundle, '*')).toThrow(/Bundle ID Mismatch/);
    });

    test('Rule 2 Rejection: Tampered Signature', () => {
        const p1: Protocol = { name: 'P1', category: 'Habit', preconditions: [], execution: [] };
        const bundle = createSignedBundle({
            libraryName: 'test', version: '1', owner: { publicKey: adminKeys.publicKey, scope: '*' },
            protocols: [p1], createdAt: ''
        }, adminKeys);

        bundle.signature = 'ed25519:bad-sig';
        expect(() => protocol.loadBundle(bundle, '*')).toThrow(/Invalid Bundle Signature/);
    });

    test('Rule 3 Rejection: Scope Violation', () => {
        const p1: Protocol = { name: 'P1', category: 'Habit', preconditions: [], execution: [] };
        const bundle = createSignedBundle({
            libraryName: 'test', version: '1', owner: { publicKey: adminKeys.publicKey, scope: 'org.audit' },
            protocols: [p1], createdAt: ''
        }, adminKeys);

        // Try to load in 'user' trust scope (User cannot load Audit protocols)
        expect(() => protocol.loadBundle(bundle, 'user')).toThrow(/Owner Scope Violation/);
    });

    test('Rule 7 Rejection: Bundle Conflict', () => {
        protocol.register({
            id: 'existing', name: 'Existing', category: 'Habit',
            preconditions: [], execution: [{ type: 'MUTATE_METRIC', metricId: 'recovery', mutation: 1 }]
        });

        const p2: Protocol = {
            name: 'Conflict', category: 'Habit',
            preconditions: [], execution: [{ type: 'MUTATE_METRIC', metricId: 'recovery', mutation: 5 }]
        };

        const bundle = createSignedBundle({
            libraryName: 'conflict-lib', version: '1', owner: { publicKey: adminKeys.publicKey, scope: '*' },
            protocols: [p2], createdAt: ''
        }, adminKeys);

        expect(() => protocol.loadBundle(bundle, '*')).toThrow(/Bundle Conflict/);
    });
});
