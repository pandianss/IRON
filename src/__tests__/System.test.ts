
import { DeterministicTime, Budget, BudgetType } from '../L0/Kernel';
import { generateKeyPair, KeyPair, hash } from '../L0/Crypto';
import { IdentityManager, Principal, Delegation, DelegationEngine } from '../L1/Identity';
import { StateModel, MetricRegistry, MetricType } from '../L2/State';
import { IntentFactory } from '../L2/IntentFactory';
import { TrendAnalyzer, SimulationEngine } from '../L3/Sim';
import { ProtocolEngine } from '../L4/Protocol';
import { AuditLog } from '../L5/Audit';
import { GovernanceInterface } from '../L6/Interface';

describe('Iron. Formal Gap Verification', () => {
    // Core (Setup similar to prev tests)
    let time: DeterministicTime;
    let identity: IdentityManager;
    let delegation: DelegationEngine;
    let auditLog: AuditLog;
    let registry: MetricRegistry;
    let state: StateModel;
    let sim: SimulationEngine;
    let protocol: ProtocolEngine;

    // Identities
    let adminKeys: KeyPair;
    let admin: Principal;
    let userKeys: KeyPair;
    let user: Principal;

    beforeEach(() => {
        time = new DeterministicTime();

        adminKeys = generateKeyPair();
        admin = { id: 'admin', publicKey: adminKeys.publicKey, type: 'INDIVIDUAL', validFrom: 0, validUntil: 9999999999999, rules: ['*'] };

        userKeys = generateKeyPair();
        user = { id: 'user', publicKey: userKeys.publicKey, type: 'INDIVIDUAL', validFrom: 0, validUntil: 9999999999999 };

        identity = new IdentityManager();
        identity.register(admin);
        identity.register(user);

        delegation = new DelegationEngine(identity); // Gap 1 & 4 Logic here

        auditLog = new AuditLog();
        registry = new MetricRegistry();
        state = new StateModel(auditLog, registry, identity); // Gap 3 & 5 Logic here

        registry.register({ id: 'load', description: '', type: MetricType.GAUGE });
        registry.register({ id: 'fan', description: '', type: MetricType.GAUGE });

        sim = new SimulationEngine(registry);
        protocol = new ProtocolEngine(state);
    });

    test('Gap 1: Delegation Scope Subset Enforcement', () => {
        // Admin has '*' via rules.
        // Admin grants L2:load:Read to User.
        const d1: Delegation = {
            delegator: admin.id, delegate: user.id, scope: 'L2:load:Read',
            validUntil: Date.now() + 10000,
            signature: ''
        };
        // Sign d1
        const sigData = `${d1.delegator}:${d1.delegate}:${d1.scope}:${d1.validUntil}`;
        d1.signature = require('../L0/Crypto').signData(sigData, adminKeys.privateKey);

        expect(delegation.grant(d1)).toBe(true);

        // Usage check
        expect(delegation.isAuthorized(user.id, 'L2:load:Read', admin.id)).toBe(true);
        expect(delegation.isAuthorized(user.id, 'L2:load:Write', admin.id)).toBe(false); // Scope mismatch
    });

    test('Gap 2: Protocol Conflict Rejection', () => {
        // Two protocols modify 'fan' based on 'load'
        protocol.register({ id: 'p1', triggerMetric: 'load', threshold: 50, actionMetric: 'fan', actionMutation: 1 });
        protocol.register({ id: 'p2', triggerMetric: 'load', threshold: 50, actionMetric: 'fan', actionMutation: 2 });

        state.apply(IntentFactory.create('load', 60, admin.id, adminKeys.privateKey));

        expect(() => {
            protocol.evaluateAndExecute(admin.id, adminKeys.privateKey, time.getNow());
        }).toThrow(/Protocol Conflict/);
    });

    test('Gap 3: Monotonic Time Enforcement', () => {
        // T1
        state.apply(IntentFactory.create('load', 10, admin.id, adminKeys.privateKey, 1000));

        // T2 < T1 (Backwards)
        expect(() => {
            state.apply(IntentFactory.create('load', 20, admin.id, adminKeys.privateKey, 900));
        }).toThrow(/Time Violation/); // Caught by try-catch? No, Error thrown unless logged as failure.
        // Wait, State.ts implementation catches errors and logs FAILURE, then Re-Throws.
        // So checking toThrow is correct, AND we should see FAILURE Log.
    });

    test('Gap 4: Revoked Principal Cannot Act', () => {
        identity.revoke(admin.id);

        expect(() => {
            state.apply(IntentFactory.create('load', 10, admin.id, adminKeys.privateKey));
        }).toThrow(/Principal Revoked/);
    });

    test('Gap 5: Failed Attempts are Logged', () => {
        // Try to apply invalid signature
        const badIntent = IntentFactory.create('load', 10, admin.id, adminKeys.privateKey);
        badIntent.signature = 'bad';

        try {
            state.apply(badIntent);
        } catch (e) {
            // Expected
        }

        const log = auditLog.getHistory();
        const failEntry = log.find(e => e.status === 'FAILURE');
        expect(failEntry).toBeDefined();
        expect(failEntry?.intent.intentId).toBe(badIntent.intentId);
    });
});
