
import { jest, describe, test, expect, beforeEach, beforeAll } from '@jest/globals';

// --- Mocks for Outer Layers ---
jest.unstable_mockModule('../L2/State.js', () => ({
    StateModel: jest.fn().mockImplementation(() => ({
        validateMutation: jest.fn(),
        applyTrusted: jest.fn(),
        get: jest.fn()
    })),
    MetricRegistry: jest.fn().mockImplementation(() => ({
        get: jest.fn()
    })),
}));

jest.unstable_mockModule('../L4/Protocol.js', () => ({
    ProtocolEngine: jest.fn().mockImplementation(() => ({
        isRegistered: jest.fn().mockReturnValue(true),
        evaluate: jest.fn().mockReturnValue([])
    }))
}));

// --- Real Inner Layers (The Core) ---
import { GovernanceKernel } from '../Kernel.js';
import { IdentityManager, AuthorityEngine } from '../L1/Identity.js';
import { AuditLog } from '../L5/Audit.js';
import { Budget, BudgetType } from '../L0/Kernel.js';
import { generateKeyPair, signData, hash } from '../L0/Crypto.js';
import type { Action } from '../L2/State.js';

describe('The CONSTITUTION (Supreme Court Verification)', () => {
    let kernel: GovernanceKernel;
    let identity: IdentityManager;
    let authority: AuthorityEngine;
    let audit: AuditLog;

    // Mocks
    let mockState: any;
    let mockProtocols: any;
    let mockRegistry: any;

    const rootKeys = generateKeyPair();
    const userKeys = generateKeyPair();
    const malloryKeys = generateKeyPair(); // Attacker

    let testTime = 1000000;
    const realNow = Date.now;

    beforeAll(() => {
        global.Date.now = () => testTime;
    });

    afterAll(() => {
        global.Date.now = realNow;
    });

    beforeEach(async () => {
        testTime += 1000;
        const StateModule = await import('../L2/State.js');
        const ProtocolModule = await import('../L4/Protocol.js');

        mockState = new StateModule.StateModel(audit, mockRegistry, identity);
        mockRegistry = new StateModule.MetricRegistry();
        mockProtocols = new ProtocolModule.ProtocolEngine(mockState);

        // Real Logic
        audit = new AuditLog();
        identity = new IdentityManager();
        authority = new AuthorityEngine(identity);

        // Register ROOT (Article I)
        identity.register({
            id: 'ROOT',
            type: 'ACTOR',
            identityProof: 'ROOT_PROOF',
            status: 'ACTIVE',
            publicKey: rootKeys.publicKey,
            isRoot: true,
            createdAt: '0:0'
        });

        // Register USER
        identity.register({
            id: 'user',
            type: 'ACTOR',
            identityProof: 'USER_PROOF',
            status: 'ACTIVE',
            publicKey: userKeys.publicKey,
            createdAt: '0:0'
        });

        kernel = new GovernanceKernel(
            identity,
            authority,
            mockState,
            mockProtocols,
            audit,
            mockRegistry
        );

        kernel.boot();

        // DELEGATE POWER (Article III.2)
        kernel.grantAuthority('ROOT', 'ROOT', 'user', 'USER_ROLE', 'user.data');
    });

    const createAction = (initiator: string, keys: any, metric: string, val: any, ts: string = '1000:0') => {
        const payload = { metricId: metric, value: val };
        const exp = '0:0';

        // Match ActionFactory: Action ID = SHA256(Initiator + Payload + TS + Exp)
        const id = hash(`${initiator}:${JSON.stringify(payload)}:${ts}:${exp}`);

        // MATCH Guards.ts: `${intent.actionId}:${intent.initiator}:${JSON.stringify(intent.payload)}:${intent.timestamp}:${intent.expiresAt}`
        const data = `${id}:${initiator}:${JSON.stringify(payload)}:${ts}:${exp}`;

        return {
            actionId: id,
            initiator: initiator,
            payload,
            timestamp: ts,
            expiresAt: exp,
            signature: signData(data, keys.privateKey)
        } as Action;
    };

    // --- III. Authority Law ---
    test('Law I (Authority): Signature Forgery is Impossible', () => {
        kernel.boot();

        // Mallory masquerades as User
        const fakeAction = createAction('user', malloryKeys, 'user.data', 666);

        const aid = kernel.submitAttempt('attacker', 'proto1', fakeAction);
        const result = kernel.guardAttempt(aid);

        expect(result.status).toBe('REJECTED');

        // Verify Audit Log (Evidence System)
        const entry = audit.getHistory().slice().reverse().find(e => e.action.actionId === fakeAction.actionId);
        expect(entry).toBeDefined();
        expect(entry?.status).toBe('REJECT');
        expect(entry?.reason).toMatch(/Invalid Signature/);
    });

    test('Law I (Authority): Jurisdiction Enforcement', () => {
        kernel.boot();

        // User tries to write to ROOT data (Outside of granted jurisdiction)
        const exceedAction = createAction('user', userKeys, 'kernel.root.config', 1);

        const aid = kernel.submitAttempt('user', 'proto1', exceedAction);
        const result = kernel.guardAttempt(aid);

        expect(result.status).toBe('REJECTED');
        const entry = audit.getHistory().slice().reverse().find(e => e.action.actionId === exceedAction.actionId);
        expect(entry?.status).toBe('REJECT');
        expect(entry?.reason).toMatch(/lacks Jurisdiction/);
    });

    // --- II. State Law ---
    test('Law II (State): Action requires Active Kernel', () => {
        const audit2 = new AuditLog();
        const kernel2 = new GovernanceKernel(identity, authority, mockState, mockProtocols, audit2, mockRegistry);

        const action = createAction('user', userKeys, 'user.data', 1);

        expect(() => {
            kernel2.submitAttempt('user', 'proto1', action);
        }).toThrow(/Cannot submit attempt in state CONSTITUTED/);
    });

    // --- III. Economic Law ---
    test('Law III (Economics): Budget is Finite', () => {
        kernel.boot();
        const action = createAction('user', userKeys, 'user.data', 1);
        const aid = kernel.submitAttempt('user', 'proto1', action, 50);
        kernel.guardAttempt(aid);

        const tinyBudget = new Budget(BudgetType.ENERGY, 40);

        expect(() => {
            kernel.commitAttempt(aid, tinyBudget);
        }).toThrow(/Budget Violation/);
    });

    // --- IV. Truth & Time Law ---
    test('Law IV (Truth): Time is Monotonic', async () => {
        const startTs = testTime;

        const i1 = createAction('user', userKeys, 'user.data', 1, `${startTs}:0`);
        const aid1 = kernel.submitAttempt('user', 'proto1', i1);
        kernel.guardAttempt(aid1);
        kernel.commitAttempt(aid1, new Budget(BudgetType.ENERGY, 100));

        // Move time BACKWARDS
        testTime = startTs - 500;

        const i2 = createAction('user', userKeys, 'user.data', 2, `${testTime}:0`);
        expect(() => {
            kernel.submitAttempt('user', 'proto1', i2);
        }).toThrow(/Temporal integrity breached/);
    });

    // --- V. Identity Lifecycle Law ---
    test('Law V (Identity): Revoked Entity has Zero Power', () => {
        kernel.boot();

        // Revoke user
        kernel.revokeEntity('ROOT', 'user');

        const action = createAction('user', userKeys, 'user.data', 1);

        const aid = kernel.submitAttempt('user', 'proto1', action);
        const result = kernel.guardAttempt(aid);

        expect(result.status).toBe('REJECTED');
        const entry = audit.getHistory().slice().reverse().find(e => e.action.actionId === action.actionId);
        expect(entry?.reason).toMatch(/Entity revoked/);
    });
});
