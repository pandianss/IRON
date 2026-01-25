import { jest, describe, test, expect, beforeEach } from '@jest/globals';
import { GovernanceKernel } from '../Kernel.js';
import { IdentityManager, AuthorityEngine } from '../L1/Identity.js';
import { StateModel, MetricRegistry } from '../L2/State.js';
import { ProtocolEngine } from '../L4/Protocol.js';
import { AuditLog } from '../L5/Audit.js';
import { ActionFactory } from '../L2/ActionFactory.js';
import { GovernanceInterface } from '../L6/Interface.js';
import { generateKeyPair } from '../L0/Crypto.js';
import { Budget } from '../L0/Kernel.js';

describe('Commercial Verification: DAS & GBM', () => {
    let kernel: GovernanceKernel;
    let identity: IdentityManager;
    let authority: AuthorityEngine;
    let state: StateModel;
    let protocol: ProtocolEngine;
    let auditLog: AuditLog;
    let registry: MetricRegistry;
    let ui: GovernanceInterface;

    const adminKeys = generateKeyPair();
    const userKeys = generateKeyPair();

    beforeEach(() => {
        identity = new IdentityManager();
        authority = new AuthorityEngine(identity);
        auditLog = new AuditLog();
        registry = new MetricRegistry();
        state = new StateModel(auditLog, registry, identity);
        protocol = new ProtocolEngine(state);
        kernel = new GovernanceKernel(identity, authority, state, protocol, auditLog, registry);
        kernel.boot();

        // Register commercial metrics (Product 1 requirement)
        registry.register({
            id: 'load',
            description: 'System Load',
            type: 'GAUGE' as any
        });

        ui = new GovernanceInterface(kernel, state, auditLog);

        // Register Admin
        identity.register({
            id: 'admin',
            publicKey: adminKeys.publicKey,
            type: 'ACTOR',
            identityProof: 'SYSTEM',
            status: 'ACTIVE',
            createdAt: '0:0',
            isRoot: true
        });

        // Register User
        identity.register({
            id: 'user',
            publicKey: userKeys.publicKey,
            type: 'ACTOR',
            identityProof: 'USER_INVITE',
            status: 'ACTIVE',
            createdAt: '0:0'
        });
    });

    test('Product 1 (DAS): Temporal Expiry enforcement', () => {
        const now = Date.now();
        const expiry = now + 1000; // Expires in 1 second

        authority.grant(
            'delegation-1',
            'admin',
            'user',
            'USER_ROLE',
            'load',
            '0:0',
            'GOVERNANCE_SIGNATURE',
            expiry.toString()
        );

        // 1. Act before expiry
        const action1 = ActionFactory.create('load', 50, 'user', userKeys.privateKey, now.toString());

        expect(() => kernel.execute(action1)).not.toThrow();
        expect(state.get('load')).toBe(50);

        // 2. Act after expiry
        const action2 = ActionFactory.create('load', 60, 'user', userKeys.privateKey, (expiry + 100).toString());

        expect(() => kernel.execute(action2)).toThrow(/lacks Jurisdiction or exceeds limits/);
    });

    test('Product 1 (DAS): Capacity Limit enforcement', () => {
        authority.grant(
            'delegation-2',
            'admin',
            'user',
            'USER_ROLE',
            'load',
            '0:0',
            'GOVERNANCE_SIGNATURE',
            undefined,
            { 'METRIC.WRITE': 100 } // Limit to 100
        );

        // 1. Within limit
        const action1 = ActionFactory.create('load', 90, 'user', userKeys.privateKey);
        expect(() => kernel.execute(action1)).not.toThrow();

        // 2. Exceed limit
        const action2 = ActionFactory.create('load', 110, 'user', userKeys.privateKey);
        expect(() => kernel.execute(action2)).toThrow(/exceeds limits/);
    });

    test('Product 2 (GBM): Structured Breach Detection & Reconstruction', () => {
        // Setup a limit
        authority.grant(
            'delegation-3',
            'admin',
            'user',
            'USER_ROLE',
            'load',
            '0:0',
            'GOVERNANCE_SIGNATURE',
            undefined,
            { 'METRIC.WRITE': 50 }
        );

        // Trigger a breach
        const badAction = ActionFactory.create('load', 500, 'user', userKeys.privateKey);
        try { kernel.execute(badAction); } catch (e) { }

        // Verify Breach Report
        const breaches = ui.getBreachReports();
        expect(breaches.length).toBe(1);
        const breach = breaches[0]!;
        expect(breach.metadata?.violationType).toBe('AUTHORITY_OVERSCOPE');
        expect(breach.metadata?.target).toBe('load');
        expect(breach.metadata?.context.value).toBe(500);

        // Verify Incident Reconstruction
        const incident = ui.reconstructIncident(badAction.actionId);
        expect(incident).toBeDefined();
        expect(incident?.incident.action.actionId).toBe(badAction.actionId);
        expect(incident?.timeline.length).toBeGreaterThan(0);
    });

    test('Product 1 (DAS): Automatic Revocation on Limit Breach', () => {
        // 1. Grant authority with limit
        authority.grant(
            'delegation-auto',
            'admin',
            'user',
            'USER_ROLE',
            'load',
            '0:0',
            'GOVERNANCE_SIGNATURE',
            undefined,
            { 'METRIC.WRITE': 50 }
        );

        // 2. Trigger a breach (Value 100 > 50)
        const breachAction = ActionFactory.create('load', 100, 'user', userKeys.privateKey);
        expect(() => kernel.execute(breachAction)).toThrow(/exceeds limits/);

        // 3. Verify that the user is now REVOKED and cannot act even with valid data
        const validAction = ActionFactory.create('load', 10, 'user', userKeys.privateKey);
        expect(() => kernel.execute(validAction)).toThrow(/revoked/);

        const user = identity.get('user');
        expect(user?.status).toBe('REVOKED');
    });
});
