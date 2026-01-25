
import { describe, test, expect, beforeEach } from '@jest/globals';
import { IdentityManager, AuthorityEngine } from '../L1/Identity.js';

describe('Authority Calculus (Primitive 4)', () => {
    let identity: IdentityManager;
    let authority: AuthorityEngine;

    beforeEach(() => {
        identity = new IdentityManager();
        identity.register({
            id: 'ROOT',
            type: 'ACTOR',
            identityProof: 'ROOT',
            status: 'ACTIVE',
            publicKey: 'key-root',
            isRoot: true,
            createdAt: '0:0'
        });

        identity.register({
            id: 'user',
            type: 'ACTOR',
            identityProof: 'USER',
            status: 'ACTIVE',
            publicKey: 'key-user',
            createdAt: '0:0'
        });

        authority = new AuthorityEngine(identity);
    });

    test('Jurisdiction: Exact Match', () => {
        authority.grant('auth1', 'ROOT', 'user', 'WRITER', 'system.load', '0:0', 'GOVERNANCE_SIGNATURE');
        expect(authority.authorized('user', 'METRIC.WRITE:system.load')).toBe(true);
        expect(authority.authorized('user', 'METRIC.WRITE:system.memory')).toBe(false);
    });

    test('Jurisdiction: Wildcard', () => {
        authority.grant('auth1', 'ROOT', 'user', 'ADMIN', '*', '0:0', 'GOVERNANCE_SIGNATURE');
        expect(authority.authorized('user', 'METRIC.WRITE:any.thing')).toBe(true);
    });

    test('Jurisdiction: Hierarchical Containment', () => {
        authority.grant('auth1', 'ROOT', 'user', 'DEVOPS', 'system', '0:0', 'GOVERNANCE_SIGNATURE');

        expect(authority.authorized('user', 'METRIC.WRITE:system.load')).toBe(true);
        expect(authority.authorized('user', 'METRIC.WRITE:system.cpu.core1')).toBe(true);
        expect(authority.authorized('user', 'METRIC.WRITE:user.data')).toBe(false);
    });

    test('Identity: Revoked Entity lacks Authority', () => {
        authority.grant('auth1', 'ROOT', 'user', 'WRITER', '*', '0:0', 'GOVERNANCE_SIGNATURE');
        expect(authority.authorized('user', 'METRIC.WRITE:test')).toBe(true);

        identity.revoke('user', '1:0');
        expect(authority.authorized('user', 'METRIC.WRITE:test')).toBe(false);
    });
});
