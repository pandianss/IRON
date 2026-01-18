
// src/L1/Identity.ts
import { verifySignature, Ed25519PublicKey, Signature } from '../L0/Crypto';

export type PrincipalId = string; // DID or UUID (derived from PubKey?)

export interface Principal {
    id: PrincipalId;
    publicKey: Ed25519PublicKey; // PEM string
    type: 'INDIVIDUAL' | 'ORGANIZATION' | 'AGENT';
    validFrom: number;
    validUntil: number;
    revoked?: boolean; // Gap 4
    rules?: string[]; // Allowed scopes root
}

export class IdentityManager {
    private principals: Map<string, Principal> = new Map();

    register(p: Principal) {
        this.principals.set(p.id, { ...p, revoked: false });
    }

    get(id: string): Principal | undefined {
        return this.principals.get(id);
    }

    revoke(id: string) {
        const p = this.principals.get(id);
        if (p) p.revoked = true;
    }
}

// --- Scope Helper (Gap 1) ---
class ScopeHelper {
    // Scope Format: "Layer:Resource:Action"
    // Subset Logic: Child must be equal or more specific?
    // Actually, Delegator must HAVE the scope to give it.
    // Delegator Scope: "L2:*" -> Delegate Scope: "L2:Metric:Write" OK.

    static isSubset(childScope: string, parentScope: string): boolean {
        if (parentScope === '*') return true;
        if (parentScope === childScope) return true;

        const parentParts = parentScope.split(':');
        const childParts = childScope.split(':');

        if (parentParts.length > childParts.length) return false;

        for (let i = 0; i < parentParts.length; i++) {
            if (parentParts[i] !== '*' && parentParts[i] !== childParts[i]) {
                return false;
            }
        }
        return true;
    }
}

// --- Delegation ---
export interface Delegation {
    delegator: PrincipalId;
    delegate: PrincipalId;
    scope: string; // "Layer:Resource:Action"
    validUntil: number; // Wall clock time
    signature: Signature; // Sign(delegator + delegate + scope + validUntil)
}

export class DelegationEngine {
    private delegations: Delegation[] = [];

    constructor(private identityManager: IdentityManager) { }

    grant(d: Delegation): boolean {
        // Verify Signature
        const delegator = this.identityManager.get(d.delegator);
        if (!delegator) return false;

        const data = `${d.delegator}:${d.delegate}:${d.scope}:${d.validUntil}`;
        if (!verifySignature(data, d.signature, delegator.publicKey)) return false;

        // Gap 1: Delegation Scope Check
        // Does Delegator have authority?
        if (!this.hasAuthority(d.delegator, d.scope)) {
            // Gap 1 Violation: Delegator lacks authority for scope
            return false;
        }

        this.delegations.push(d);
        return true;
    }

    private hasAuthority(principalId: string, scope: string): boolean {
        const p = this.identityManager.get(principalId);
        if (!p) return false;
        if (p.revoked) return false; // Gap 4

        // 1. Root Authority (Implicit or Explicit field)
        if (p.rules?.some(rule => ScopeHelper.isSubset(scope, rule))) return true;

        // 2. Delegated Authority
        // Check if there is an active delegation TO this principal covering scope
        // This is simplified: it finds ANY valid path.
        const incoming = this.delegations.find(d =>
            d.delegate === principalId &&
            d.validUntil > Date.now() &&
            ScopeHelper.isSubset(scope, d.scope) // Incoming must cover outgoing
        );

        if (incoming) {
            // Recurse to ensure transitive authority
            return this.hasAuthority(incoming.delegator, incoming.scope);
        }

        return false;
    }

    isAuthorized(actor: PrincipalId, resource: string, owner: PrincipalId): boolean {
        // OWNER Check
        if (actor === owner) {
            const p = this.identityManager.get(actor);
            return !!p && !p.revoked; // Gap 4
        }

        // Chain Check
        return this.checkChain(owner, actor, resource);
    }

    private checkChain(start: string, end: string, scope: string): boolean {
        const p = this.identityManager.get(start);
        if (!p || p.revoked) return false; // Gap 4

        if (start === end) return true;

        // Find edge
        const edge = this.delegations.find(d =>
            d.delegator === start &&
            ScopeHelper.isSubset(scope, d.scope) &&
            d.validUntil > Date.now()
        );

        if (!edge) return false;

        return this.checkChain(edge.delegate, end, scope);
    }
}
