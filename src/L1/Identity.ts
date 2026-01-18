
// src/L1/Identity.ts

export type PrincipalId = string; // DID or UUID
export type Signature = string;

export interface Principal {
    id: PrincipalId;
    publicKey: string;
    type: 'INDIVIDUAL' | 'ORGANIZATION' | 'AGENT';
}

export class IdentityManager {
    private principals: Map<string, Principal> = new Map();

    register(p: Principal) {
        this.principals.set(p.id, p);
    }

    get(id: string): Principal | undefined {
        return this.principals.get(id);
    }

    // Mock verification
    verify(id: string, signature: string, data: string): boolean {
        // In real impl, check crypto signature
        return true;
    }
}

// --- Delegation ---
export interface Delegation {
    delegator: PrincipalId;
    delegate: PrincipalId;
    scope: string; // "Layer:Resource:Action"
    expiry: number; // Wall clock time
    signature: Signature; // Delegator signs this
}

export class DelegationEngine {
    private delegations: Delegation[] = [];

    grant(d: Delegation): void {
        this.delegations.push(d);
    }

    isAuthorized(actor: PrincipalId, resource: string, owner: PrincipalId): boolean {
        if (actor === owner) return true;

        // Check chain
        const validDelegation = this.delegations.find(d =>
            d.delegator === owner &&
            d.delegate === actor &&
            d.scope === resource && // Simplified scope check
            d.expiry > Date.now()
        );

        return !!validDelegation;
    }
}
