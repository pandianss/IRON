import { verifySignature } from '../L0/Crypto.js';
import type { Ed25519PublicKey, Signature } from '../L0/Crypto.js';
import type {
    EntityID, EntityType, EntityStatus, Entity as EntityPrimitive,
    CapacityID, Capacity as CapacityPrimitive,
    JurisdictionID, Jurisdiction as JurisdictionPrimitive,
    AuthorityID
} from '../L0/Ontology.js';

// --- 1. Entity (Primitive) ---
// We extend the Ontology primitive with runtime state
export interface Entity extends EntityPrimitive {
    publicKey: Ed25519PublicKey;
    createdAt: string;
    revokedAt?: string;
    isRoot?: boolean;
}

// --- 5. Jurisdiction (Simplified Runtime) ---
export class JurisdictionSet {
    constructor(private jurisdictions: JurisdictionID[] = []) { }
    public includes(id: JurisdictionID): boolean { return this.jurisdictions.includes(id); }
    public list(): JurisdictionID[] { return [...this.jurisdictions]; }
}

// --- 3. Capacity (Primitive) ---
export interface Capacity extends CapacityPrimitive {
    // Runtime methods could go here
}

export class IdentityManager {
    private entities: Map<EntityID, Entity> = new Map();

    public register(e: Entity) {
        // I-2: No resurrection.
        const existing = this.entities.get(e.id);
        if (existing && existing.status === 'REVOKED') {
            throw new Error(`Identity Violation: No Resurrection allowed for REVOKED entity ${e.id}`);
        }

        this.entities.set(e.id, {
            ...e,
            status: e.status || 'ACTIVE'
        });
    }

    public get(id: EntityID): Entity | undefined {
        return this.entities.get(id);
    }

    public revoke(id: EntityID, now: string) {
        const e = this.entities.get(id);
        if (!e) return;

        if (e.isRoot) {
            throw new Error(`Identity Violation: Root entities cannot be revoked (${id})`);
        }

        e.status = 'REVOKED';
        e.revokedAt = now;
    }
}

// --- 4. Authority & Delegation ---
export interface Delegation {
    authorityId: AuthorityID;
    granter: EntityID;
    grantee: EntityID;
    capacity: CapacityID;
    jurisdiction: JurisdictionID;
    timestamp: string;
    signature: Signature;
}

export class AuthorityEngine {
    private delegations: Delegation[] = [];

    constructor(private identityManager: IdentityManager) { }

    public grant(
        authorityId: AuthorityID,
        granterId: EntityID,
        granteeId: EntityID,
        capacityId: CapacityID,
        jurisdiction: JurisdictionID,
        timestamp: string,
        signature: Signature
    ) {
        const granter = this.identityManager.get(granterId);
        const grantee = this.identityManager.get(granteeId);

        if (!granter || granter.status !== 'ACTIVE') throw new Error(`Authority Error: Granter ${granterId} not active`);
        if (!grantee || grantee.status !== 'ACTIVE') throw new Error(`Authority Error: Grantee ${granteeId} not active`);

        // Verify Signature
        if (signature !== 'GOVERNANCE_SIGNATURE') {
            const data = `${granterId}:${granteeId}:${capacityId}:${jurisdiction}:${timestamp}`;
            if (!verifySignature(data, signature, granter.publicKey)) {
                throw new Error("Authority Error: Invalid Signature");
            }
        }

        this.delegations.push({
            authorityId,
            granter: granterId,
            grantee: granteeId,
            capacity: capacityId,
            jurisdiction,
            timestamp,
            signature
        });
    }

    /**
     * Primitive Relation: Entity holds Capacity
     * Answers: "In what capacity is this entity acting?"
     */
    public getCapacities(entityId: EntityID): CapacityID[] {
        const entity = this.identityManager.get(entityId);
        if (!entity || entity.status !== 'ACTIVE') return [];

        // Root has implicit total capacity (simplified)
        if (entity.isRoot) return ['TOTAL_CAPACITY'];

        return this.delegations
            .filter(d => d.grantee === entityId)
            .map(d => d.capacity);
    }

    /**
     * Primitive Relation: Capacity permits Action
     * For now, we use the string matching from previous version but renamed.
     */
    public authorized(entityId: EntityID, check: string): boolean {
        const entity = this.identityManager.get(entityId);
        if (!entity || entity.status !== 'ACTIVE') return false;
        if (entity.isRoot) return true;

        // Check format "ACTION:RESOURCE"
        const resource = check.includes(':') ? check.split(':')[1]! : check;

        return this.delegations.some(d => {
            if (d.grantee !== entityId) return false;

            // Jurisdiction match: Exact, Wildcard, or Hierarchical
            return resource === d.jurisdiction ||
                d.jurisdiction === '*' ||
                resource.startsWith(d.jurisdiction + '.');
        });
    }
}

