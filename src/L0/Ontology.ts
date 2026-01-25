
/**
 * IRON ONTOLOGY (v1.0 Foundational)
 * The Single Source of Truth for all Kernel Primitives.
 * 
 * Based on the IRON KERNEL PRIMITIVE SET v1.0
 */

// --- 1. Entity ---
export type EntityID = string;
export type EntityType = 'ACTOR' | 'OFFICE' | 'ASSET' | 'SYSTEM' | 'ABSTRACT';
export type EntityStatus = 'ACTIVE' | 'SUSPENDED' | 'DISSOLVED' | 'REVOKED';

export interface Entity {
    id: EntityID;
    type: EntityType;
    identityProof: string; // auth ref or cryptographic proof
    status: EntityStatus;
}

// --- 2. Identity ---
export interface Identity {
    entityId: EntityID;
    publicKey: string;
    verificationMethod: string;
    validityWindow: { from: string; until?: string };
    delegationChain: string[]; // List of DelegationIDs or similar
}

// --- 3. Capacity ---
export type CapacityID = string;
export interface Capacity {
    id: CapacityID;
    heldBy: EntityID;
    conferredBy: AuthorityID;
    scope: JurisdictionID[];
    validity: string;
    revocationConditions: string;
}

// --- 4. Authority ---
export type AuthorityID = string;
export interface Authority {
    id: AuthorityID;
    source: 'CONSTITUTION' | 'DELEGATION' | 'LAW' | 'EMERGENCY';
    grantsCapacities: CapacityID[];
    permitsActions: string[]; // Action types or ProtoIDs
    imposesObligations: string[];
    boundedBy: JurisdictionID;
}

// --- 5. Jurisdiction ---
export type JurisdictionID = string;
export interface Jurisdiction {
    id: JurisdictionID;
    scopeDefinition: string;
    inclusionRules: string[];
    exclusionRules: string[];
    temporalBoundaries: string;
}

// --- 6. Governed State ---
export type StateID = string;
export type StateValue = number | string | boolean | any;
export interface GovernedState {
    id: StateID;
    schema: string;
    currentValue: StateValue;
    version: number;
    derivationHistory: string; // EvidenceID link
}

// --- 7. Protocol ---
export type ProtocolID = string;
export interface Protocol {
    id: ProtocolID;
    triggerConditions: string[];
    preconditions: string[];
    authorizedCapacities: CapacityID[];
    stateTransitions: string[];
    completionConditions: string[];
}

// --- 8. Action ---
export type ActionID = string;
export interface Action {
    id: ActionID;
    initiator: EntityID;
    invokedCapacity: CapacityID;
    protocolReference: ProtocolID;
    declaredIntent: string;
    timestamp: string; // LogicalTimestamp
    signature: string;
}

// --- 9. Invariant ---
export type InvariantID = string;
export interface Invariant {
    id: InvariantID;
    predicate: string;
    scope: JurisdictionID;
    severity: 'WARNING' | 'CRITICAL' | 'FATAL';
    enforcementDirective: string;
}

// --- 10. Sanction ---
export type SanctionID = string;
export interface Sanction {
    id: SanctionID;
    trigger: string; // Violation info
    target: EntityID;
    effect: string;
    executionMode: 'AUTOMATIC' | 'AUDIT_ONLY';
}

// --- 11. Override ---
export type OverrideID = string;
export interface Override {
    id: OverrideID;
    authorizingAuthority: AuthorityID;
    scope: JurisdictionID;
    justificationRecord: string;
    auditObligation: string;
}

// --- 12. Evidence ---
export type EvidenceID = string;
export interface Evidence {
    id: EvidenceID;
    linkedAction: ActionID;
    authorityTrace: string;
    protocolTrace: string;
    stateDiff: string;
    immutabilityProof: string;
}

// --- Kernel Lifecycle ---
export type KernelState =
    | 'UNINITIALIZED'
    | 'CONSTITUTED'
    | 'ACTIVE'
    | 'SUSPENDED'
    | 'VIOLATED'
    | 'RECOVERED'
    | 'DISSOLVED';
