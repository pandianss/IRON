// src/L4/ProtocolTypes.ts
import type { Protocol as ProtocolPrimitive, EntityID, CapacityID, ProtocolID } from '../L0/Ontology.js';

export type ProtocolLifecycle = 'PROPOSED' | 'RATIFIED' | 'ACTIVE' | 'SUSPENDED' | 'DEPRECATED' | 'REVOKED';
export type ProtocolCategory = 'Intent' | 'Habit' | 'Budget' | 'Authority' | 'Accountability' | 'Risk';

/**
 * 7. Protocol (Primitive)
 * Enforce minimal structure for institutional state transitions.
 */
export interface Protocol extends ProtocolPrimitive {
    name: string; // Human identifier (Management requirement)
    version: string;
    category: ProtocolCategory;
    lifecycle: ProtocolLifecycle;
    strict?: boolean; // If true, must satisfy rules or be REJECTED (Product 3)


    // Core Logic (Charter defined)
    // triggerConditions: string[]; // Handled by engine
    // preconditions: string[]; // Handled by engine
    // stateTransitions: string[]; // Handled by engine

    // Runtime execution fields (Legacy support / MVP mapping)
    execution: any[];
    preconditions: any[];
}

export interface Rule {
    type: 'MUTATE_METRIC' | 'ALLOW_ACTION';
    metricId?: string;
    mutation?: number;
}

export interface Predicate {
    type: 'METRIC_THRESHOLD' | 'ACTION_SIGNATURE' | 'TIME_WINDOW' | 'ALWAYS';
    metricId?: string;
    operator?: '>' | '<' | '==' | '>=' | '<=';
    value?: number | string | boolean;
}

export interface ProtocolBundle {
    bundleId: string;
    protocols: Protocol[];
    owner: {
        entityId: EntityID;
        publicKey: string;
    };
    signature: string;
}

