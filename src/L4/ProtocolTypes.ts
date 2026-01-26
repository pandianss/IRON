// src/L4/ProtocolTypes.ts
import type { Protocol as ProtocolPrimitive, EntityID, CapacityID, ProtocolID } from '../L0/Ontology.js';

export type ProtocolLifecycle = 'PROPOSED' | 'RATIFIED' | 'ACTIVE' | 'SUSPENDED' | 'DEPRECATED' | 'REVOKED';
export type ProtocolCategory = 'Intent' | 'Habit' | 'Budget' | 'Authority' | 'Accountability' | 'Risk' | 'Continuity' | 'Incapacity' | 'Coordination';

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


import { z } from 'zod';

export const RuleSchema = z.object({
    type: z.enum(['MUTATE_METRIC', 'ALLOW_ACTION']),
    metricId: z.string().optional(),
    mutation: z.number().optional()
});

export const PredicateSchema = z.object({
    type: z.enum(['METRIC_THRESHOLD', 'ACTION_SIGNATURE', 'TIME_WINDOW', 'ALWAYS']),
    metricId: z.string().optional(),
    operator: z.enum(['>', '<', '==', '>=', '<=']).optional(),
    value: z.union([z.number(), z.string(), z.boolean()]).optional()
});

export const ProtocolSchema = z.object({
    id: z.string().optional(), // Server generated if missing
    name: z.string().min(3),
    version: z.string().default('1.0.0'),
    category: z.enum(['Intent', 'Habit', 'Budget', 'Authority', 'Accountability', 'Risk', 'Continuity', 'Incapacity', 'Coordination']),
    lifecycle: z.enum(['PROPOSED', 'RATIFIED', 'ACTIVE', 'SUSPENDED', 'DEPRECATED', 'REVOKED']).default('PROPOSED'),
    strict: z.boolean().optional(),
    execution: z.array(RuleSchema),
    preconditions: z.array(PredicateSchema)
});

export type ProtocolDraft = z.infer<typeof ProtocolSchema>; // Runtime type from schema
