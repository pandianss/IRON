
// src/L4/ProtocolTypes.ts
import { PrincipalId } from '../L1/Identity';

// --- Canonical Schema Definitions ---

export type ProtocolCategory = 'Intent' | 'Habit' | 'Budget' | 'Authority' | 'Accountability' | 'Risk';

export interface Validity {
    from: number;
    until?: number;
}

export interface Scope {
    actors: string[];
    resources: string[]; // State domains
}

// Predicate: Simple Logic for Preconditions
export interface Predicate {
    type: 'METRIC_THRESHOLD' | 'INTENT_SIGNATURE' | 'TIME_WINDOW' | 'ALWAYS';
    metricId?: string;
    operator?: '>' | '<' | '==' | '>=' | '<=';
    value?: number | string | boolean;
}

// Rule: Deterministic Execution
export interface Rule {
    type: 'MUTATE_METRIC' | 'ALLOW_INTENT';
    metricId?: string;
    mutation?: number;
}

export interface BudgetDef {
    type: 'time' | 'attention' | 'risk' | 'simulation' | 'authority';
    limit: number;
}

export interface AccountabilityDef {
    mode: 'self' | 'peer' | 'org';
    severityOnViolation: 'info' | 'warn' | 'critical';
}

export interface RevocationDef {
    allowedBy: string;
    propagates: boolean;
}

export interface Protocol {
    id?: string;
    name: string;
    version?: string;
    category: ProtocolCategory;
    author?: string;

    validity?: Validity;
    scope?: Scope;

    preconditions: (Predicate | string)[];
    execution: (Rule | string)[];

    budgets?: BudgetDef[];
    accountability?: AccountabilityDef;
    revocation?: RevocationDef;

    // Legacy mapping helpers if needed
    triggerMetric?: string;
    threshold?: number;
    actionMetric?: string; // Implicitly derived or explicit?
    actionMutation?: number;
}

export interface ProtocolBundle {
    bundleId: string;
    libraryName: string;
    version: string;
    owner: {
        publicKey: string; // ed25519:hex
        scope: string;
    };
    protocols: Protocol[];
    createdAt: string;
    signature: string; // ed25519:hex
}
