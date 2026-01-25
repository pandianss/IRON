// src/L2/State.ts
import type { EntityID } from '../L0/Ontology.js';
import { IdentityManager } from '../L1/Identity.js';
import { verifySignature, hash } from '../L0/Crypto.js';
import { AuditLog } from '../L5/Audit.js';
import { LogicalTimestamp } from '../L0/Kernel.js';

// --- Action ---
export interface ActionPayload {
    metricId: string;
    value: any;
}

export interface Action {
    actionId: string;
    initiator: EntityID;
    payload: ActionPayload;
    timestamp: string;
    expiresAt: string;
    signature: string;
}


// --- Metrics ---
export enum MetricType {
    COUNTER = 'COUNTER',
    GAUGE = 'GAUGE',
    BOOLEAN = 'BOOLEAN'
}

export interface MetricDefinition {
    id: string;
    description: string;
    type: MetricType;
    unit?: string;
    validator?: (value: any) => boolean;
}

export class MetricRegistry {
    private metrics: Map<string, MetricDefinition> = new Map();
    register(def: MetricDefinition) { this.metrics.set(def.id, def); }
    get(id: string) { return this.metrics.get(id); }
}

// --- State ---
export interface StateValue<T = any> {
    value: T;
    updatedAt: string; // Timestamp from Intent
    evidenceHash: string; // Link to Audit Log Entry
    stateHash: string; // SHA256(PrevStateHash + LogEntryHash)
}

export class StateModel {
    private state: Map<string, StateValue> = new Map();
    private history: Map<string, StateValue[]> = new Map();

    constructor(
        private auditLog: AuditLog,
        private registry: MetricRegistry,
        private identityManager: IdentityManager
    ) { }

    public apply(action: Action): void {
        try {
            // 1. Verify Identity & Signature
            const entity = this.identityManager.get(action.initiator);
            if (!entity) throw new Error("Unknown Entity");
            if (entity.status === 'REVOKED') throw new Error("Entity Revoked");

            const data = `${action.actionId}:${action.initiator}:${JSON.stringify(action.payload)}:${action.timestamp}:${action.expiresAt}`;

            if (!verifySignature(data, action.signature, entity.publicKey)) {
                throw new Error("Invalid Action Signature");
            }

            // 2. Delegate to common application logic
            this.applyTrusted(action.payload, action.timestamp, action.initiator, action.actionId);

        } catch (e: any) {
            console.warn(`State Transition Failed: ${e.message}`);
            this.auditLog.append(action, 'FAILURE');
            throw e;
        }
    }

    public validateMutation(payload: ActionPayload): void {
        if (!payload?.metricId) throw new Error("Missing Metric ID");
        const def = this.registry.get(payload.metricId);
        if (!def) throw new Error(`Unknown metric: ${payload.metricId}`);
        if (def.validator && !def.validator(payload.value)) throw new Error("Invalid Value");
    }

    /**
     * Applies a state transition without signature verification.
     * Use ONLY from trusted sources (e.g., Kernel after verification, Internal Engines).
     */
    public applyTrusted(payload: ActionPayload, timestamp: string, initiator: string = 'system', actionId?: string): Action {
        this.validateMutation(payload);

        // 2. Monotonic Time Check
        const lastState = this.state.get(payload.metricId);
        if (lastState) {
            const current = LogicalTimestamp.fromString(timestamp);
            const last = LogicalTimestamp.fromString(lastState.updatedAt);

            if (current.time < last.time || (current.time === last.time && current.logical < last.logical)) {
                throw new Error("Time Violation: Monotonicity Breach");
            }
        }

        // 3. Construct action record for logging if not provided
        const action: Action = {
            actionId: actionId || hash(`trusted:${initiator}:${payload.metricId}:${timestamp}:${Math.random()}`),
            initiator,
            payload,
            timestamp,
            expiresAt: '0',
            signature: 'TRUSTED'
        };

        // 4. Commit SUCCESS to Audit Log
        const logEntry = this.auditLog.append(action, 'SUCCESS');

        // 5. Update State
        const prevStateHash = lastState ? lastState.stateHash : '0000000000000000000000000000000000000000000000000000000000000000';
        const stateHash = hash(prevStateHash + logEntry.evidenceId);

        const newState: StateValue = {
            value: payload.value,
            updatedAt: timestamp,
            evidenceHash: logEntry.evidenceId,
            stateHash: stateHash
        };

        this.state.set(payload.metricId, newState);
        if (!this.history.has(payload.metricId)) this.history.set(payload.metricId, []);
        this.history.get(payload.metricId)?.push(newState);

        return action;
    }

    public get(id: string) { return this.state.get(id)?.value; }
    public getHistory(id: string) { return this.history.get(id) || []; }
}
